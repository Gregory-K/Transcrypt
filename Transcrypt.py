"""
@name     Transcrypt
@package  sublime_plugin
@author   Elliot Marsden

This Sublime Text 4 plugin adds AES encryption and decryption
to the right-click context menu.

Usage:
- Make a selection, or none for the whole file.
- Choose Transcrypt > Encrypt or Decrypt from the context menu.
- Enter a password.
"""

import base64
import binascii
import bisect
from functools import partial

import sublime
import sublime_plugin

from . import tc2
from .pyaes import AESModeOfOperationECB


class AES:
    """AES in ECB mode, with the subset of the PyCrypto 'AES' API used here.

    pyaes encrypts one block at a time, so data is processed block by block.
    Data that is not a multiple of 'block_size' raises ValueError,
    as with PyCrypto.
    """

    block_size = 16

    def __init__(self, key):
        self._ecb = AESModeOfOperationECB(key)

    @classmethod
    def new(cls, key):
        return cls(key)

    def _blocks(self, func, data):
        size = self.block_size
        return b"".join(func(data[i:i + size])
                        for i in range(0, len(data), size))

    def encrypt(self, data):
        return self._blocks(self._ecb.encrypt, data)

    def decrypt(self, data):
        return self._blocks(self._ecb.decrypt, data)


class BadPaddingException(Exception):
    pass


class WrongPasswordException(Exception):
    pass


class SettingsError(Exception):
    pass


class AlreadyEncryptedError(Exception):
    pass


C_PAD = b"\0"
KEY_SIZES = [16, 24, 32]
SETTINGS_FILE = "Transcrypt.sublime-settings"

# Passwords are kept in memory only, never in settings or command arguments.
# The remembered password lasts until it is forgotten, or the plugin host stops.
# The handoff password lives only while one 'transcrypt' command runs.
_remembered_password = None
_handoff_password = None


def normalize_key(key):
    """Pad or truncate a key to be compatible with AES encryption.

    Pad or truncate key (assumed to be bytes) as needed to be compatible
    with AES encryption.
    """
    key_len = len(key)
    # Pad
    if key_len < max(KEY_SIZES):
        next_biggest = KEY_SIZES[bisect.bisect_left(KEY_SIZES, key_len)]
        return key + (next_biggest - key_len) * C_PAD
    # Truncate
    else:
        return key[:max(KEY_SIZES)]


def decrypt_bytes(secret, s):
    """Decrypt byte string with a key.

    Decrypt byte string 's' with the AES algorithm using secret 'secret',
    removing padding as needed.
    """
    try:
        return secret.decrypt(base64.b64decode(s, validate=True)).rstrip(C_PAD)
    except (ValueError, binascii.Error) as e:
        raise BadPaddingException


def encrypt_bytes(secret, s):
    """Encrypt byte string with a key.

    Encrypt byte string 's' with the AES algorithm using secret 'secret',
    padded as needed.
    """
    pad_nr = AES.block_size - (len(s) % AES.block_size)
    return base64.b64encode(secret.encrypt(s + (pad_nr * C_PAD)))


def transcrypt_text(input_text, key_text, enc, encoding='utf-8'):
    # On decryption, keep surrounding whitespace (e.g. a document's final
    # newline) out of the cipher text and put it back around the result.
    lead = trail = ""
    if not enc:
        stripped = input_text.lstrip()
        lead = input_text[:len(input_text) - len(stripped)]
        input_text = stripped.rstrip()
        trail = stripped[len(input_text):]
    secret = AES.new(normalize_key(key_text.encode(encoding)))
    crypt_bytes_func = encrypt_bytes if enc else decrypt_bytes
    output_bytes = crypt_bytes_func(secret, input_text.encode(encoding))
    try:
        return lead + output_bytes.decode(encoding) + trail
    except UnicodeError:
        if enc:
            raise
        else:
            raise WrongPasswordException


def is_encrypted(text):
    """Return True if the whole text looks like one encrypted part.

    TC2 is recognised by its marker. Legacy output has no marker, so any
    base64 that decodes to whole AES blocks counts as encrypted.
    """
    text = text.strip()
    if not text:
        return False
    if tc2.is_tc2(text):
        return True
    try:
        return len(base64.b64decode(text, validate=True)) % AES.block_size == 0
    except (ValueError, binascii.Error):
        return False


def encrypt_text(text, password, settings):
    """Encrypt text in the format chosen by the settings.

    'secure_format' picks TC2 over the legacy format, and 'scrypt_memory'
    picks the TC2 scrypt preset. Text that already looks encrypted is
    refused, so it is never encrypted twice.
    """
    if is_encrypted(text):
        raise AlreadyEncryptedError
    if not settings.get("secure_format", False):
        return transcrypt_text(text, password, enc=True)
    memory = settings.get("scrypt_memory", tc2.DEFAULT_MEMORY)
    if memory not in tc2.PRESETS:
        raise SettingsError("'scrypt_memory' must be one of %s"
                            % ", ".join(map(str, tc2.PRESETS)))
    return tc2.encrypt(text, password, memory)


def decrypt_text(text, password):
    """Decrypt text in either format, whatever the settings say.

    Every TC2 part in the text is decrypted, and the text around them is kept.
    Text with no TC2 part is decrypted as one legacy part.
    """
    if tc2.PATTERN.search(text):
        return tc2.PATTERN.sub(lambda m: tc2.decrypt(m.group(), password),
                               text)
    return transcrypt_text(text, password, enc=False)


class SetContentsCommand(sublime_plugin.TextCommand):

    def run(self, edit, text):
        r = sublime.Region(0, self.view.size())
        self.view.replace(edit, r, text)
        self.view.end_edit(edit)


class ShowPanelMessageCommand(sublime_plugin.WindowCommand):

    def run(self, message):
        v = self.window.create_output_panel('transcrypt_error')
        v.run_command("set_contents", {"text": message})
        self.window.run_command(
            "show_panel",
            {"panel": "output.transcrypt_error"},
        )


def show_panel_message(window, message):
    window.run_command("show_panel_message", {"message": message})


def get_input(window, message, callback):
    window.show_input_panel(message, "", callback, None, None)


def get_new_password(window, message, callback):
    """Ask for a password twice, and pass it to 'callback' if both match."""
    def confirm(password):
        def check(password_confirm):
            if password_confirm != password:
                show_panel_message(window, "Error: Passwords do not match")
            else:
                callback(password)
        get_input(window, "Confirm password:", check)
    get_input(window, message, confirm)


class TranscryptCommand(sublime_plugin.TextCommand):

    WRONG_PW_TEXT = "Error: Wrong password"
    BAD_INPUT_TEXT = ("Error: Input is not valid output of AES encryption, "
                      "sure it's been encrypted?")
    TC2_AUTH_TEXT = "Error: Wrong password, or the text was modified"
    TC2_BAD_TEXT = "Error: Invalid TC2 encrypted text (%s)"
    SETTINGS_TEXT = "Error: Invalid Transcrypt setting. %s"
    ALREADY_TEXT = "Error: The text is already encrypted"
    REMEMBERED_TEXT = (" (the remembered password).")

    def transcrypt_regions(self, regions, enc, password, remembered):
        """Return the new text of each region, or an error message."""
        settings = sublime.load_settings(SETTINGS_FILE)
        hint = self.REMEMBERED_TEXT if remembered else ""
        try:
            if enc:
                return [encrypt_text(self.view.substr(r), password, settings)
                        for r in regions], None
            return [decrypt_text(self.view.substr(r), password)
                    for r in regions], None
        except WrongPasswordException:
            return None, self.WRONG_PW_TEXT + hint
        except BadPaddingException:
            return None, self.BAD_INPUT_TEXT
        except tc2.TC2AuthError:
            return None, self.TC2_AUTH_TEXT + hint
        except tc2.TC2Error as e:
            return None, self.TC2_BAD_TEXT % e
        except SettingsError as e:
            return None, self.SETTINGS_TEXT % e
        except AlreadyEncryptedError:
            return None, self.ALREADY_TEXT

    def run(self, edit, enc, save=False, remembered=False):
        # The password comes from transcrypt(), not from the arguments.
        password = _handoff_password
        if password is None:
            return

        # Save the document size.
        view_size = self.view.size()

        # Get selections.
        regions = self.view.sel()
        nr_regions = len(regions)
        # Select the whole document if there is no selection.
        if nr_regions <= 1 and len(self.view.substr(regions[0])) == 0:
            regions.clear()
            regions.add(sublime.Region(0, view_size))

        # Transcrypt every region before changing any, so an error leaves
        # the document untouched.
        regions = list(regions)
        results, error = self.transcrypt_regions(regions, enc, password,
                                                 remembered)
        if error:
            window = self.view.window()
            if window:
                show_panel_message(window, error)
        else:
            # Replace from the end, so earlier regions keep their offsets.
            for region, result in reversed(list(zip(regions, results))):
                self.view.replace(edit, region, result)
            # Save only after a successful encryption, never the plain text.
            if save:
                sublime.set_timeout(lambda: self.view.run_command("save"))
        self.view.end_edit(edit)


def transcrypt(enc, view, password, save=False, remembered=False):
    """Run the 'transcrypt' command, handing over the password in memory.

    run_command() returns only after the command has run, so the handoff
    password is cleared straight after.
    """
    global _handoff_password
    if not view:
        return
    _handoff_password = password
    try:
        view.run_command(
            "transcrypt",
            {"enc": enc, "save": save, "remembered": remembered}
        )
    finally:
        _handoff_password = None


encrypt = partial(transcrypt, True)
decrypt = partial(transcrypt, False)


class EncryptCommand(sublime_plugin.WindowCommand):

    SET_TEXT = "Set password:"

    def run(self, save=False):
        # The save, if asked, happens only if encryption succeeds.
        view = self.window.active_view()
        if _remembered_password is not None:
            encrypt(view, _remembered_password, save=save, remembered=True)
        else:
            get_new_password(self.window, self.SET_TEXT,
                             partial(encrypt, view, save=save))


class DecryptCommand(sublime_plugin.WindowCommand):

    ENTER_TEXT = "Enter password:"

    def run(self):
        view = self.window.active_view()
        if _remembered_password is not None:
            decrypt(view, _remembered_password, remembered=True)
        else:
            get_input(self.window, self.ENTER_TEXT, partial(decrypt, view))


class ToggleRememberPasswordCommand(sublime_plugin.WindowCommand):
    """Remember a password for this session, or forget it.

    While a password is remembered, Encrypt and Decrypt use it without
    asking. It is kept in memory only, so closing Sublime Text forgets it.
    """

    SET_TEXT = "Password to remember:"

    def is_checked(self):
        return _remembered_password is not None

    def run(self):
        global _remembered_password
        if _remembered_password is not None:
            _remembered_password = None
            sublime.status_message("Transcrypt: Password forgotten")
        else:
            get_new_password(self.window, self.SET_TEXT, self.remember)

    def remember(self, password):
        global _remembered_password
        _remembered_password = password
        sublime.status_message(
            "Transcrypt: Password remembered for this session")
