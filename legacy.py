"""Legacy: the encryption format of the original Transcrypt package.

- The password, padded with zero bytes or truncated to 16, 24 or 32 bytes,
  is used directly as the AES key. There is no salt and no key derivation.
- The text is zero-padded, encrypted with AES in ECB mode & written as base64.
- There is no checksum. A wrong password is only noticed when the result is not
  valid UTF-8.

The module has no Sublime dependency and it can be tested on its own.
"""

import base64
import binascii
import bisect

from .pyaes import AESModeOfOperationECB


# ~ Constants
# -----------

C_PAD = b"\0"
KEY_SIZES = [16, 24, 32]


# ~ Exceptions
# ------------

class BadPaddingException(Exception):
    pass


class WrongPasswordException(Exception):
    pass


# ~ AES
# -----

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


# ~ Helpers
# ---------

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


# ~ Public API
# ------------

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
