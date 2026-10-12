"""TC2: password-based authenticated encryption for Transcrypt.

Format of an encrypted part:

    TC2$<log2 N>.<r>.<p>$<salt>$<Fernet token>

- The key is derived from the password with scrypt
  (N, r, p and a random 16-byte salt, all stored in the output).
- The text is encrypted as a Fernet token (AES-128-CBC with PKCS7
  padding, HMAC-SHA256 over the token), following the Fernet spec:
  https://github.com/fernet/spec/blob/master/Spec.md
- Salt and token are URL-safe base64. '$' is not a base64 character, so
  TC2 output can never be mistaken for legacy output and is easy to find
  in a document (see PATTERN).

The module has no Sublime dependency and it can be tested on its own.
"""

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import struct
import time

from .pyaes import AESModeOfOperationCBC


MARKER = "TC2"

# Equal-strength scrypt settings from the OWASP Password Storage Cheat Sheet,
# keyed by memory cost in MiB: (log2 N, r, p).
PRESETS = {
    128: (17, 8, 1),
    64: (16, 8, 2),
    32: (15, 8, 3),
    16: (14, 8, 5),
    8: (13, 8, 10),
}
DEFAULT_MEMORY = 128

PATTERN = re.compile(
    r"TC2\$\d+\.\d+\.\d+\$[A-Za-z0-9_=-]+\$[A-Za-z0-9_=-]+")

SALT_SIZE = 16
BLOCK_SIZE = 16
FERNET_VERSION = 0x80
HMAC_SIZE = 32
# version (1) + timestamp (8) + IV (16)
HEADER_SIZE = 1 + 8 + BLOCK_SIZE


class TC2Error(Exception):
    """Input is not a valid TC2 part."""


class TC2AuthError(TC2Error):
    """Wrong password, or the text has been modified."""


# ~ Helpers
# ---------

def _b64encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64decode(text):
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except (ValueError, binascii.Error) as e:
        raise TC2Error("invalid base64") from e


def _derive_key(password, salt, log_n, r, p):
    """Derive the 32-byte Fernet key from the password with scrypt."""
    n = 1 << log_n
    # OpenSSL refuses more than 32 MiB unless 'maxmem' allows it.
    # scrypt needs 128 * N * r bytes, plus some headroom.
    maxmem = 128 * n * r + (1 << 20)
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=n, r=r, p=p, maxmem=maxmem, dklen=32)


def _pkcs7_pad(data):
    pad = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE:
        raise TC2Error("invalid padding")
    pad = data[-1]
    if not 1 <= pad <= BLOCK_SIZE or data[-pad:] != bytes([pad]) * pad:
        raise TC2Error("invalid padding")
    return data[:-pad]


def _cbc(func_name, key, iv, data):
    """Run AES-CBC over 'data', block by block, in pyaes."""
    cbc = AESModeOfOperationCBC(key, iv=iv)
    func = getattr(cbc, func_name)
    return b"".join(func(data[i:i + BLOCK_SIZE])
                    for i in range(0, len(data), BLOCK_SIZE))


def fernet_encrypt(key, data, iv=None, timestamp=None):
    """Encrypt bytes into a Fernet token (bytes, before base64).

    'iv' and 'timestamp' are for tests only. By default they are random
    and the current time, as the spec requires.
    """
    signing_key, encryption_key = key[:16], key[16:]
    iv = secrets.token_bytes(BLOCK_SIZE) if iv is None else iv
    timestamp = int(time.time()) if timestamp is None else timestamp
    body = (bytes([FERNET_VERSION]) + struct.pack(">Q", timestamp) + iv
            + _cbc("encrypt", encryption_key, iv, _pkcs7_pad(data)))
    return body + hmac.new(signing_key, body, hashlib.sha256).digest()


def fernet_decrypt(key, token):
    """Verify and decrypt a Fernet token (bytes, after base64)."""
    signing_key, encryption_key = key[:16], key[16:]
    if (len(token) < HEADER_SIZE + BLOCK_SIZE + HMAC_SIZE
            or token[0] != FERNET_VERSION
            or (len(token) - HEADER_SIZE - HMAC_SIZE) % BLOCK_SIZE):
        raise TC2Error("invalid Fernet token")
    body, mac = token[:-HMAC_SIZE], token[-HMAC_SIZE:]
    expected = hmac.new(signing_key, body, hashlib.sha256).digest()
    # Check the MAC before touching the cipher text.
    if not hmac.compare_digest(mac, expected):
        raise TC2AuthError("wrong password or modified text")
    iv = body[1 + 8:HEADER_SIZE]
    return _pkcs7_unpad(_cbc("decrypt", encryption_key, iv,
                             body[HEADER_SIZE:]))


# ~ Public API
# ------------


def is_tc2(text):
    """Return True if 'text' is a single TC2 part (whitespace aside)."""
    return PATTERN.fullmatch(text.strip()) is not None


def encrypt(text, password, memory=DEFAULT_MEMORY):
    """Encrypt 'text' with 'password' into a TC2 part.

    'memory' picks the scrypt preset (MiB), see PRESETS.
    """
    if memory not in PRESETS:
        raise ValueError("scrypt memory must be one of %s MiB"
                         % sorted(PRESETS, reverse=True))
    log_n, r, p = PRESETS[memory]
    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(password, salt, log_n, r, p)
    token = fernet_encrypt(key, text.encode("utf-8"))
    return "%s$%d.%d.%d$%s$%s" % (MARKER, log_n, r, p,
                                  _b64encode(salt), _b64encode(token))


def decrypt(part, password):
    """Decrypt a TC2 part produced by encrypt().

    Raises TC2Error for malformed input or unknown scrypt parameters,
    and TC2AuthError for a wrong password or modified text.
    """
    part = part.strip()
    if not PATTERN.fullmatch(part):
        raise TC2Error("not a TC2 part")
    _, params, salt, token = part.split("$")
    log_n, r, p = (int(x) for x in params.split("."))
    # Only accept known presets, so a crafted or corrupted part cannot make
    # scrypt allocate an arbitrary amount of memory.
    if (log_n, r, p) not in PRESETS.values():
        raise TC2Error("unsupported scrypt parameters %s" % params)
    salt = _b64decode(salt)
    if len(salt) != SALT_SIZE:
        raise TC2Error("invalid salt")
    key = _derive_key(password, salt, log_n, r, p)
    data = fernet_decrypt(key, _b64decode(token))
    try:
        return data.decode("utf-8")
    except UnicodeError as e:
        raise TC2Error("decrypted text is not UTF-8") from e
