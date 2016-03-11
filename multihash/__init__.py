"""hashlib compatible multihash implementation."""


__all__ = ('MultiHash', 'decode', 'encode', 'is_app_code', 'is_valid_code')

from .multihash import MultiHash, decode, encode
from .constants import CODES
from .compat import integer_types


def is_app_code(code):
    """Check if the code is an application specific code.

    >>> is_app_code(SHA1)
    False
    >>> is_app_code(0)
    True
    """
    if isinstance(code, integer_types):
        return code >= 0 and code < 0x10

    else:
        return False


def is_valid_code(code):
    """Check if the digest algorithm code is valid.

    >>> is_valid_code(SHA1)
    True
    >>> is_valid_code(0)
    True
    """
    if is_app_code(code):
        return True

    elif isinstance(code, integer_types):
        return code in CODES

    else:
        return False
