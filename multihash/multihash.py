"""Multihash logic."""

import collections
import struct
from . import exceptions as exc
from . import constants, compat


def len_compat(digest):
    """Python version agnostic buffer length comparison."""
    if compat.PY3 and isinstance(digest, str):
        return len(digest.encode('utf8'))
    if compat.PY2 and isinstance(digest, unicode):
        return len(digest.encode('utf8'))
    return len(digest)


def digest_compat(digest):
    """Python version agnostic digest decoding."""
    if compat.PY3 and isinstance(digest, bytes):
        return digest.decode('utf8')
    return digest


def ident_name_code(ident):
    """Coerce hash ident (name or code) to tuple (name, code)."""
    if ident in constants.CODES:
        return constants.CODES[ident], ident
    if ident in constants.NAMES:
        return ident, constants.NAMES[ident]
    raise exc.UnknownCode("Unknown multihash code or name: {0}".format(ident))


#: Base class that inherits from the `collections.namedtuple` interface.
_MultiHash = collections.namedtuple('MultiHash', 'name code length digest')


class MultiHash(_MultiHash):  # NOQA

    """Multihash implementation compatible with Python hashlib."""

    def __new__(cls, ident, digest, length=None):
        """Create a new MultiHash class instance."""
        len_digest = len_compat(digest)
        if length and len_digest != length:
            raise exc.InconsistentLen('Digest length should be equal to '
                                      'specified length.')
        if not length:
            length = len_digest
        if length > 127:
            raise exc.LenNotSupported('Multihash does not yet support digests '
                                      'longer than 127 bytes')
        name, code = ident_name_code(ident)
        init_args = cls, name, code, length, digest_compat(digest)
        return super(MultiHash, cls).__new__(*init_args)

    def __eq__(self, other):
        """Test if the multihash is equal to other."""
        if not isinstance(other, MultiHash):
            return False

        conditions = (
            self.name == other.name,
            self.code == other.code,
            self.length == other.length,
            self.digest == other.digest,
        )
        return all(conditions)

    def encode(self):
        """Encode the multihash to a binary buffer."""
        struct_fmt = "BB{0}s".format(self.length)
        if compat.PY3:
            digest = self.digest.encode('utf-8')
        else:
            digest = self.digest
        struct_args = self.code, self.length, digest
        return struct.pack(struct_fmt, *struct_args)


def decode(mh_bytes):
    r"""Decode a hash from the given Multihash bytes.

    After validating the hash type and length in the two prefix bytes, this
    function removes them and returns the raw hash.

    >>> encoded = b'\x11\x14\xc3\xd4XGWbx`AAh\x01%\xa4o\xef9Nl('
    >>> bytearray(decode(encoded))
    bytearray(b'\xc3\xd4XGWbx`AAh\x01%\xa4o\xef9Nl(')

    >>> decode(encoded) == encoded[2:] == hashlib.sha1(b'thanked').digest()
    True
    """
    len_mh_bytes = len(mh_bytes)
    if len_mh_bytes > 127:
        fmt_str = 'Multihash {0} bytes long. Must be < 129 bytes'
        raise exc.TooLong(fmt_str.format(len_mh_bytes))
    if len_mh_bytes < 3:
        fmt_str = 'Multihash {0} bytes long. Must be > 3 bytes'
        raise exc.TooShort(fmt_str.format(len_mh_bytes))
    len_digest = len(mh_bytes[2:])
    (code, length), digest = struct.unpack('BB', mh_bytes[:2]), mh_bytes[2:]
    if len_digest != length:
        raise exc.InconsistentLen('Digest length should be equal to specified '
                                  'length.')
    return MultiHash(code, digest, length)


def encode(message, code):
    r"""Encode a message along with the specified function code.

    >>> from multihash import encode, SHA1, SHA3
    >>> from multihash.compat import b
    >>> encoded = encode('testing', SHA1)
    >>> len(encoded)
    22
    >>> encoded == b('\\x11\\x07')
    True

    >>> encoded = encode('works with sha3?', SHA3)
    >>> len(encoded)
    66
    >>> encoded == b('\\x14\\x10')
    True
    """
    return MultiHash(code, message).encode()
