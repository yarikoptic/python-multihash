import collections
import struct
from . import exceptions as exc
from . import constants


def ident_name_code(ident):
    'Coerce hash ident (name or code) to tuple (name, code)'
    if ident in constants.CODES:
        return constants.CODES[ident], ident
    if ident in constants.NAMES:
        return ident, constants.NAMES[ident]
    raise exc.UnknownCode("Unknown multihash code or name: {0}".format(ident))


_MultiHash = collections.namedtuple('MultiHash', 'name code length digest')
class MultiHash(_MultiHash):  # NOQA

    def __new__(cls, ident, digest, length=None):
        if length and len(digest) != length:
            raise exc.InconsistentLen('Digest length should be equal to '
                                      'specified length.')
        else:
            length = len(digest)
        if length > 127:
            raise exc.LenNotSupported('Multihash does not yet support digests '
                                      'longer than 127 bytes')
        name, code = ident_name_code(ident)
        return super(MultiHash, cls).__new__(cls, name, code, length, digest)

    def __eq__(self, other):
        conditions = (
            self.name == other.name,
            self.code == other.code,
            self.length == other.length,
            self.digest == other.digest,
        )
        return all(conditions)

    def encode(self):
        struct_fmt = "BB{0}s".format(self.length)
        digest_bytes = map(ord, self.digest)
        return struct.pack(struct_fmt, self.code, self.length, self.digest)


def decode(mh_bytes):
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
