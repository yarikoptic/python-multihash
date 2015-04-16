import struct
from . import exceptions as exc

SHA1     = 0x11
SHA2_256 = 0x12
SHA2_512 = 0x13
SHA3     = 0x14
BLAKE2B  = 0x40
BLAKE2S  = 0x41

NAMES = {
    'sha1':     SHA1,
    'sha2-256': SHA2_256,
    'sha2-512': SHA2_512,
    'sha3':     SHA3,
    'blake2b':  BLAKE2B,
    'blake2s':  BLAKE2S,
}

CODES = {
    SHA1:     'sha1',
    SHA2_256: 'sha2-256',
    SHA2_512: 'sha2-512',
    SHA3:     'sha3',
    BLAKE2B:  'blake2b',
    BLAKE2S:  'blake2s',
}

INCONSISTEN_LEN_MSG = 'Digest length should be equal to specified length.'


def ident_name_code(ident):
    'Coerce hash ident (name or code) to tuple (name, code)'
    if ident in CODES:
        return CODES[ident], ident
    if ident in NAMES:
        return ident, NAMES[ident]
    raise exc.UnknownCode("Unknown multihash code or name: {0}".format(ident))


class MultiHash(object):

    def __init__(self, ident, digest, length=None):
        if length and len(digest) != length:
            raise exc.InconsistentLen(INCONSISTEN_LEN_MSG)
        else:
            length = len(digest)
        if length > 127:
            raise exc.LenNotSupported('Multihash does not yet support digests '
                                      'longer than 127 bytes')
        name, code = ident_name_code(ident)
        self.name = name
        self.code = code
        self.length = length
        self.digest = digest

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
        return struct.pack(struct_fmt, self.code, self.length, *digest_bytes)


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
        raise exc.InconsistentLen(INCONSISTEN_LEN_MSG)
    return MultiHash(code, digest, length)
