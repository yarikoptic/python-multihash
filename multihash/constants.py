"""Constants used by multihash."""

#: Individual hash codes
SHA1 = 0x11
SHA2_256 = 0x12
SHA2_512 = 0x13
SHA3 = 0x14
BLAKE2B = 0x40
BLAKE2S = 0x41

#: Map of name to code
NAMES = {
    'sha1':     SHA1,
    'sha2-256': SHA2_256,
    'sha2-512': SHA2_512,
    'sha3':     SHA3,
    'blake2b':  BLAKE2B,
    'blake2s':  BLAKE2S,
}

#: Map of code to name
CODES = {
    SHA1:     'sha1',
    SHA2_256: 'sha2-256',
    SHA2_512: 'sha2-512',
    SHA3:     'sha3',
    BLAKE2B:  'blake2b',
    BLAKE2S:  'blake2s',
}
