# coding: utf-8
import multihash
from multihash.compat import b


ENCODE_TESTS = (
    (('a', 'sha1'), b('\x11\x01a')),
    (('💻', 'sha1'), b('\x11\x04\xf0\x9f\x92\xbb')),
)


def test_encode_sha1():
    """Test encoding."""
    mh = multihash.MultiHash('sha1', 'a', 1)
    assert mh.encode() == b('\x11\x01a')


def test_encode_sha1_nolen():
    """Test encoding without a preset lenght."""
    mh = multihash.MultiHash('sha1', 'a')
    assert mh.encode() == b('\x11\x01a')


def test_encode_sha1_utf8():
    """Test encoding wide character UTF-8."""
    digest = '💻'
    mh = multihash.MultiHash('sha1', digest)
    encoded = mh.encode()
    assert encoded == b('\x11\x04\xf0\x9f\x92\xbb')
    assert multihash.decode(encoded).digest == digest


def test_encode():
    """Test multihash.encode compatability function."""
    for (test, code), want in ENCODE_TESTS:
        got = multihash.encode(test, code)
        assert got == want
