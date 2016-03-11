# coding: utf-8
import six
import multihash


def test_encode_sha1():
    mh = multihash.MultiHash('sha1', 'a', 1)
    assert mh.encode() == six.b('\x11\x01a')


def test_encode_sha1_nolen():
    mh = multihash.MultiHash('sha1', 'a')
    assert mh.encode() == six.b('\x11\x01a')


def test_encode_sha1_utf8():
    digest = '💻'
    mh = multihash.MultiHash('sha1', digest)
    encoded = mh.encode()
    assert encoded == six.b('\x11\x04\xf0\x9f\x92\xbb')
    assert multihash.decode(encoded).digest == digest
