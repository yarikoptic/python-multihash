# coding: utf-8
import multihash


def test_encode_sha1():
    mh = multihash.MultiHash('sha1', 'a', 1)
    assert mh.encode() == '\x11\x01a'


def test_encode_sha1_nolen():
    mh = multihash.MultiHash('sha1', 'a')
    assert mh.encode() == '\x11\x01a'


def test_encode_sha1_utf8():
    mh = multihash.MultiHash('sha1', '💻')
    assert mh.encode() == '\x11\x04\xf0\x9f\x92\xbb'
