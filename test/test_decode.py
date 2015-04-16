import pytest
import multihash

def test_decode_sha1():
    mh_bytes = '\x11(86f7e437faa5a7fce15d1ddcb9eaeaea377667b8'
    mh = multihash.decode(mh_bytes)
    assert mh.name == 'sha1'
    assert mh.length == 40
    assert mh.code == 0x11
    assert mh.digest == '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8'

@pytest.mark.parametrize('mh_bytes,exception', (
    ('\x44\x01a', multihash.exceptions.UnknownCode),
    ('', multihash.exceptions.TooShort),
    ('\x00' * 200, multihash.exceptions.TooLong),
    ('\x11d' + 'a' * 10, multihash.exceptions.InconsistentLen),
))
def test_decode_raises(mh_bytes, exception):
    with pytest.raises(exception):
        multihash.decode(mh_bytes)
