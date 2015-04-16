import pytest
import multihash

@pytest.mark.parametrize('args,exception', (
    (('frob-35', 'a'), multihash.exceptions.UnknownCode),
    (('sha1', 'a', 100), multihash.exceptions.InconsistentLen),
    (('sha1', 'a' * 200, 200), multihash.exceptions.LenNotSupported),
    (('sha1', 'a' * 200), multihash.exceptions.LenNotSupported),
))
def test_decode_raises(args, exception):
    with pytest.raises(exception):
        multihash.MultiHash(*args)

def test_object_eq():
    a = multihash.MultiHash('sha1', 'a')
    b = multihash.MultiHash('sha1', 'a')
    assert a == b


def test_object_neq():
    a = multihash.MultiHash('sha1', 'a')
    b = multihash.MultiHash('sha1', 'b')
    assert a != b
