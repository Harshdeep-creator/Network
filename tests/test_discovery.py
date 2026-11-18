import pytest

from netdrive.discovery import Peer, expire_peers, parse_beacon, parse_hostport


def test_beacon_and_hostport():
    good = b'{"app":"netdrive","v":1,"nick":"Maya","port":5000,"sid":"abcd1234"}'
    peer = parse_beacon(good, "127.0.0.1", 10.0, own_sid="ffff")
    assert peer == Peer("Maya", "127.0.0.1", 5000, "abcd1234", 10.0)
    assert parse_beacon(good, "127.0.0.1", 10.0, own_sid="abcd1234") is None
    assert parse_beacon(b"not-json", "127.0.0.1", 1, "") is None
    assert parse_beacon(b'{"app":"other","v":1,"nick":"a","port":1,"sid":"b"}', "127.0.0.1", 1, "") is None
    assert parse_beacon(b"x" * 600, "127.0.0.1", 1, "") is None
    peers = [Peer("Maya", "127.0.0.1", 1, "abc", 0.0)]
    assert expire_peers(peers, now=16.0) == []
    assert expire_peers(peers, now=10.0) == peers
    assert parse_hostport("192.168.1.20:5000") == ("192.168.1.20", 5000)
    with pytest.raises(ValueError):
        parse_hostport("localhost:80")
    with pytest.raises(ValueError):
        parse_hostport("10.0.0.1:70000")
    with pytest.raises(ValueError):
        parse_hostport("10.0.0.1")
