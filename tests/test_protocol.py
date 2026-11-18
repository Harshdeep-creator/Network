import pytest

from netdrive.errors import ProtocolError
from netdrive.protocol import encode_offer, parse_manifest, parse_offer


def test_offer_validation():
    good = encode_offer("Maya", [{"name": "a.txt", "size": 3}])
    parsed = parse_offer(good)
    assert parsed["files"][0]["size"] == 3
    body = good.decode().replace('"v":1', '"v":2')
    with pytest.raises(ProtocolError):
        parse_offer(body.encode())
    missing = b'{"v":1,"offer_id":"0011223344556677","sender_nick":"Maya"}'
    with pytest.raises(ProtocolError):
        parse_offer(missing)
    negative = encode_offer("Maya", [{"name": "a.txt", "size": 1}]).decode().replace('"size":1', '"size":-1')
    with pytest.raises(ProtocolError):
        parse_offer(negative.encode())
    many = encode_offer("Maya", [{"name": f"{i}.txt", "size": 1} for i in range(101)])
    with pytest.raises(ProtocolError):
        parse_offer(many)
    with pytest.raises(ProtocolError):
        parse_manifest(b'["../x"]')
    assert parse_manifest(b'["notes/a.txt"]') == ["notes/a.txt"]
