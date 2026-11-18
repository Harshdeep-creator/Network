import io
import time
from pathlib import Path

from netdrive.errors import ProtocolError
from netdrive.protocol import parse_offer
from netdrive.sender import send_text
from tests.support import listen


def test_text_note(tmp_path: Path):
    dst = tmp_path / "dst"
    receiver = listen(dst)
    assert send_text("127.0.0.1", receiver.port, "Ada", "meet at the lab", out=io.StringIO()) == 0
    for _ in range(30):
        if receiver.notes:
            break
        time.sleep(0.05)
    assert receiver.notes == ["meet at the lab"]
    assert list(dst.glob("*.txt")) == []
    assert send_text("127.0.0.1", receiver.port, "Ada", "x" * 5000, out=io.StringIO()) == 2
    try:
        parse_offer(
            b'{"v":1,"offer_id":"0011223344556677","sender_nick":"Ada","files":[{"name":"n.txt","size":1,"mime":"text/plain"}],"text":"'
            + b"y" * 5000
            + b'"}'
        )
        assert False
    except ProtocolError:
        pass
    receiver.stop()
