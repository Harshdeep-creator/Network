import io
import time
from pathlib import Path

from netdrive.sender import send_files
from tests.support import listen


def test_cancel_removes_partials(tmp_path: Path):
    src = tmp_path / "big.bin"
    src.write_bytes(b"z" * 200_000)
    dst = tmp_path / "dst"
    receiver = listen(dst)
    started = time.monotonic()
    code = send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO(), cancel_after=1)
    assert code == 1
    deadline = started + 2
    while time.monotonic() < deadline and list(dst.rglob("*.part")):
        time.sleep(0.05)
    assert time.monotonic() - started < 2
    assert list(dst.rglob("*.part")) == []
    assert not (dst / "big.bin").exists()
    receiver.stop()
