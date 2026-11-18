import errno
import io
import os
import threading
import time
from pathlib import Path

from netdrive.receiver import spool
from netdrive.sender import send_files
from tests.support import listen


def _file(path: Path, size: int, marker: bytes = b"") -> None:
    if size == 0:
        path.write_bytes(b"")
        return
    if size <= len(marker):
        path.write_bytes(marker[:size])
        return
    path.write_bytes(marker + os.urandom(size - len(marker)))


def test_sizes_and_three_files(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    names = {"zero.bin": 0, "one.bin": 1, "block.bin": 64 * 1024, "over.bin": 64 * 1024 + 1, "five.bin": 5 * 1024 * 1024}
    for name, size in names.items():
        _file(src / name, size, b"MARK")
    receiver = listen(dst, limit=50)
    code = send_files([src / "zero.bin"], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert code == 0
    assert (dst / "zero.bin").read_bytes() == b""
    for name in ("one.bin", "block.bin", "over.bin", "five.bin"):
        code = send_files([src / name], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
        assert code == 0
        assert (dst / name).read_bytes() == (src / name).read_bytes()
    code = send_files([src / "one.bin", src / "zero.bin", src / "block.bin"], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert code == 0
    receiver.stop()


def test_decline_then_accept(tmp_path: Path):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    answers = {"value": False}

    def prompt(summary, offer):
        return answers["value"]

    dst = tmp_path / "dst"
    receiver = listen(dst, prompt=prompt)
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO()) == 1
    assert list(dst.glob("*.txt")) == []
    answers["value"] = True
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO()) == 0
    assert (dst / "note.txt").read_text() == "hello"
    receiver.stop()


def test_limits(tmp_path: Path, monkeypatch):
    src = tmp_path / "big.txt"
    src.write_bytes(b"12345")
    seen = []

    def prompt(summary, offer):
        seen.append(1)
        return False

    dst = tmp_path / "dst"
    receiver = listen(dst, prompt=prompt, max_size=4)
    out = io.StringIO()
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=out) == 1
    assert "limit" in out.getvalue()
    assert seen == []
    receiver.stop()

    class Usage:
        free = 4

    monkeypatch.setattr("netdrive.receiver.shutil.disk_usage", lambda _path: Usage())
    dst2 = tmp_path / "dst2"
    seen.clear()
    receiver = listen(dst2, prompt=prompt, max_size=100)
    out = io.StringIO()
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=out) == 1
    assert "free" in out.getvalue()
    receiver.stop()

    class Enough:
        free = 5

    monkeypatch.setattr("netdrive.receiver.shutil.disk_usage", lambda _path: Enough())
    dst3 = tmp_path / "dst3"
    receiver = listen(dst3, prompt=prompt, max_size=5)
    send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert seen == [1]
    receiver.stop()


def test_enospc(tmp_path: Path, monkeypatch):
    def boom(_handle, _data):
        raise OSError(errno.ENOSPC, "No space")

    monkeypatch.setattr("netdrive.receiver.spool", boom)
    src = tmp_path / "a.txt"
    src.write_bytes(b"hello-disk")
    dst = tmp_path / "dst"
    receiver = listen(dst)
    code = send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert code == 2
    assert list(dst.glob("*.txt")) == []
    receiver.stop()
    assert spool is not None


def test_changed_bytes_fail_hash(tmp_path: Path):
    src = tmp_path / "flip.txt"
    src.write_bytes(b"abcdef")

    def flip(_path: Path):
        src.write_bytes(b"abcdeg")

    dst = tmp_path / "dst"
    receiver = listen(dst)
    code = send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO(), on_hashed=flip)
    assert code == 3
    assert list(dst.glob("*.txt")) == []
    receiver.stop()


def test_queue_and_busy(tmp_path: Path):
    hold = threading.Event()
    started = threading.Event()

    def prompt(summary, offer):
        if "first.txt" in summary:
            started.set()
            assert hold.wait(5)
        return True

    dst = tmp_path / "dst"
    receiver = listen(dst, prompt=prompt)
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    third = tmp_path / "third.txt"
    first.write_text("1")
    second.write_text("2")
    third.write_text("3")
    results = []

    def run(path, slot):
        results.append((slot, send_files([path], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())))

    threading.Thread(target=run, args=(first, 1)).start()
    assert started.wait(3)
    threading.Thread(target=run, args=(second, 2)).start()
    time.sleep(0.4)
    busy = io.StringIO()
    code = send_files([third], "127.0.0.1", receiver.port, "Ada", out=busy)
    assert code == 1
    assert "busy" in busy.getvalue().lower()
    hold.set()
    for _ in range(50):
        if len(results) >= 2:
            break
        time.sleep(0.1)
    assert (1, 0) in results and (2, 0) in results
    receiver.stop()
