import hashlib
import io
import socket
import threading
from pathlib import Path

from netdrive.channel import SecureChannel
from netdrive.protocol import MSG_ACCEPT, MSG_OFFER, encode_offer
from netdrive.resume import purge_expired, save_have
from netdrive.sender import send_files
from tests.support import listen


def test_resume_after_drop(tmp_path: Path):
    src = tmp_path / "book.bin"
    src.write_bytes(b"R" * (70 * 1024))
    digest = hashlib.sha256(src.read_bytes()).digest()
    dst = tmp_path / "dst"
    # Pretend two chunks already arrived, then finish the file.
    partial = dst / ".netdrive-tmp" / digest.hex() / "data.part"
    partial.parent.mkdir(parents=True)
    partial.write_bytes(b"R" * (64 * 1024))
    save_have(dst, digest, src.stat().st_size, {0}, created=1.0)
    receiver = listen(dst)
    code = send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert code == 0
    assert (dst / "book.bin").read_bytes() == src.read_bytes()
    old = dst / ".netdrive-tmp" / "ab" / "state.json"
    old.parent.mkdir(parents=True)
    old.write_text('{"created": 0, "size": 1, "have": []}', encoding="utf-8")
    purge_expired(dst, now=8 * 24 * 3600)
    assert not old.exists()
    receiver.stop()


def test_truncated_stream_leaves_no_finished_file(tmp_path: Path):
    dst = tmp_path / "dst"
    receiver = listen(dst)
    sock = socket.create_connection(("127.0.0.1", receiver.port))
    chan = SecureChannel.connect(sock)
    chan.send(MSG_OFFER, encode_offer("Ada", [{"name": "cut.txt", "size": 10}]))
    assert chan.recv(timeout=5)[0] == MSG_ACCEPT
    chan.close()
    for _ in range(20):
        threading.Event().wait(0.05)
        if receiver._active is False:
            break
    assert not (dst / "cut.txt").exists()
    receiver.stop()
