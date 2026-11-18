import io
import socket
import threading
from pathlib import Path

from netdrive.receiver import accept_offer
from netdrive.sender import send_files
from tests.support import listen


def test_no_plaintext_name_or_marker(tmp_path: Path):
    marker = b"MARKER-9f3a-unique-string-not-random"
    src = tmp_path / "secret-name.txt"
    src.write_bytes(marker + b" hello")
    dst = tmp_path / "dst"
    receiver = listen(dst)
    gate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    gate.bind(("127.0.0.1", 0))
    gate.listen(1)
    blob = bytearray()

    def proxy():
        left, _addr = gate.accept()
        right = socket.create_connection(("127.0.0.1", receiver.port))

        def copy(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    blob.extend(data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threading.Thread(target=copy, args=(left, right), daemon=True).start()
        copy(right, left)

    threading.Thread(target=proxy, daemon=True).start()
    code = send_files([src], *gate.getsockname(), "Ada", out=io.StringIO())
    assert code == 0
    assert marker not in blob
    assert b"secret-name.txt" not in blob
    gate.close()
    receiver.stop()


def test_accept_only_from_prompt_and_closed_stdin(tmp_path: Path, monkeypatch):
    import sys

    source = Path("src/netdrive/receiver.py").read_text(encoding="utf-8")
    hits = [line.strip() for line in source.splitlines() if "chan.send(MSG_ACCEPT" in line]
    assert hits == ['chan.send(MSG_ACCEPT, b"")']
    assert "def accept_offer" in source
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    from netdrive.receiver import production_prompt

    assert production_prompt("Incoming", {}) is False
    cli = Path("src/netdrive/cli.py").read_text(encoding="utf-8")
    assert "--yes" not in cli
    accept_offer  # the function exists and is the only sender of ACCEPT
