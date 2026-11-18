"""Show that the verification code matches in an honest run and differs under a proxy."""

from __future__ import annotations

import socket
import threading

from netdrive.channel import SecureChannel
from netdrive.protocol import MSG_PING


def _listen() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock


def honest_codes() -> tuple[str, str]:
    """Both ends of one handshake. The codes are the same."""
    gate = _listen()
    found: dict[str, str] = {}

    def responder() -> None:
        conn, _addr = gate.accept()
        chan = SecureChannel.accept(conn)
        found["receiver"] = chan.session_code
        kind, _payload = chan.recv(timeout=5)
        if kind == MSG_PING:
            chan.send(MSG_PING, b"ok")
        chan.close()

    threading.Thread(target=responder, daemon=True).start()
    client = socket.create_connection(gate.getsockname())
    chan = SecureChannel.connect(client)
    found["sender"] = chan.session_code
    chan.send(MSG_PING, b"ping")
    chan.recv(timeout=5)
    chan.close()
    gate.close()
    return found["sender"], found["receiver"]


def mitm_codes() -> tuple[str, str]:
    """A proxy terminates both handshakes, so each side sees a different code."""
    real = _listen()
    proxy = _listen()
    found: dict[str, str] = {}

    def receiver() -> None:
        conn, _addr = real.accept()
        chan = SecureChannel.accept(conn)
        found["receiver"] = chan.session_code
        kind, payload = chan.recv(timeout=5)
        if kind == MSG_PING:
            chan.send(MSG_PING, payload)
        chan.close()

    def sender() -> None:
        conn = socket.create_connection(proxy.getsockname())
        chan = SecureChannel.connect(conn)
        found["sender"] = chan.session_code
        chan.send(MSG_PING, b"ping")
        chan.recv(timeout=5)
        chan.close()

    threading.Thread(target=receiver, daemon=True).start()
    threading.Thread(target=sender, daemon=True).start()
    left, _addr = proxy.accept()
    toward_sender = SecureChannel.accept(left)
    right = socket.create_connection(real.getsockname())
    toward_receiver = SecureChannel.connect(right)
    kind, payload = toward_sender.recv(timeout=5)
    toward_receiver.send(kind, payload)
    kind, payload = toward_receiver.recv(timeout=5)
    toward_sender.send(kind, payload)
    toward_sender.close()
    toward_receiver.close()
    proxy.close()
    real.close()
    return found["sender"], found["receiver"]


def run_demo() -> str:
    """Honest MATCH, then MITM MISMATCH, then the one-sentence limit."""
    left, right = honest_codes()
    honest = "MATCH" if left == right else "MISMATCH"
    poisoned_left, poisoned_right = mitm_codes()
    poisoned = "MATCH" if poisoned_left == poisoned_right else "MISMATCH"
    return "\n".join(
        [
            f"Honest run: sender {left} | receiver {right} -> {honest}",
            f"MITM run: sender {poisoned_left} | receiver {poisoned_right} -> {poisoned}",
            "The program does not detect this by itself. A person has to compare the codes. "
            "Eight digits can be ground; the identity path adds a commit before the code is shown.",
        ]
    )


if __name__ == "__main__":
    print(run_demo())
