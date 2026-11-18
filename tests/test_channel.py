import socket
import struct
import threading

from netdrive.channel import AAD, MAX_FRAME, SecureChannel
from netdrive.crypto import nonce
from netdrive.errors import AuthError, ProtocolError
from netdrive.protocol import MSG_PING


def _pair():
    left, right = socket.socketpair()
    box = {}

    def accept():
        box["b"] = SecureChannel.accept(right)

    thread = threading.Thread(target=accept)
    thread.start()
    box["a"] = SecureChannel.connect(left)
    thread.join(timeout=5)
    return box["a"], box["b"]


def _take_frame(sock):
    header = sock.recv(4)
    while len(header) < 4:
        header += sock.recv(4 - len(header))
    length = struct.unpack(">I", header)[0]
    body = b""
    while len(body) < length:
        body += sock.recv(length - len(body))
    return header, body


def test_round_trip_and_failures():
    alice, bob = _pair()
    alice.send(MSG_PING, b"hello")
    kind, payload = bob.recv()
    assert kind == MSG_PING and payload == b"hello"
    bob.send(MSG_PING, b"back")
    assert alice.recv()[1] == b"back"

    alice.send(MSG_PING, b"frame-one")
    alice.send(MSG_PING, b"frame-two")
    first = _take_frame(bob._sock)
    second = _take_frame(bob._sock)
    flipped = second[1][:-1] + bytes([second[1][-1] ^ 0x01])
    feed, read = socket.socketpair()
    bob._sock = read
    bob._recv_ctr = 1
    feed.sendall(second[0] + flipped)
    try:
        bob.recv()
        assert False
    except AuthError:
        pass

    # Replay the first frame now that the counter has moved.
    carol_a, carol_b = _pair()
    carol_a.send(MSG_PING, b"once")
    saved = _take_frame(carol_b._sock)
    carol_b._recv_ctr = 1
    again, sink = socket.socketpair()
    carol_b._sock = sink
    again.sendall(saved[0] + saved[1])
    try:
        carol_b.recv()
        assert False
    except AuthError:
        pass

    # Reorder: deliver the second frame while the first is still expected.
    dave_a, dave_b = _pair()
    dave_a.send(MSG_PING, b"aaa")
    dave_a.send(MSG_PING, b"bbb")
    one = _take_frame(dave_b._sock)
    two = _take_frame(dave_b._sock)
    out, inn = socket.socketpair()
    dave_b._sock = inn
    out.sendall(two[0] + two[1])
    try:
        dave_b.recv()
        assert False
    except AuthError:
        pass
    assert one[1] != two[1]

    erin_a, erin_b = _pair()
    huge, sink = socket.socketpair()
    erin_b._sock = sink
    huge.sendall(struct.pack(">I", MAX_FRAME + 1))
    try:
        erin_b.recv()
        assert False
    except ProtocolError:
        pass

    for _ in range(2):
        erin_a.send(0xFE, b"x")
        try:
            # erin_b socket was replaced; use a fresh pair for violations
            break
        except ProtocolError:
            pass
    frank_a, frank_b = _pair()
    for _ in range(3):
        frank_a.send(0xFE, b"x")
        try:
            frank_b.recv()
            assert False
        except ProtocolError:
            pass
    assert frank_b.violations >= 3
    nonce(0)
    assert AAD == b"ND01"
