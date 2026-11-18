"""The ND01 handshake and the encrypted frames that follow it."""

from __future__ import annotations

import socket
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from netdrive.crypto import derive_keys, generate_ephemeral, nonce, session_code, transcript
from netdrive.errors import AuthError, HandshakeError, ProtocolError
from netdrive.protocol import KNOWN_TYPES

MAGIC = b"ND01"
VERSION = 1
HELLO = 37
MAX_FRAME = 1024 * 1024
AAD = b"ND01"


def _read_exact(sock: socket.socket, count: int) -> bytes:
    """Read `count` bytes or raise ConnectionError."""
    buf = bytearray()
    while len(buf) < count:
        try:
            piece = sock.recv(count - len(buf))
        except TimeoutError as exc:
            raise TimeoutError("Timed out waiting for the other computer.") from exc
        except OSError as exc:
            raise ConnectionError("The connection closed.") from exc
        if not piece:
            raise ConnectionError("The connection closed.")
        buf += piece
    return bytes(buf)


def _write_all(sock: socket.socket, data: bytes) -> None:
    """Send every byte."""
    try:
        sock.sendall(data)
    except OSError as exc:
        raise ConnectionError("The connection closed.") from exc


class SecureChannel:
    """One direction pair of ChaCha20-Poly1305 keys and their counters."""

    def __init__(
        self,
        sock: socket.socket,
        key_send: bytes,
        key_recv: bytes,
        code: str,
    ) -> None:
        self._sock = sock
        self._send_key = ChaCha20Poly1305(key_send)
        self._recv_key = ChaCha20Poly1305(key_recv)
        self.session_code = code
        self._send_ctr = 0
        self._recv_ctr = 0
        self.violations = 0
        self._closed = False
        self.transcript = b""

    @classmethod
    def connect(cls, sock: socket.socket, timeout: float = 10.0) -> "SecureChannel":
        """Handshake as the initiator (the sender)."""
        sock.settimeout(timeout)
        private, own_pub = generate_ephemeral()
        _write_all(sock, MAGIC + bytes([VERSION]) + own_pub)
        peer_pub = cls._read_hello(sock)
        key_i2r, key_r2i = derive_keys(private, peer_pub, own_pub, peer_pub)
        shared = private.exchange(X25519PublicKey.from_public_bytes(peer_pub))
        del private
        channel = cls(sock, key_i2r, key_r2i, session_code(own_pub, peer_pub))
        channel.transcript = transcript(shared, own_pub, peer_pub)
        return channel

    @classmethod
    def accept(cls, sock: socket.socket, timeout: float = 10.0) -> "SecureChannel":
        """Handshake as the responder (the receiver)."""
        sock.settimeout(timeout)
        peer_pub = cls._read_hello(sock)
        private, own_pub = generate_ephemeral()
        _write_all(sock, MAGIC + bytes([VERSION]) + own_pub)
        key_i2r, key_r2i = derive_keys(private, peer_pub, peer_pub, own_pub)
        shared = private.exchange(X25519PublicKey.from_public_bytes(peer_pub))
        del private
        channel = cls(sock, key_r2i, key_i2r, session_code(peer_pub, own_pub))
        channel.transcript = transcript(shared, peer_pub, own_pub)
        return channel

    @staticmethod
    def _read_hello(sock: socket.socket) -> bytes:
        try:
            blob = _read_exact(sock, HELLO)
        except TimeoutError as exc:
            raise HandshakeError("The other computer did not answer the handshake.") from exc
        except ConnectionError as exc:
            raise HandshakeError("The handshake ended early.") from exc
        if blob[:4] != MAGIC or blob[4] != VERSION:
            raise HandshakeError("This does not look like a NetDrive connection.")
        return blob[5:]

    def send(self, msg_type: int, payload: bytes = b"") -> None:
        """Encrypt one message. The counter is local; it is not written on the wire."""
        if self._closed:
            raise ConnectionError("The connection is already closed.")
        if self._send_ctr >= 2**64:
            raise ProtocolError("The frame counter would wrap. The session has to stop.")
        body = bytes([msg_type & 0xFF]) + payload
        token = self._send_key.encrypt(nonce(self._send_ctr), body, AAD)
        self._send_ctr += 1
        _write_all(self._sock, struct.pack(">I", len(token)) + token)

    def recv(self, timeout: float | None = None) -> tuple[int, bytes]:
        """Decrypt the next frame. A bad tag ends the session."""
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            header = _read_exact(self._sock, 4)
        except TimeoutError:
            raise
        length = struct.unpack(">I", header)[0]
        if length <= 0 or length > MAX_FRAME:
            self.close()
            raise ProtocolError("A frame had an impossible length, so the session stopped.")
        try:
            token = _read_exact(self._sock, length)
        except TimeoutError:
            raise
        try:
            plain = self._recv_key.decrypt(nonce(self._recv_ctr), token, AAD)
        except Exception as exc:
            self.close()
            raise AuthError("Transfer stopped: data was altered.") from exc
        self._recv_ctr += 1
        if not plain:
            self._violation("A frame was empty.")
        msg_type = plain[0]
        if msg_type not in KNOWN_TYPES:
            self._violation("A frame had an unknown type.")
        return msg_type, plain[1:]

    def _violation(self, message: str) -> None:
        self.violations += 1
        if self.violations >= 3:
            self.close()
            raise ProtocolError("Too many malformed frames. The session stopped.")
        raise ProtocolError(message)

    def close(self) -> None:
        """Close the socket. Repeated calls do nothing."""
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass
