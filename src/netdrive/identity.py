"""Ed25519 identity stored in the receive folder, not in a phone keystore."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from netdrive.crypto import commit, identity_code, load_identity, public_raw, reset_identity
from netdrive.errors import HandshakeError
from netdrive.protocol import MSG_COMMIT, MSG_REVEAL

__all__ = [
    "identity_path",
    "load_identity",
    "public_raw",
    "reset_identity",
    "begin_identity",
    "accept_identity",
    "contact_uri",
    "parse_contact_uri",
    "Ed25519PrivateKey",
]


def identity_path(directory: Path) -> Path:
    """Where this machine's private key lives."""
    return Path(directory) / ".netdrive" / "identity.key"


def contact_secret_path(directory: Path) -> Path:
    """The secret used in a contact QR. It is not the signing key."""
    return Path(directory) / ".netdrive" / "contact.secret"


def load_contact_secret(directory: Path) -> bytes:
    """Load or create the 32-byte contact secret."""
    path = contact_secret_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes()
    secret = os.urandom(32)
    path.write_bytes(secret)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return secret


def _key_bytes(text: str) -> bytes:
    """Accept a 32-byte key as hex or as base64url."""
    cleaned = text.strip()
    if len(cleaned) == 64 and all(char in "0123456789abcdefABCDEF" for char in cleaned):
        raw = bytes.fromhex(cleaned)
    else:
        pad = "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            raw = base64.urlsafe_b64decode(cleaned + pad)
        except Exception as exc:
            raise ValueError("That contact link is missing a key.") from exc
    if len(raw) != 32:
        raise ValueError("That contact link is missing a key.")
    return raw


def _key_token(raw: bytes) -> str:
    """base64url without padding, which is what the contact QR carries."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def contact_uri(pk_hex: str, secret_hex: str) -> str:
    """App link. It has a public key and a secret, and no name or address."""
    return f"netdrive://c?pk={_key_token(_key_bytes(pk_hex))}&secret={_key_token(_key_bytes(secret_hex))}"


def contact_http(host: str, port: int, pk_hex: str, secret_hex: str) -> str:
    """A normal address a phone can open after scanning the QR."""
    pk = _key_token(_key_bytes(pk_hex))
    secret = _key_token(_key_bytes(secret_hex))
    return f"http://{host}:{port}/c?pk={pk}&secret={secret}"


def parse_contact_uri(text: str) -> tuple[str, str]:
    """Read pk and secret from a netdrive:// link or from the http page link."""
    parsed = urlparse(text.strip())
    if parsed.scheme == "netdrive" and parsed.netloc != "c":
        raise ValueError("That is not a NetDrive contact link.")
    if parsed.scheme not in {"netdrive", "http", "https", ""}:
        raise ValueError("That is not a NetDrive contact link.")
    query = parse_qs(parsed.query)
    pk = (query.get("pk") or [""])[0]
    secret = (query.get("secret") or [""])[0]
    return _key_bytes(pk).hex(), _key_bytes(secret).hex()


def begin_identity(chan, private: Ed25519PrivateKey) -> str:
    """Initiator: commit, then reveal. Returns the code both sides can show."""
    reveal = os.urandom(32)
    own = public_raw(private)
    chan.send(MSG_COMMIT, commit(reveal) + own)
    kind, payload = chan.recv(timeout=10)
    if kind != MSG_COMMIT or len(payload) < 64:
        raise HandshakeError("The identity commit did not arrive.")
    their_commit, their_pub = payload[:32], payload[32:64]
    chan.send(MSG_REVEAL, reveal)
    kind, their_reveal = chan.recv(timeout=10)
    if kind != MSG_REVEAL or hashlib.sha256(their_reveal).digest() != their_commit:
        raise HandshakeError("The identity commit did not open.")
    return identity_code(chan.transcript, own, their_pub, reveal, their_reveal)


def accept_identity(chan, private: Ed25519PrivateKey, first: bytes) -> str:
    """Responder, given the initiator's commit message."""
    if len(first) < 64:
        raise HandshakeError("The identity commit did not arrive.")
    their_commit, their_pub = first[:32], first[32:64]
    reveal = os.urandom(32)
    own = public_raw(private)
    chan.send(MSG_COMMIT, commit(reveal) + own)
    kind, their_reveal = chan.recv(timeout=10)
    if kind != MSG_REVEAL or hashlib.sha256(their_reveal).digest() != their_commit:
        raise HandshakeError("The identity commit did not open.")
    chan.send(MSG_REVEAL, reveal)
    return identity_code(chan.transcript, their_pub, own, their_reveal, reveal)


def revert_visibility(mode: str, previous: str, started: float, now: float, limit: float = 600.0) -> str:
    """Everyone falls back after 10 minutes. Other modes stay put."""
    if mode == "Everyone" and now - started >= limit:
        return previous
    return mode
