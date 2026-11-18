"""Ephemeral X25519, HKDF, the session code, and the local Ed25519 identity."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from netdrive.errors import HandshakeError

INFO_KEYS = b"netdrive-v0.1 keys"
INFO_TRANSCRIPT = b"netdrive-nd02 transcript"
SAS_V1 = b"netdrive-v0.1 sas"
SAS_V2 = b"netdrive-nd02 sas"


def generate_ephemeral() -> tuple[X25519PrivateKey, bytes]:
    """Return a new X25519 private key and its 32-byte raw public key."""
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def reject_shared(shared: bytes) -> bytes:
    """Refuse the all-zero shared secret."""
    if shared == b"\x00" * 32:
        raise HandshakeError("Handshake failed: the shared secret was empty.")
    return shared


def derive_keys(
    private: X25519PrivateKey,
    peer_pub: bytes,
    init_pub: bytes,
    resp_pub: bytes,
) -> tuple[bytes, bytes]:
    """Return (key initiator-to-responder, key responder-to-initiator)."""
    peer = X25519PublicKey.from_public_bytes(peer_pub)
    shared = reject_shared(private.exchange(peer))
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=init_pub + resp_pub,
        info=INFO_KEYS,
    ).derive(shared)
    return okm[:32], okm[32:]


def transcript(shared: bytes, init_eph: bytes, resp_eph: bytes) -> bytes:
    """HKDF stand-in used in the identity-path code. This is not Noise XX."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=init_eph + resp_eph,
        info=INFO_TRANSCRIPT,
    ).derive(reject_shared(shared))


def _grouped(digest: bytes) -> str:
    number = int.from_bytes(digest[:4], "big") % 10**8
    return f"{number // 10000:04d} {number % 10000:04d}"


def session_code(init_pub: bytes, resp_pub: bytes) -> str:
    """Eight-digit code for an ephemeral session. Humans compare it."""
    digest = hashlib.sha256(SAS_V1 + init_pub + resp_pub).digest()
    return _grouped(digest)


def identity_code(
    transcript_bytes: bytes,
    init_static: bytes,
    resp_static: bytes,
    reveal_i: bytes,
    reveal_r: bytes,
) -> str:
    """Code after both sides have revealed their commit secrets."""
    digest = hashlib.sha256(
        SAS_V2 + transcript_bytes + init_static + resp_static + reveal_i + reveal_r
    ).digest()
    return _grouped(digest)


def commit(reveal: bytes) -> bytes:
    """SHA-256 commitment opened later by sending `reveal`."""
    return hashlib.sha256(reveal).digest()


def nonce(counter: int) -> bytes:
    """12-byte ChaCha nonce: 4 zero bytes and an 8-byte counter."""
    if counter < 0 or counter >= 2**64:
        raise HandshakeError("The frame counter would wrap. The session has to stop.")
    return b"\x00" * 4 + counter.to_bytes(8, "big")


def rotating_id(secret: bytes, prefix: bytes | None = None) -> bytes:
    """8 random bytes plus HMAC(secret, prefix)[:8]. A contact can recognise it."""
    head = prefix if prefix is not None else os.urandom(8)
    if len(head) != 8:
        raise ValueError("The rotating prefix must be 8 bytes.")
    mac = hmac.new(secret, head, hashlib.sha256).digest()[:8]
    return head + mac


def recognizes(secret: bytes, token: bytes) -> bool:
    """True when `token` was built with `secret`."""
    if len(token) != 16:
        return False
    expect = hmac.new(secret, token[:8], hashlib.sha256).digest()[:8]
    return hmac.compare_digest(expect, token[8:])


def forced_distinct_prefix(previous: bytes) -> bytes:
    """A new prefix that differs in every byte position from `previous`."""
    flipped = bytes(b ^ 0xFF for b in previous)
    if flipped == previous:
        flipped = bytes((b + 1) % 256 for b in previous)
    return flipped


def load_identity(path: Path) -> Ed25519PrivateKey:
    """Load the raw Ed25519 key, or create it on first use."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    private = Ed25519PrivateKey.generate()
    path.write_bytes(
        private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return private


def public_raw(private: Ed25519PrivateKey) -> bytes:
    """32-byte raw public key."""
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def reset_identity(path: Path) -> Ed25519PrivateKey:
    """Replace the key file. The caller already checked the user typed RESET."""
    if path.exists():
        path.unlink()
    return load_identity(path)


def sign_bytes(private: Ed25519PrivateKey, payload: bytes) -> bytes:
    """Ed25519 signature."""
    return private.sign(payload)


def verify_bytes(public: bytes, payload: bytes, signature: bytes) -> bool:
    """True when the signature matches. Invalid signatures return False."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, payload)
        return True
    except Exception:
        return False


def spki_der(cert) -> bytes:
    """SubjectPublicKeyInfo bytes of a certificate, for the browser code."""
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def browser_code(cert_spki: bytes, token: bytes) -> str:
    """Code shown beside the browser download. Both sides use this function."""
    digest = hashlib.sha256(cert_spki + token).digest()
    return _grouped(digest)


# serialization is imported so identity files stay Raw. Re-export keeps the
# module honest if a caller wants the same enums.
RAW = serialization.Encoding.Raw
