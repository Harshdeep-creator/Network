import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from netdrive.crypto import (
    commit,
    derive_keys,
    forced_distinct_prefix,
    generate_ephemeral,
    identity_code,
    recognizes,
    reject_shared,
    rotating_id,
    session_code,
    transcript,
)
from netdrive.errors import HandshakeError


def test_session_code_known_answer_and_order():
    left = b"a" * 32
    right = b"b" * 32
    digest = hashlib.sha256(b"netdrive-v0.1 sas" + left + right).digest()
    number = int.from_bytes(digest[:4], "big") % 10**8
    expect = f"{number // 10000:04d} {number % 10000:04d}"
    assert session_code(left, right) == expect
    assert session_code(left, right) != session_code(right, left)


def test_keys_mirror_and_zero_secret_is_rejected():
    alice, alice_pub = generate_ephemeral()
    bob, bob_pub = generate_ephemeral()
    a_i, a_r = derive_keys(alice, bob_pub, alice_pub, bob_pub)
    b_i, b_r = derive_keys(bob, alice_pub, alice_pub, bob_pub)
    assert a_i == b_i and a_r == b_r

    class Fake:
        def exchange(self, _peer):
            return b"\x00" * 32

    try:
        derive_keys(Fake(), b"\x11" * 32, b"\x22" * 32, b"\x33" * 32)
        assert False
    except HandshakeError:
        pass
    try:
        reject_shared(b"\x00" * 32)
        assert False
    except HandshakeError:
        pass


def test_identity_commit_and_rotating_id():
    reveal_i = b"i" * 32
    reveal_r = b"r" * 32
    assert hashlib.sha256(reveal_i).digest() == commit(reveal_i)
    shared = b"\x02" * 32
    material = transcript(shared, b"e" * 32, b"f" * 32)
    code = identity_code(material, b"s" * 32, b"t" * 32, reveal_i, reveal_r)
    assert code == identity_code(material, b"s" * 32, b"t" * 32, reveal_i, reveal_r)
    secret = b"contact-secret"
    first = rotating_id(secret, b"\x01" * 8)
    second = rotating_id(secret, forced_distinct_prefix(first[:8]))
    assert first != second
    assert all(a != b for a, b in zip(first, second))
    assert recognizes(secret, first)
    assert not recognizes(b"other-secret", first)
    X25519PrivateKey.generate()
