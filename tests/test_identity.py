from pathlib import Path

from netdrive.contacts import Contacts
from netdrive.crypto import forced_distinct_prefix, recognizes, rotating_id
from netdrive.identity import identity_path, load_identity, public_raw, reset_identity


def test_key_change_block_and_rotation(tmp_path: Path):
    book = Contacts(tmp_path / "contacts.json")
    book.add("Maya", "aa" * 32, "bb" * 32, auto=False)
    assert book.key_changed("Maya", "cc" * 32)
    assert not book.key_changed("Maya", "aa" * 32)
    book.block("cc" * 32)
    assert book.is_blocked("cc" * 32)
    assert not book.may_auto("Maya", 10)
    book.add("Maya", "aa" * 32, "bb" * 32, auto=True, limit=100)
    assert book.may_auto("Maya", 100)
    assert not book.may_auto("Maya", 101)
    key = load_identity(identity_path(tmp_path))
    first = public_raw(key).hex()
    second = public_raw(reset_identity(identity_path(tmp_path))).hex()
    assert first != second
    secret = b"secret!!"
    token = rotating_id(secret, b"\x10" * 8)
    other = rotating_id(secret, forced_distinct_prefix(token[:8]))
    assert recognizes(secret, token) and not recognizes(b"nope!!!!", other)
