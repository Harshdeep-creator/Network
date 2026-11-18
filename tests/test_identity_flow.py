import io
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from netdrive.contacts import Contacts
from netdrive.crypto import public_raw, rotating_id
from netdrive.identity import contact_uri, parse_contact_uri, revert_visibility
from netdrive.sender import send_files
from tests.support import listen


def test_identity_codes_match(tmp_path: Path):
    src = tmp_path / "note.txt"
    src.write_text("identity")
    seen = []

    def prompt(summary, offer):
        seen.append(summary)
        return True

    receiver = listen(tmp_path / "dst", prompt=prompt)
    private = Ed25519PrivateKey.generate()
    out = io.StringIO()
    code = send_files(
        [src],
        "127.0.0.1",
        receiver.port,
        "Ada",
        out=out,
        static_private=private,
        sender_pk=public_raw(private).hex(),
    )
    assert code == 0
    line = [row for row in out.getvalue().splitlines() if row.startswith("Verification code:")][0]
    shown = line.split(": ", 1)[1]
    assert shown in seen[0]
    receiver.stop()


def test_visibility_key_change_and_auto(tmp_path: Path):
    src = tmp_path / "a.txt"
    src.write_text("a")
    prompts = []

    def prompt(summary, offer):
        prompts.append(1)
        return True

    hidden = listen(tmp_path / "off", prompt=prompt, visibility="off")
    out = io.StringIO()
    assert send_files([src], "127.0.0.1", hidden.port, "Ada", out=out) == 1
    assert "not visible" in out.getvalue()
    assert prompts == []
    hidden.stop()

    secret = b"s" * 32
    token = rotating_id(secret, b"\x02" * 8).hex()
    allowed = listen(tmp_path / "contacts", prompt=prompt, visibility="contacts", contact_secret=secret)
    assert send_files([src], "127.0.0.1", allowed.port, "Ada", out=io.StringIO(), rotating=token) == 0
    assert prompts == [1]
    blocked = listen(tmp_path / "contacts-bad", prompt=prompt, visibility="contacts", contact_secret=secret)
    assert send_files([src], "127.0.0.1", blocked.port, "Ada", out=io.StringIO(), rotating="11" * 16) == 1
    allowed.stop()
    blocked.stop()

    book_dir = tmp_path / "keys"
    receiver = listen(book_dir, prompt=prompt)
    receiver.contacts.add("Ada", "aa" * 32, "bb" * 32)
    out = io.StringIO()
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=out, sender_pk="cc" * 32) == 1
    assert "key changed" in out.getvalue()
    receiver.contacts.add("Ada", "dd" * 32, "bb" * 32, auto=True, limit=1000)
    before = len(prompts)
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO(), sender_pk="dd" * 32) == 0
    assert len(prompts) == before
    receiver.stop()

    uri = contact_uri("ab" * 32, "cd" * 32)
    assert parse_contact_uri(uri) == ("ab" * 32, "cd" * 32)
    from netdrive.identity import contact_http
    page = contact_http("127.0.0.1", 8765, "ab" * 32, "cd" * 32)
    assert page.startswith("http://127.0.0.1:8765/c?")
    assert parse_contact_uri(page) == ("ab" * 32, "cd" * 32)
    assert revert_visibility("Everyone", "Contacts only", 0, 601) == "Contacts only"
    assert revert_visibility("Off", "Everyone", 0, 999) == "Off"
    assert isinstance(Contacts(tmp_path / "c.json"), Contacts)
