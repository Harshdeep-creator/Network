import io
from pathlib import Path

import pytest

from netdrive.errors import ProtocolError
from netdrive.protocol import parse_manifest
from netdrive.sender import send_files
from tests.support import listen


def test_folder_round_trip_and_reject(tmp_path: Path):
    root = tmp_path / "pack"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "a.txt").write_text("alpha")
    dst = tmp_path / "dst"
    receiver = listen(dst)
    assert send_files([root], "127.0.0.1", receiver.port, "Ada", out=io.StringIO()) == 0
    assert (dst / "notes" / "a.txt").read_text() == "alpha"
    with pytest.raises(ProtocolError):
        parse_manifest(b'["../evil.txt"]')
    receiver.stop()
