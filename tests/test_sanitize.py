import os
import subprocess
from pathlib import Path

import pytest

from netdrive.sanitize import is_dangerous, safe_join, sanitize_filename, unique_path


def test_names():
    assert sanitize_filename("../x") == "x"
    assert sanitize_filename("..\\x") == "x"
    assert sanitize_filename("/abs/x") == "x"
    assert sanitize_filename("C:\\win\\x") == "x"
    assert sanitize_filename("a/../../b") == "b"
    assert sanitize_filename("a\x00b.txt") == "ab.txt"
    long_name = "n" * 300 + ".txt"
    assert len(sanitize_filename(long_name).encode("utf-8")) <= 255
    assert sanitize_filename("CON.txt").startswith("_")
    assert sanitize_filename(".") == "received_file"
    assert sanitize_filename("..") == "received_file"
    assert sanitize_filename("") == "received_file"
    assert sanitize_filename("file...") == "file"
    assert sanitize_filename("file. ") == "file"
    assert "🙂" in sanitize_filename("🙂.txt")
    assert sanitize_filename(".env").startswith("_")
    assert is_dangerous("setup.exe")
    assert is_dangerous("report.pdf.exe")
    assert not is_dangerous("notes.txt")


def test_collisions(tmp_path: Path):
    for _ in range(100):
        unique_path(tmp_path, "f.txt")
    assert unique_path(tmp_path, "f.txt").name == "f (100).txt"


def test_symlink_escape(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "inbox"
    root.mkdir()
    link = root / "link"
    if os.name == "nt":
        subprocess.check_call(["cmd", "/c", "mklink", "/J", str(link), str(outside)], stdout=subprocess.DEVNULL)
    else:
        os.symlink(outside, link, target_is_directory=True)
    with pytest.raises(ValueError):
        safe_join(root, "link/evil.txt")
