"""File names that are safe to write on Windows and macOS."""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path

RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{n}" for n in range(1, 10)),
    *(f"LPT{n}" for n in range(1, 10)),
}
ILLEGAL = '<>:"|?*'


def sanitize_filename(raw: str) -> str:
    """Return a single path segment that can be stored as a file name."""
    if not isinstance(raw, str):
        raise TypeError("A file name must be text.")
    name = unicodedata.normalize("NFC", raw).replace("\\", "/")
    name = name.split("/")[-1]
    name = "".join(ch for ch in name if not (ord(ch) <= 31 or ord(ch) == 127))
    name = name.strip(" ")
    while name.endswith(" ") or name.endswith("."):
        name = name[:-1]
    for char in ILLEGAL:
        name = name.replace(char, "_")
    stem = name.split(".", 1)[0].upper()
    if stem in RESERVED:
        name = "_" + name
    if name in ("", ".", ".."):
        name = "received_file"
    if name.startswith("."):
        name = "_" + name
    encoded = name.encode("utf-8")
    if len(encoded) > 255:
        if "." in name[1:]:
            base, ext = name.rsplit(".", 1)
            ext_b = ("." + ext).encode("utf-8")
            room = 255 - len(ext_b)
            if room < 1:
                name = encoded[:255].decode("utf-8", "ignore")
            else:
                name = base.encode("utf-8")[:room].decode("utf-8", "ignore") + "." + ext
        else:
            name = encoded[:255].decode("utf-8", "ignore")
    return name or "received_file"


def safe_join(root: Path, relative: str) -> Path:
    """Resolve `relative` inside `root`, or raise ValueError."""
    root_r = root.resolve()
    text = relative.replace("\\", "/")
    rel = Path(text)
    if rel.is_absolute() or rel.drive or ".." in rel.parts or text.startswith("/"):
        raise ValueError("Refusing a path that leaves the receive folder.")
    if any(part in ("", ".", "..") for part in rel.parts):
        raise ValueError("Refusing a path that leaves the receive folder.")
    current = root_r
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Refusing a symlink.")
    resolved = (root_r / rel).resolve()
    if resolved != root_r and root_r not in resolved.parents:
        raise ValueError("Refusing a path that leaves the receive folder.")
    return resolved


def unique_path(directory: Path, name: str) -> Path:
    """Create an empty file that no one else owns yet. Callers replace it after the hash check."""
    directory.mkdir(parents=True, exist_ok=True)
    candidate = sanitize_filename(name)
    stem = Path(candidate).stem
    suffix = Path(candidate).suffix
    number = 0
    root = directory.resolve()
    while True:
        picked = candidate if number == 0 else f"{stem} ({number}){suffix}"
        path = directory / picked
        if path.is_symlink():
            raise ValueError("Refusing a symlink.")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(str(path), flags, 0o644)
        except FileExistsError:
            number += 1
            continue
        os.close(fd)
        resolved = path.resolve()
        if resolved != root and root not in resolved.parents:
            path.unlink(missing_ok=True)
            raise ValueError("Refusing a path that leaves the receive folder.")
        return path


def is_dangerous(name: str) -> bool:
    """True for executable types and names such as report.pdf.exe."""
    blocked = {".apk", ".exe", ".bat", ".sh", ".js", ".vbs", ".jar", ".msi"}
    lower = name.lower()
    suffix = Path(lower).suffix
    parts = lower.split(".")
    double = len(parts) >= 3 and ("." + parts[-1]) in blocked
    return suffix in blocked or double
