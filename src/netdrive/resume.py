"""Partial files and the chunk bitmap. The final name is written only after the hash matches."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

WEEK = 7 * 24 * 60 * 60


def folder_for(root: Path, digest: bytes) -> Path:
    """Older temp directory, keyed by the file hash."""
    return root / ".netdrive-tmp" / digest.hex()


def offer_folder(root: Path, offer_id: str) -> Path:
    """Temp directory named by the offer id, as the protocol describes."""
    return root / ".netdrive-tmp" / offer_id


def part_path(root: Path, digest: bytes, offer_id: str | None = None, index: int = 0) -> Path:
    """Partial bytes. New transfers use `<offer_id>/<index>.part`."""
    legacy = folder_for(root, digest) / "data.part"
    if offer_id and not legacy.exists():
        return offer_folder(root, offer_id) / f"{index}.part"
    if offer_id and legacy.exists():
        return legacy
    return legacy


def _state_path(root: Path, digest: bytes, offer_id: str | None, index: int) -> Path:
    if offer_id and not (folder_for(root, digest) / "data.part").exists():
        return offer_folder(root, offer_id) / f"{index}.json"
    return folder_for(root, digest) / "state.json"


def load_have(root: Path, digest: bytes, size: int, offer_id: str | None = None, index: int = 0) -> set[int]:
    """Chunk indexes already on disk. A size mismatch throws the partial away."""
    state = _state_path(root, digest, offer_id, index)
    folder = state.parent
    if not state.exists():
        return set()
    try:
        data = json.loads(state.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    if int(data.get("size", -1)) != size:
        shutil.rmtree(folder, ignore_errors=True)
        return set()
    return set(int(n) for n in data.get("have", []))


def save_have(
    root: Path,
    digest: bytes,
    size: int,
    have: set[int],
    created: float | None = None,
    offer_id: str | None = None,
    index: int = 0,
) -> None:
    """Remember which chunks survived a dropped connection."""
    previous = _state_path(root, digest, offer_id, index)
    folder = previous.parent
    folder.mkdir(parents=True, exist_ok=True)
    stamp = created
    if stamp is None and previous.exists():
        try:
            stamp = float(json.loads(previous.read_text(encoding="utf-8")).get("created", time.monotonic()))
        except (json.JSONDecodeError, TypeError, ValueError):
            stamp = time.monotonic()
    if stamp is None:
        stamp = time.monotonic()
    previous.write_text(
        json.dumps({"size": size, "have": sorted(have), "created": stamp}),
        encoding="utf-8",
    )


def purge_expired(root: Path, now: float, max_age: float = WEEK) -> None:
    """Delete partials whose stored monotonic stamp is older than 7 days."""
    base = root / ".netdrive-tmp"
    if not base.exists():
        return
    seen = set()
    for state in list(base.glob("*/state.json")) + list(base.glob("*/*.json")):
        if state in seen or not state.exists():
            continue
        seen.add(state)
        try:
            created = float(json.loads(state.read_text(encoding="utf-8")).get("created", now))
        except (json.JSONDecodeError, TypeError, ValueError, OSError):
            created = now
        if now - created > max_age:
            shutil.rmtree(state.parent, ignore_errors=True)


def remove_digest(root: Path, digest: bytes, offer_id: str | None = None, index: int = 0) -> None:
    """Delete one partial tree, including the offer-id layout."""
    shutil.rmtree(folder_for(root, digest), ignore_errors=True)
    if not offer_id:
        return
    folder = offer_folder(root, offer_id)
    for name in (f"{index}.part", f"{index}.json"):
        try:
            (folder / name).unlink()
        except OSError:
            pass
    try:
        folder.rmdir()
    except OSError:
        pass
