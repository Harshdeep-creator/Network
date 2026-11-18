"""Message numbers, the offer JSON, and path checks for a folder manifest."""

from __future__ import annotations

import json
import mimetypes
import secrets
import struct
from pathlib import Path

from netdrive.errors import ProtocolError

MSG_OFFER = 0x01
MSG_ACCEPT = 0x02
MSG_DECLINE = 0x03
MSG_FILE_START = 0x04
MSG_CHUNK = 0x05
MSG_FILE_END = 0x06
MSG_FILE_RESULT = 0x07
MSG_CANCEL = 0x08
MSG_ERROR = 0x09
MSG_CHUNK_ACK = 0x0A
MSG_RESUME = 0x0B
MSG_TEXT = 0x0C
MSG_FOLDER = 0x0D
MSG_UPGRADE_OFFER = 0x0E
MSG_UPGRADE_ACCEPT = 0x0F
MSG_PING = 0x10
MSG_COMMIT = 0x11
MSG_REVEAL = 0x12

KNOWN_TYPES = {
    MSG_OFFER,
    MSG_ACCEPT,
    MSG_DECLINE,
    MSG_FILE_START,
    MSG_CHUNK,
    MSG_FILE_END,
    MSG_FILE_RESULT,
    MSG_CANCEL,
    MSG_ERROR,
    MSG_CHUNK_ACK,
    MSG_RESUME,
    MSG_TEXT,
    MSG_FOLDER,
    MSG_UPGRADE_OFFER,
    MSG_UPGRADE_ACCEPT,
    MSG_PING,
    MSG_COMMIT,
    MSG_REVEAL,
}

DECLINE_REASONS = {
    "user_declined",
    "too_large",
    "no_space",
    "timeout",
    "busy",
    "rate_limited",
    "blocked",
    "key_changed",
}

TEXT_MAX = 4096
MAX_FILES = 100
CHUNK = 64 * 1024


def u32(value: int) -> bytes:
    """Pack an unsigned 32-bit integer."""
    return struct.pack(">I", value)


def take_u32(payload: bytes, offset: int = 0) -> int:
    """Read an unsigned 32-bit integer."""
    return struct.unpack(">I", payload[offset : offset + 4])[0]


def guess_mime(name: str) -> str:
    """MIME type from the file name, or the generic binary type."""
    guessed, _ = mimetypes.guess_type(name)
    return guessed or "application/octet-stream"


def encode_offer(nick: str, files: list[dict], offer_id: str | None = None) -> bytes:
    """Build the OFFER payload. `files` items need name and size."""
    body = {
        "v": 1,
        "offer_id": offer_id or secrets.token_hex(8),
        "sender_nick": nick[:32],
        "files": [
            {
                "name": item["name"],
                "size": int(item["size"]),
                "mime": item.get("mime") or guess_mime(item["name"]),
            }
            for item in files
        ],
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def parse_offer(payload: bytes) -> dict:
    """Validate an OFFER. Unknown keys are ignored. Bad offers raise ProtocolError."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("The offer could not be read.") from exc
    if not isinstance(data, dict) or data.get("v") != 1:
        raise ProtocolError("This offer version is not supported.")
    files = data.get("files")
    nick = data.get("sender_nick")
    offer_id = data.get("offer_id")
    if not isinstance(nick, str) or not nick or len(nick) > 32:
        raise ProtocolError("The offer is missing a sender name.")
    if not isinstance(offer_id, str) or len(offer_id) != 16:
        raise ProtocolError("The offer id is not valid.")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ProtocolError("The offer must list between 1 and 100 files.")
    clean = []
    for item in files:
        if not isinstance(item, dict):
            raise ProtocolError("A file entry in the offer is not valid.")
        name = item.get("name")
        size = item.get("size")
        if not isinstance(name, str) or len(name) > 1024 or name == "":
            raise ProtocolError("A file name in the offer is not valid.")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ProtocolError("A file size in the offer is not valid.")
        mime = item.get("mime")
        if not isinstance(mime, str) or not mime:
            mime = guess_mime(name)
        clean.append({"name": name, "size": size, "mime": mime})
    result = {"v": 1, "offer_id": offer_id, "sender_nick": nick, "files": clean}
    sender_pk = data.get("sender_pk")
    if isinstance(sender_pk, str):
        try:
            raw_key = bytes.fromhex(sender_pk)
        except ValueError as exc:
            raise ProtocolError("The sender key is not valid.") from exc
        if len(raw_key) != 32:
            raise ProtocolError("The sender key is not valid.")
        result["sender_pk"] = sender_pk
    rotating = data.get("rotating")
    if isinstance(rotating, str) and rotating:
        try:
            raw_token = bytes.fromhex(rotating)
        except ValueError as exc:
            raise ProtocolError("The rotating id is not valid.") from exc
        if len(raw_token) != 16:
            raise ProtocolError("The rotating id is not valid.")
        result["rotating"] = rotating
    note = data.get("text")
    if note is not None:
        if not isinstance(note, str) or len(note.encode("utf-8")) > 4096:
            raise ProtocolError("That note is over 4 KB.")
        result["text"] = note
    return result


def validate_relative_path(relative: str) -> str:
    """Reject absolute paths, drive prefixes, and `..` in a folder manifest."""
    if not isinstance(relative, str) or relative == "":
        raise ProtocolError("A folder entry has an empty path.")
    if relative.startswith("/") or relative.startswith("\\"):
        raise ProtocolError("A folder entry has an absolute path.")
    parts = Path(relative.replace("\\", "/")).parts
    if Path(relative).drive or ".." in parts or parts[:1] == ("/",):
        raise ProtocolError("A folder entry leaves the receive folder.")
    if any(part in ("", ".", "..") for part in parts):
        raise ProtocolError("A folder entry is not a plain relative path.")
    return "/".join(parts)


def encode_manifest(paths: list[str]) -> bytes:
    """JSON list of relative paths, each checked first."""
    clean = [validate_relative_path(p) for p in paths]
    return json.dumps(clean).encode("utf-8")


def parse_manifest(payload: bytes) -> list[str]:
    """Read a folder manifest."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("The folder list could not be read.") from exc
    if not isinstance(data, list):
        raise ProtocolError("The folder list could not be read.")
    return [validate_relative_path(item) for item in data]


def bitmap_bytes(count: int, have: set[int]) -> bytes:
    """Bit 0 of byte 0 is chunk 0."""
    raw = bytearray((count + 7) // 8)
    for index in have:
        if 0 <= index < count:
            raw[index // 8] |= 1 << (index % 8)
    return bytes(raw)


def bitmap_set(raw: bytes, count: int) -> set[int]:
    """Chunk indexes whose bits are set."""
    found = set()
    for index in range(count):
        if index // 8 < len(raw) and raw[index // 8] & (1 << (index % 8)):
            found.add(index)
    return found


def chunk_count(size: int) -> int:
    """How many 64 KiB chunks a file needs. An empty file is one empty chunk."""
    if size <= 0:
        return 1
    return (size + CHUNK - 1) // CHUNK
