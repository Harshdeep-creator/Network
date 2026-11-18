"""Send files, a folder, or a short text to a receiver that is already listening."""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import threading
from pathlib import Path

from netdrive.channel import SecureChannel
from netdrive.errors import CancelledError, DeclinedError, IntegrityError, NetDriveError
from netdrive.progress import Progress
from netdrive.protocol import (
    CHUNK,
    MSG_ACCEPT,
    MSG_CANCEL,
    MSG_CHUNK,
    MSG_CHUNK_ACK,
    MSG_DECLINE,
    MSG_ERROR,
    MSG_FILE_END,
    MSG_FILE_RESULT,
    MSG_FILE_START,
    MSG_FOLDER,
    MSG_OFFER,
    MSG_RESUME,
    MSG_TEXT,
    TEXT_MAX,
    bitmap_set,
    chunk_count,
    encode_manifest,
    encode_offer,
    u32,
    validate_relative_path,
)

DECLINE_TEXT = {
    "user_declined": "Receiver declined.",
    "timeout": "Receiver declined.",
    "busy": "Receiver declined: busy.",
    "too_large": "Offer rejected: a file is over the size limit.",
    "no_space": "Offer rejected: not enough free space.",
    "rate_limited": "Receiver declined: too many offers.",
    "blocked": "Receiver declined.",
    "key_changed": "This contact's key changed. Verify again before accepting.",
}


def hash_file(path: Path) -> tuple[bytes, int]:
    """SHA-256 and size, read in 64 KiB chunks."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.digest(), size


def collect_paths(paths: list[Path]) -> tuple[list[tuple[str, Path]], list[str]]:
    """Files as (relative name, path). A directory becomes a manifest."""
    files: list[tuple[str, Path]] = []
    manifest: list[str] = []
    for raw in paths:
        if raw.is_dir():
            for child in sorted(item for item in raw.rglob("*") if item.is_file()):
                relative = validate_relative_path(child.relative_to(raw).as_posix())
                if child.is_symlink():
                    raise NetDriveError("Refusing to send a symlink.")
                files.append((relative, child))
                manifest.append(relative)
        elif raw.is_file():
            if raw.is_symlink():
                raise NetDriveError("Refusing to send a symlink.")
            files.append((raw.name, raw))
        else:
            raise NetDriveError(f"Could not read {raw}.")
    if not files:
        raise NetDriveError("There is no file to send.")
    return files, manifest


def _decline_message(payload: bytes) -> tuple[str, str]:
    text = payload.decode("utf-8", "replace")
    code, _, detail = text.partition("\n")
    return code, detail or DECLINE_TEXT.get(code, "Receiver declined.")


def _plain(exc: BaseException) -> str:
    if isinstance(exc, NetDriveError):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return "Timed out waiting for the other computer."
    return "The connection closed."


def _cancelled(cancel: threading.Event | None, cancel_after: int | None, sent: int) -> bool:
    if cancel is not None and cancel.is_set():
        return True
    return cancel_after is not None and sent >= cancel_after


def send_files(
    paths: list[Path],
    host: str,
    port: int,
    nick: str,
    out=sys.stdout,
    sender_pk: str = "",
    offer_id: str | None = None,
    on_hashed=None,
    cancel: threading.Event | None = None,
    cancel_after: int | None = None,
    handshake_timeout: float = 10.0,
    static_private=None,
    rotating: str = "",
    on_progress=None,
) -> int:
    """Connect, show the code, and send. Returns a process exit code."""
    try:
        listed, manifest = collect_paths(paths)
        prepared: list[tuple[str, Path, bytes, int]] = []
        for name, path in listed:
            digest, size = hash_file(path)
            if on_hashed:
                on_hashed(path)
            prepared.append((name, path, digest, size))
    except NetDriveError as exc:
        print(str(exc), file=out)
        return 2

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chan: SecureChannel | None = None
    try:
        sock.settimeout(handshake_timeout)
        sock.connect((host, port))
        chan = SecureChannel.connect(sock, timeout=handshake_timeout)
        if static_private is not None:
            from netdrive.identity import begin_identity

            chan.session_code = begin_identity(chan, static_private)
        print(f"Verification code: {chan.session_code}", file=out)
        print("Ask the receiver to confirm it matches.", file=out)
        print("Path: Wi-Fi LAN (TCP, encrypted)", file=out)
        files_meta = [{"name": name, "size": size} for name, _, _, size in prepared]
        payload = encode_offer(nick, files_meta, offer_id)
        if sender_pk or rotating:
            body = json.loads(payload)
            if sender_pk:
                body["sender_pk"] = sender_pk
            if rotating:
                body["rotating"] = rotating
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        chan.send(MSG_OFFER, payload)
        kind, reply = chan.recv(timeout=70)
        if kind == MSG_DECLINE:
            _code, message = _decline_message(reply)
            print(message, file=out)
            raise DeclinedError(_code)
        if kind != MSG_ACCEPT:
            print("The receiver did not accept.", file=out)
            return 1
        if manifest:
            chan.send(MSG_FOLDER, encode_manifest(manifest))
        offer_id = json.loads(payload.decode("utf-8"))["offer_id"]
        return _transfer(chan, prepared, out, cancel, cancel_after, offer_id, on_progress)
    except DeclinedError:
        return 1
    except CancelledError:
        if chan:
            try:
                chan.send(MSG_CANCEL, b"")
            except Exception:
                pass
        print("Cancelled. Partial files removed.", file=out)
        return 1
    except IntegrityError as exc:
        print(str(exc), file=out)
        return 3
    except (NetDriveError, ConnectionError, TimeoutError, OSError) as exc:
        print(_plain(exc), file=out)
        return 2
    finally:
        if chan:
            chan.close()
        else:
            sock.close()


def _transfer(chan: SecureChannel, prepared, out, cancel, cancel_after, offer_id: str, on_progress=None) -> int:
    total = sum(size for _, _, _, size in prepared)
    progress = Progress(total, prepared[0][0])
    sent_bytes = 0
    for index, (name, path, digest, size) in enumerate(prepared):
        if _cancelled(cancel, cancel_after, sent_bytes):
            raise CancelledError()
        progress.label = name
        chan.send(MSG_RESUME, offer_id.encode("ascii") + digest)
        kind, body = chan.recv(timeout=30)
        if kind == MSG_CANCEL:
            raise CancelledError()
        if kind != MSG_CHUNK_ACK:
            raise NetDriveError("The receiver did not answer the resume check.")
        have = bitmap_set(body[4:], chunk_count(size))
        chan.send(MSG_FILE_START, u32(index))
        with path.open("rb") as handle:
            cursor = 0
            chunk_index = 0
            while True:
                if _cancelled(cancel, cancel_after, sent_bytes):
                    raise CancelledError()
                block = handle.read(CHUNK)
                if not block:
                    if size == 0 and chunk_index == 0 and 0 not in have:
                        chan.send(MSG_CHUNK, b"")
                    break
                if path.stat().st_size != size:
                    print("\nFile changed while sending.", file=out)
                    chan.send(MSG_ERROR, b"File changed while sending.")
                    return 2
                if chunk_index not in have:
                    chan.send(MSG_CHUNK, block)
                sent_bytes += len(block)
                progress.update(len(block))
                if progress.due(0.2):
                    line = progress.render()
                    print("\r" + line, end="", file=out, flush=True)
                    if on_progress:
                        on_progress(line)
                cursor += len(block)
                chunk_index += 1
            if cursor != size and not (size == 0 and cursor == 0):
                print("\nFile changed while sending.", file=out)
                chan.send(MSG_ERROR, b"File changed while sending.")
                return 2
        chan.send(MSG_FILE_END, u32(index) + digest)
        kind, body = chan.recv(timeout=30)
        if kind == MSG_CANCEL:
            raise CancelledError()
        if kind == MSG_ERROR:
            raise NetDriveError(body.decode("utf-8", "replace"))
        if kind != MSG_FILE_RESULT or len(body) < 5 or body[4] != 1:
            reason = body[5:].decode("utf-8", "replace") if len(body) > 5 else ""
            raise IntegrityError(reason or f"File corrupted in transit and was discarded: {name}")
    print("\r" + progress.finish(), file=out)
    print("Sent.", file=out)
    return 0


def send_text(host: str, port: int, nick: str, text: str, out=sys.stdout) -> int:
    """Offer a short note. The receiver shows it and does not open links."""
    raw = text.encode("utf-8")
    if len(raw) > TEXT_MAX:
        print("That note is over 4 KB.", file=out)
        return 2
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chan: SecureChannel | None = None
    try:
        sock.settimeout(10)
        sock.connect((host, port))
        chan = SecureChannel.connect(sock)
        print(f"Verification code: {chan.session_code}", file=out)
        payload = encode_offer(
            nick,
            [{"name": "note.txt", "size": len(raw), "mime": "text/plain"}],
        )
        body = json.loads(payload)
        body["text"] = text
        chan.send(MSG_OFFER, json.dumps(body, separators=(",", ":")).encode("utf-8"))
        kind, reply = chan.recv(timeout=70)
        if kind == MSG_DECLINE:
            _code, message = _decline_message(reply)
            print(message, file=out)
            return 1
        if kind != MSG_ACCEPT:
            print("The receiver did not accept.", file=out)
            return 1
        chan.send(MSG_TEXT, raw)
        print("Sent.", file=out)
        return 0
    except (NetDriveError, OSError, TimeoutError) as exc:
        print(_plain(exc), file=out)
        return 2
    finally:
        if chan:
            chan.close()
        else:
            sock.close()
