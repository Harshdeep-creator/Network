"""Listen for one sender at a time, then return to listening."""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

from netdrive.channel import SecureChannel
from netdrive.contacts import Contacts
from netdrive.crypto import recognizes
from netdrive.errors import AuthError, IntegrityError, NetDriveError, ProtocolError
from netdrive.identity import accept_identity, identity_path, load_identity
from netdrive.progress import Progress, format_bytes
from netdrive.protocol import (
    CHUNK,
    MSG_ACCEPT,
    MSG_CANCEL,
    MSG_CHUNK,
    MSG_COMMIT,
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
    bitmap_bytes,
    chunk_count,
    parse_manifest,
    parse_offer,
    u32,
)
from netdrive.resume import load_have, purge_expired, remove_digest, save_have, part_path
from netdrive.sanitize import is_dangerous, safe_join, sanitize_filename, unique_path
from netdrive.ratelimit import RateLimiter


def spool(handle, data: bytes) -> None:
    """Write one chunk. Tests replace this to inject a full disk."""
    handle.write(data)


def accept_offer(chan: SecureChannel) -> None:
    """The only place an ACCEPT frame is sent."""
    chan.send(MSG_ACCEPT, b"")


def production_prompt(summary: str, offer: dict) -> bool:
    """Read one line. Empty input and a closed terminal both mean no."""
    print(summary, flush=True)
    print("Accept? [y/N]", flush=True)
    try:
        if sys.stdin is None or sys.stdin.closed:
            return False
        line = sys.stdin.readline()
    except Exception:
        return False
    return line.strip().lower() in {"y", "yes"}


class Receiver:
    """TCP listener. A second offer waits; a third is declined as busy."""

    def __init__(
        self,
        directory: Path,
        nick: str,
        port: int = 0,
        max_size: int = 4 * 1024**3,
        prompt=production_prompt,
        now=time.monotonic,
        offer_timeout: float = 60.0,
        host: str = "0.0.0.0",
        mute_after: int = 3,
        limit: int = 5,
        visibility: str = "everyone",
        contact_secret: bytes | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.nick = nick
        self.max_size = max_size
        self.prompt = prompt
        self.now = now
        self.offer_timeout = offer_timeout
        self.contacts = Contacts(self.directory / ".netdrive" / "contacts.json")
        self.limiter = RateLimiter(limit=limit, mute_after=mute_after)
        self.notes: list[str] = []
        self.visibility = visibility
        self.contact_secret = contact_secret
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._active = False
        self._waiter: tuple[socket.socket, tuple] | None = None
        purge_expired(self.directory, self.now())

    def stop(self) -> None:
        """Stop accepting. The current session is left to finish or fail."""
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def serve_forever(self) -> None:
        """Accept until `stop`. Sessions run on their own threads."""
        while not self._stop.is_set():
            self._sock.settimeout(0.3)
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._dispatch, args=(conn, addr), daemon=True).start()

    def _dispatch(self, conn: socket.socket, addr: tuple) -> None:
        run_now = False
        with self._lock:
            if not self._active and self._waiter is None:
                self._active = True
                run_now = True
            elif self._waiter is None:
                self._waiter = (conn, addr)
            else:
                threading.Thread(target=self._reject_busy, args=(conn,), daemon=True).start()
                return
        if not run_now:
            return
        try:
            self.handle_connection(conn, addr)
        finally:
            self._release()

    def _release(self) -> None:
        nxt = None
        with self._lock:
            nxt = self._waiter
            self._waiter = None
            if nxt is None:
                self._active = False
        if nxt:
            try:
                self.handle_connection(*nxt)
            finally:
                with self._lock:
                    self._active = False

    def _reject_busy(self, conn: socket.socket) -> None:
        try:
            chan = SecureChannel.accept(conn)
            self._decline(chan, "busy", "")
            chan.close()
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        """One session, then the caller marks the listener free."""
        chan: SecureChannel | None = None
        offer_id = ""
        try:
            chan = SecureChannel.accept(conn)
            kind, payload = chan.recv(timeout=30)
            if kind == MSG_COMMIT:
                private = load_identity(identity_path(self.directory))
                chan.session_code = accept_identity(chan, private, payload)
                kind, payload = chan.recv(timeout=30)
            if kind != MSG_OFFER:
                raise ProtocolError("Expected an offer.")
            offer = parse_offer(payload)
            offer_id = offer["offer_id"]
            self._screen(chan, offer, addr[0])
        except (NetDriveError, ConnectionError, TimeoutError, OSError):
            pass
        finally:
            if chan:
                chan.close()
            else:
                try:
                    conn.close()
                except OSError:
                    pass

    def _allows(self, offer: dict) -> bool:
        mode = self.visibility.lower()
        if mode == "off":
            return False
        if mode in {"contacts", "contacts only"}:
            token = offer.get("rotating", "")
            if not self.contact_secret or not token:
                return False
            try:
                return recognizes(self.contact_secret, bytes.fromhex(token))
            except ValueError:
                return False
        return True

    def _screen(self, chan: SecureChannel, offer: dict, ip: str) -> None:
        if not self._allows(offer):
            self._decline(chan, "user_declined", "Receiver is not visible.")
            return
        peer = offer.get("sender_pk") or ip
        if not self.limiter.allow(peer, self.now()):
            self._decline(chan, "rate_limited", "Receiver declined: too many offers.")
            return
        presented = offer.get("sender_pk", "")
        token = str(offer.get("rotating") or "")
        if (presented and self.contacts.is_blocked(presented)) or (token and self.contacts.is_blocked(token)):
            self._note_block()
            self._decline(chan, "blocked", "Receiver declined.")
            self.limiter.declined(peer, self.now())
            return
        if presented and self.contacts.key_changed(offer["sender_nick"], presented):
            message = "This contact's key changed. Verify again before accepting."
            self._decline(chan, "key_changed", message)
            self.limiter.declined(peer, self.now())
            return
        total = sum(item["size"] for item in offer["files"])
        try:
            free = shutil.disk_usage(self.directory).free
        except OSError:
            free = 0
        if any(item["size"] > self.max_size for item in offer["files"]) or total > self.max_size:
            detail = (
                f"Offer rejected: needs {format_bytes(total)}, "
                f"limit is {format_bytes(self.max_size)}."
            )
            print(detail)
            self._decline(chan, "too_large", detail)
            self.limiter.declined(peer, self.now())
            return
        if total > free:
            detail = f"Offer rejected: needs {format_bytes(total)}, only {format_bytes(free)} free."
            print(detail)
            self._decline(chan, "no_space", detail)
            self.limiter.declined(peer, self.now())
            return
        summary = self._summary(offer, ip, chan.session_code, free)
        if self.contacts.may_auto(offer["sender_nick"], total) and presented:
            accept_offer(chan)
            self.limiter.accepted(peer)
            self._receive(chan, offer)
            return
        decision = self._ask(summary, offer)
        if decision != "accept":
            reason = "timeout" if decision == "timeout" else "user_declined"
            self._decline(chan, reason, "Receiver declined.")
            self.limiter.declined(peer, self.now())
            return
        accept_offer(chan)
        self.limiter.accepted(peer)
        self._receive(chan, offer)

    def _ask(self, summary: str, offer: dict) -> str:
        box: dict[str, bool] = {}

        def run() -> None:
            try:
                box["value"] = bool(self.prompt(summary, offer))
            except Exception:
                box["value"] = False

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(self.offer_timeout)
        if worker.is_alive():
            return "timeout"
        return "accept" if box.get("value") else "user_declined"

    def _summary(self, offer: dict, ip: str, code: str, free: int) -> str:
        verified = bool(offer.get("sender_pk")) and not self.contacts.key_changed(
            offer["sender_nick"], offer["sender_pk"]
        ) and self.contacts.by_nick(offer["sender_nick"]) is not None
        state = "verified contact" if verified else "not identity-verified; compare with the sender's screen"
        lines = [
            f'Incoming transfer from "{offer["sender_nick"]}" ({ip})',
            f"Verification code: {code}   [{state}]",
        ]
        if offer.get("text") is not None:
            lines.append("Text note (not opened as a link):")
            lines.append(offer["text"])
        for index, item in enumerate(offer["files"], start=1):
            lines.append(f"  {index}. {item['name']}   {format_bytes(item['size'])}   {item['mime']}")
            if is_dangerous(item["name"]):
                lines.append("This file type can run code. Accept only if you asked for it.")
        total = sum(item["size"] for item in offer["files"])
        lines.append(f"Total: {format_bytes(total)}   Free space: {format_bytes(free)}")
        return "\n".join(lines)

    def _note_block(self) -> None:
        """A local note only. The key itself is not written down."""
        path = self.directory / ".netdrive" / "blocks.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("Blocked before the prompt.\n")

    def _decline(self, chan: SecureChannel, reason: str, detail: str) -> None:
        payload = reason if not detail else reason + "\n" + detail
        try:
            chan.send(MSG_DECLINE, payload.encode("utf-8"))
        except Exception:
            pass

    def _receive(self, chan: SecureChannel, offer: dict) -> None:
        if offer.get("text") is not None:
            kind, payload = chan.recv(timeout=30)
            if kind != MSG_TEXT:
                raise ProtocolError("Expected the text note.")
            if len(payload) > 4096:
                raise ProtocolError("That note is over 4 KB.")
            self.notes.append(payload.decode("utf-8"))
            print(self.notes[-1])
            return
        kind, payload = chan.recv(timeout=30)
        if kind == MSG_FOLDER:
            parse_manifest(payload)
            kind, payload = chan.recv(timeout=30)
        for expected in range(len(offer["files"])):
            if kind != MSG_RESUME:
                raise ProtocolError("Expected a resume check.")
            offer_id, digest = _split_resume(payload, offer)
            meta = offer["files"][expected]
            have = load_have(self.directory, digest, meta["size"], offer_id, expected)
            chan.send(
                MSG_CHUNK_ACK,
                u32(expected) + bitmap_bytes(chunk_count(meta["size"]), have),
            )
            kind, payload = chan.recv(timeout=30)
            if kind == MSG_CANCEL:
                self._wipe_offer(offer)
                print("Cancelled. Partial files removed.")
                return
            if kind != MSG_FILE_START:
                raise ProtocolError("Expected the start of a file.")
            status = self._one_file(chan, offer, expected, digest, have, offer_id)
            if status != "ok":
                return
            if expected + 1 < len(offer["files"]):
                kind, payload = chan.recv(timeout=60)
                if kind == MSG_CANCEL:
                    self._wipe_offer(offer)
                    print("Cancelled. Partial files removed.")
                    return
        print("Received.")

    def _one_file(self, chan: SecureChannel, offer: dict, index: int, digest: bytes, have: set[int], offer_id: str = "") -> str:
        meta = offer["files"][index]
        relative = meta["name"]
        target_dir = self.directory
        if "/" in relative.replace("\\", "/"):
            parts = [sanitize_filename(part) for part in relative.replace("\\", "/").split("/") if part]
            relative = "/".join(parts)
            folder = safe_join(self.directory, str(Path(relative).parent)) if Path(relative).parent.parts else self.directory
            folder.mkdir(parents=True, exist_ok=True)
            target_dir = folder
            leaf = Path(relative).name
        else:
            leaf = sanitize_filename(relative)
        partial = part_path(self.directory, digest, offer_id or offer.get("offer_id"), index)
        partial.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        mode = "r+b" if partial.exists() else "w+b"
        received = 0
        try:
            with partial.open(mode) as handle:
                if have:
                    handle.seek(0)
                    existing = handle.read()
                    hasher.update(existing)
                    received = len(existing)
                count = chunk_count(meta["size"])
                incoming = 0
                for number in range(count):
                    if number in have:
                        continue
                    kind, payload = chan.recv(timeout=60)
                    if kind == MSG_CANCEL:
                        raise NetDriveError("cancelled")
                    if kind != MSG_CHUNK:
                        raise ProtocolError("Expected file data.")
                    handle.seek(number * CHUNK)
                    try:
                        spool(handle, payload)
                    except OSError as exc:
                        if exc.errno == errno.ENOSPC:
                            raise NetDriveError(
                                f"The disk filled up. Needed {format_bytes(meta['size'])}."
                            ) from exc
                        raise
                    hasher.update(payload)
                    received += len(payload)
                    have.add(number)
                    save_have(self.directory, digest, meta["size"], have, offer_id=offer_id or offer.get("offer_id"), index=index)
                    incoming += 1
                handle.flush()
            kind, payload = chan.recv(timeout=30)
            if kind != MSG_FILE_END:
                raise ProtocolError("The file did not finish.")
            got = payload[4:]
            if received != meta["size"] or not hmac_compare(hasher.digest(), got) or got != digest:
                partial.unlink(missing_ok=True)
                remove_digest(self.directory, digest, offer_id or offer.get("offer_id"), index)
                reason = f"File corrupted in transit and was discarded: {meta['name']}"
                chan.send(MSG_FILE_RESULT, u32(index) + b"\x00" + reason.encode("utf-8"))
                print(reason)
                return "bad"
            final = unique_path(target_dir, leaf)
            os.replace(partial, final)
            remove_digest(self.directory, digest, offer_id or offer.get("offer_id"), index)
            chan.send(MSG_FILE_RESULT, u32(index) + b"\x01" + b"ok")
            bar = Progress(meta["size"], leaf)
            bar.update(meta["size"])
            print(bar.finish())
            return "ok"
        except NetDriveError as exc:
            if str(exc) == "cancelled":
                remove_digest(self.directory, digest, offer_id or offer.get("offer_id"), index)
                partial.unlink(missing_ok=True)
                print("Cancelled. Partial files removed.")
                return "cancel"
            remove_digest(self.directory, digest, offer_id or offer.get("offer_id"), index)
            partial.unlink(missing_ok=True)
            try:
                chan.send(MSG_ERROR, str(exc).encode("utf-8"))
            except Exception:
                pass
            print(str(exc))
            return "error"

    def _wipe_offer(self, offer: dict) -> None:
        base = self.directory / ".netdrive-tmp"
        if base.exists():
            shutil.rmtree(base, ignore_errors=True)


def _split_resume(payload: bytes, offer: dict) -> tuple[str, bytes]:
    """RESUME is the 16-byte offer id plus the file hash. A bare hash still works."""
    if len(payload) == 48:
        offer_id = payload[:16].decode("ascii")
        digest = payload[16:]
    elif len(payload) == 32:
        offer_id = str(offer.get("offer_id") or "")
        digest = payload
    else:
        raise ProtocolError("The resume check is not valid.")
    return offer_id, digest


def hmac_compare(left: bytes, right: bytes) -> bool:
    """Constant-time compare that also rejects different lengths."""
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)
