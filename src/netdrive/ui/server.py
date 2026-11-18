"""The local UI. It binds to 127.0.0.1 and uses the same send and receive code as the CLI."""

from __future__ import annotations

import base64
import html
import json
import mimetypes
import os
import re
import secrets
import socket
import tempfile
import threading
import time
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from netdrive.contacts import Contacts
from netdrive.crypto import recognizes, rotating_id
from netdrive.discovery import Beacon, discover
from netdrive.identity import (
    contact_http,
    contact_uri,
    identity_path,
    load_contact_secret,
    load_identity,
    parse_contact_uri,
    public_raw,
    revert_visibility,
)
from netdrive.receiver import Receiver
from netdrive.sanitize import is_dangerous, sanitize_filename
from netdrive.sender import send_files
from netdrive.webreceiver import WebDrop, qr_png_bytes

HERE = Path(__file__).resolve().parent
CODE_RE = re.compile(r"Verification code: (\d{4} \d{4})")
DEFAULT_SHARE_LIMIT = 10000


def share_limit(value) -> int:
    """A long download cap. Time never expires these links."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return DEFAULT_SHARE_LIMIT
    return min(1_000_000, max(1, number))


def lan_ip() -> str:
    """An address other computers on this network can open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def share_root(port: int) -> str:
    """Public address when one is set, otherwise this computer's Wi-Fi address."""
    public = os.environ.get("NETDRIVE_PUBLIC", "").strip().rstrip("/")
    if public:
        return public
    return f"http://{lan_ip()}:{port}"


class Hub:
    """Shared state between the browser and the transfer threads."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.nick = "netdrive-" + secrets.token_hex(2)
        self.max_size = 4 * 1024**3
        self.visibility = "Everyone"
        self.previous_visibility = "Contacts only"
        self.visible_since = time.monotonic()
        self.language = "en"
        self.relay = False
        self.auto = False
        self.send_cancel = threading.Event()
        self.status = "Idle."
        self.progress = ""
        self.send_code = ""
        self.history: list[dict] = []
        self.incoming: dict | None = None
        self.offer_deadline = 0.0
        self.qr_started = 0.0
        self.qr_used = False
        self.qr_png = b""
        self.qr_uri = ""
        self.qr_app = ""
        self.http_port = 8765
        self.shares: dict[str, dict] = {}
        self.web_png = b""
        self.web_url = ""
        self.web_code = ""
        self.web_drop: WebDrop | None = None
        self.auto_limit = 10 * 1024 * 1024
        self._decision = threading.Event()
        self._accept = False
        self.receiver: Receiver | None = None
        self.beacon: Beacon | None = None
        self._lock = threading.Lock()
        self.ensure_receiver()

    def ensure_receiver(self) -> None:
        """Start the listener once. The browser prompt is the accept step."""
        if self.receiver is not None:
            return

        def prompt(summary: str, offer: dict) -> bool:
            match = CODE_RE.search(summary)
            with self._lock:
                self.incoming = {
                    "summary": summary,
                    "code": match.group(1) if match else "",
                    "dangerous": any(is_dangerous(item["name"]) for item in offer["files"]),
                    "files": offer["files"],
                }
                self.status = "Incoming offer. Compare the code."
                self.offer_deadline = time.monotonic() + 60
            self._accept = False
            self._decision.clear()
            self._decision.wait(60)
            with self._lock:
                self.incoming = None
            return self._accept

        self.receiver = Receiver(self.directory, self.nick, port=0, host="0.0.0.0", prompt=prompt, max_size=self.max_size)
        threading.Thread(target=self.receiver.serve_forever, name="netdrive-ui-rx", daemon=True).start()
        self.apply_visibility()
        self.status = f"Listening on port {self.receiver.port}."

    def apply_visibility(self) -> None:
        """Off stops the beacon and refuses offers. Other modes keep the beacon on."""
        if self.receiver is None:
            return
        self.receiver.nick = self.nick
        self.receiver.max_size = self.max_size
        self.receiver.visibility = "off" if self.visibility == "Off" else (
            "contacts" if self.visibility == "Contacts only" else "everyone"
        )
        if self.visibility == "Contacts only":
            self.receiver.contact_secret = load_contact_secret(self.directory)
        if self.visibility == "Off":
            if self.beacon is not None:
                self.beacon.stop()
                self.beacon = None
            self.status = "Visibility is off. This computer is not advertising."
            return
        if self.beacon is None:
            self.beacon = Beacon(self.nick, self.receiver.port, secrets.token_hex(4), allow=self._allow_who)
            self.beacon.start()
        self.beacon.nick = self.nick
        self.beacon.allow = self._allow_who
        self.beacon.broadcast = self.visibility != "Contacts only"

    def _allow_who(self, data: bytes) -> bool:
        """Beacon reply. Off never reaches here. Contacts only needs a rotating id."""
        book = Contacts(self.directory / ".netdrive" / "contacts.json")
        body: dict = {}
        try:
            parsed = json.loads(data.decode("utf-8"))
            if isinstance(parsed, dict):
                body = parsed
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {}
        pk = str(body.get("pk") or "")
        token = str(body.get("rotating") or "")
        if (pk and book.is_blocked(pk)) or (token and book.is_blocked(token)):
            return False
        if self.visibility != "Contacts only":
            return True
        secret = self.receiver.contact_secret if self.receiver else None
        secret = secret or load_contact_secret(self.directory)
        try:
            return bool(token) and recognizes(secret, bytes.fromhex(token))
        except ValueError:
            return False

    def _sender_key(self, contact: str = "") -> tuple:
        private = load_identity(identity_path(self.directory))
        rotating = ""
        if contact:
            row = Contacts(self.directory / ".netdrive" / "contacts.json").by_nick(contact)
            if row and row.get("secret"):
                rotating = rotating_id(bytes.fromhex(row["secret"])).hex()
        return private, public_raw(private).hex(), rotating

    def decide(self, accept: bool, danger_ok: bool) -> None:
        """Record the button the person pressed."""
        if accept and self.incoming and self.incoming.get("dangerous") and not danger_ok:
            self.status = "Tick the warning before accepting that file."
            return
        self._accept = accept
        self._decision.set()
        self.status = "Accepted." if accept else "Receiver declined."

    def demo(self) -> None:
        """Send a real sample file to the listener on this computer."""
        self.ensure_receiver()
        folder = Path(tempfile.mkdtemp(prefix="netdrive-demo-"))
        sample = folder / "session-note.txt"
        sample.write_text("NetDrive sample. Compare the code on both sides before you accept.\n", encoding="utf-8")

        def run() -> None:
            assert self.receiver is not None
            private, sender_pk, _rotating = self._sender_key()
            code = send_files(
                [sample],
                "127.0.0.1",
                self.receiver.port,
                "Demo",
                static_private=private,
                sender_pk=sender_pk,
            )
            self.status = "Sample saved in the receive folder." if code == 0 else "Receiver declined."
            if code == 0:
                self.remember(sample.name, sample.stat().st_size, "received")

        threading.Thread(target=run, daemon=True).start()

    def remember(self, name: str, size: int, result: str) -> None:
        """History stores names and results, never the file bytes."""
        self.history.append(
            {"name": name, "size": size, "result": result, "time": time.strftime("%H:%M:%S")}
        )

    def refresh_contact_qr(self, force: bool = False) -> None:
        """Build the contact QR. It lasts 2 minutes, or until one import."""
        now = time.monotonic()
        expired = bool(self.qr_started) and now - self.qr_started >= 120
        if self.qr_png and not force and not self.qr_used and not expired:
            return
        private = load_identity(identity_path(self.directory))
        pk = public_raw(private).hex()
        secret = load_contact_secret(self.directory).hex()
        self.qr_app = contact_uri(pk, secret)
        self.qr_uri = contact_http(lan_ip(), self.http_port, pk, secret)
        self.qr_png = qr_png_bytes(self.qr_uri)
        self.qr_started = now
        self.qr_used = False

    def add_share(self, name: str, data: bytes, file_id: str | None = None, limit: int | None = None) -> dict:
        """Store one file and build a QR that opens it. The QR does not expire."""
        file_id = file_id or secrets.token_hex(8)
        safe = sanitize_filename(name)
        folder = self.directory / ".netdrive" / "shares" / file_id
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / safe
        path.write_bytes(data)
        url = f"{share_root(self.http_port)}/f/{file_id}"
        png = qr_png_bytes(url)
        (folder / "qr.png").write_bytes(png)
        row = {
            "id": file_id,
            "name": safe,
            "url": url,
            "size": len(data),
            "path": path,
            "png": png,
            "downloads": 0,
            "limit": share_limit(limit if limit is not None else DEFAULT_SHARE_LIMIT),
        }
        self.shares[file_id] = row
        self.write_share_index()
        return row

    def set_share_limit(self, file_id: str, limit: int) -> bool:
        row = self.shares.get(file_id)
        if row is None:
            return False
        row["limit"] = share_limit(limit)
        self.write_share_index()
        return True

    def write_share_index(self) -> None:
        """Remember every QR so it still opens after the app is restarted."""
        base = self.directory / ".netdrive" / "shares"
        base.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "id": row["id"],
                "name": row["name"],
                "downloads": int(row.get("downloads") or 0),
                "limit": share_limit(row.get("limit")),
            }
            for row in self.shares.values()
        ]
        (base / "index.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")

    def load_saved_shares(self) -> None:
        """Bring back files that were shared earlier, then the course PDF."""
        index = self.directory / ".netdrive" / "shares" / "index.json"
        if index.exists():
            try:
                saved = json.loads(index.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                saved = []
            for item in saved:
                file_id = str(item.get("id") or "")
                name = str(item.get("name") or "")
                path = self.directory / ".netdrive" / "shares" / file_id / name
                if not file_id or not path.is_file():
                    continue
                url = f"{share_root(self.http_port)}/f/{file_id}"
                png = qr_png_bytes(url)
                self.shares[file_id] = {
                    "id": file_id,
                    "name": name,
                    "url": url,
                    "size": path.stat().st_size,
                    "path": path,
                    "png": png,
                    "downloads": int(item.get("downloads") or 0),
                    "limit": share_limit(item.get("limit")),
                }
        self.ensure_course()
        self.write_share_index()

    def ensure_course(self) -> None:
        """The course description is the QR that is ready before any upload."""
        src = HERE / "CN_Course_Description_Odd_2026.pdf"
        if "course" in self.shares:
            row = self.shares["course"]
            row["url"] = f"{share_root(self.http_port)}/f/course"
            row["png"] = qr_png_bytes(row["url"])
            return
        if src.exists():
            self.add_share(src.name, src.read_bytes(), "course")

    def send_upload(self, address: str, files: list[tuple[str, bytes]], contact: str = "") -> None:
        """Send the chosen files to host:port. The code is shown before the bytes move."""
        from netdrive.discovery import parse_hostport

        host, port = parse_hostport(address)
        folder = Path(tempfile.mkdtemp(prefix="netdrive-out-"))
        root = folder / "out"
        root.mkdir()
        nested = False
        total = 0
        for name, data in files:
            rel = name.replace("\\", "/").lstrip("/")
            parts = [part for part in rel.split("/") if part and part not in {".", ".."}]
            if len(parts) > 1:
                nested = True
            dest = root.joinpath(*parts) if parts else root / "upload.bin"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            total += len(data)
        paths = [root] if nested or len(files) > 1 else [next(root.rglob("*"))]

        self.send_cancel = threading.Event()
        cancel = self.send_cancel

        def run() -> None:
            captured = __import__("io").StringIO()
            private, sender_pk, rotating = self._sender_key(contact)
            result = send_files(
                paths,
                host,
                port,
                self.nick,
                out=captured,
                static_private=private,
                sender_pk=sender_pk,
                rotating=rotating,
                cancel=cancel,
                on_progress=lambda line: setattr(self, "progress", line),
            )
            text = captured.getvalue()
            match = CODE_RE.search(text)
            self.send_code = match.group(1) if match else self.send_code
            names = ", ".join(item[0] for item in files)
            if result != 0 and not self.progress:
                self.progress = f"{names} stopped"
            self.status = "Sent." if result == 0 else "The send did not finish."
            if result == 0:
                self.remember(names, total, "sent")

        threading.Thread(target=run, daemon=True).start()

    def start_web(self, name: str, data: bytes) -> None:
        """One-shot browser download. The QR is the HTTPS link."""
        folder = Path(tempfile.mkdtemp(prefix="netdrive-web-"))
        path = folder / Path(name).name
        path.write_bytes(data)
        drop = WebDrop(path, host="0.0.0.0", advertise=lan_ip())
        drop.start()
        self.web_drop = drop
        self.web_url = drop.url()
        self.web_code = drop.code
        self.web_png = qr_png_bytes(self.web_url)
        self.status = "Browser link is ready. Compare the code, then release the download."

    def approve_web(self) -> None:
        """The person at this computer allowed the one download."""
        if self.web_drop is None:
            self.status = "Make a browser link before releasing a download."
            return
        self.web_drop.approve()
        self.status = "Download released. The link works once."

    def snapshot(self) -> dict:
        """JSON for the browser poll."""
        self.visibility = revert_visibility(
            self.visibility, self.previous_visibility, self.visible_since, time.monotonic()
        )
        if self.receiver is not None:
            self.apply_visibility()
        self.refresh_contact_qr()
        peers = []
        if self.visibility != "Off":
            try:
                own_port = self.receiver.port if self.receiver else None
                for peer in discover(window=0.05, own_sid="ui"):
                    if peer.port == own_port:
                        continue
                    peers.append({
                        "nick": peer.nick,
                        "ip": peer.ip,
                        "port": peer.port,
                        "via": "LAN",
                        "seen": "just now",
                    })
            except Exception:
                peers = []
        with self._lock:
            incoming = dict(self.incoming) if self.incoming else None
        if incoming:
            incoming["seconds"] = max(0, int(self.offer_deadline - time.monotonic()))
        book = Contacts(self.directory / ".netdrive" / "contacts.json")
        left = max(0, int(120 - (time.monotonic() - self.qr_started))) if self.qr_started else 120
        return {
            "status": self.status,
            "listen": f"This computer is listening on port {self.receiver.port}." if self.receiver else "",
            "peers": peers,
            "incoming": incoming,
            "progress": self.progress,
            "sendCode": self.send_code,
            "history": list(self.history),
            "settings": {
                "nick": self.nick,
                "maxSize": self.max_size,
                "visibility": self.visibility,
                "language": self.language,
                "relay": self.relay,
                "auto": self.auto,
                "autoLimit": self.auto_limit,
                "directory": str(self.directory),
            },
            "contactQr": {"uri": self.qr_uri, "seconds": left, "stamp": int(self.qr_started)},
            "files": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "url": row["url"],
                    "size": row["size"],
                    "downloads": int(row.get("downloads") or 0),
                    "limit": share_limit(row.get("limit")),
                }
                for row in self.shares.values()
            ],
            "contacts": [{"nick": row.get("nick", "")} for row in book.data["contacts"]],
            "web": {"url": self.web_url, "code": self.web_code, "ready": bool(self.web_png)},
        }


def contact_page(target: str, hub: Hub, saved: bool, error: str = "") -> str:
    """The page a phone opens after scanning the QR."""
    try:
        parse_contact_uri(target)
        ok = True
    except ValueError as exc:
        ok = False
        error = error or str(exc)
    link = html.escape(target, quote=True)
    app = html.escape(hub.qr_app, quote=True)
    nick = html.escape(hub.nick, quote=True)
    message = "Saved on this computer." if saved else "The scan worked. This link can be saved."
    if error and not ok:
        message = html.escape(error)
    form = ""
    if ok and not saved:
        form = f"""
        <form method="post" action="{link}">
          <label>Name <input name="nick" value="{nick}"></label>
          <button type="submit">Save this contact</button>
        </form>"""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetDrive contact</title>
<style>
body {{ margin: 0; background: #f3f0e8; color: #1c1915; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; }}
main {{ max-width: 560px; margin: 0 auto; padding: 36px 22px; }}
h1 {{ font-family: Palatino, Georgia, serif; font-weight: 500; font-size: 32px; }}
a, p.link {{ overflow-wrap: anywhere; font-family: Consolas, monospace; font-size: 14px; color: #0e6b52; }}
button, input {{ font: inherit; padding: 8px 12px; }}
button {{ background: #0e6b52; color: #f3f0e8; border: 0; cursor: pointer; }}
label {{ display: block; margin: 14px 0; }}
</style></head>
<body><main>
<p>NetDrive</p>
<h1>{message}</h1>
<p>Open this page on the other computer, type a name, and press Save. Or paste the app link into Settings.</p>
<p class="link">{app}</p>
{form}
</main></body></html>"""


def serve(directory: Path, port: int = 8765, block: bool = True) -> ThreadingHTTPServer:
    """Serve the UI. Tests pass block=False and get the server back."""
    hub = Hub(Path(directory))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/api/state"):
                self._json(hub.snapshot())
                return
            name = self.path.split("?", 1)[0]
            if name.startswith("/f/"):
                item = hub.shares.get(name[3:])
                if item is None:
                    self.send_error(404)
                    return
                used = int(item.get("downloads") or 0)
                cap = share_limit(item.get("limit"))
                if used >= cap:
                    self.send_error(403, "Download limit reached")
                    return
                item["downloads"] = used + 1
                hub.write_share_index()
                payload = Path(item["path"]).read_bytes()
                kind = mimetypes.guess_type(item["name"])[0] or "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Disposition", f'inline; filename="{item["name"]}"')
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if name.startswith("/api/share/") and name.endswith(".png"):
                item = hub.shares.get(name[len("/api/share/"):-4])
                if item is None:
                    self.send_error(404)
                    return
                self._bytes(item["png"], "image/png")
                return
            if name == "/c":
                self._html(contact_page(self.path, hub, saved=False))
                return
            if name == "/api/contact/qr.png":
                hub.refresh_contact_qr()
                self._bytes(hub.qr_png, "image/png")
                return
            if name == "/api/web/qr.png" and hub.web_png:
                self._bytes(hub.web_png, "image/png")
                return
            mapping = {
                "/": HERE / "index.html",
                "/app.css": HERE / "app.css",
                "/app.js": HERE / "app.js",
                "/strings_en.json": HERE / "strings_en.json",
                "/strings_hi.json": HERE / "strings_hi.json",
            }
            target = mapping.get(name)
            if target is None or not target.exists():
                self.send_error(404)
                return
            kind = "text/html"
            if name.endswith(".css"):
                kind = "text/css"
            elif name.endswith(".js"):
                kind = "text/javascript"
            elif name.endswith(".json"):
                kind = "application/json"
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                payload = {}
            path = self.path.split("?", 1)[0]
            if path == "/c":
                fields = parse_qs(raw.decode("utf-8", "replace"))
                nick = (fields.get("nick") or ["Contact"])[0]
                try:
                    pk, secret = parse_contact_uri(self.path)
                    Contacts(hub.directory / ".netdrive" / "contacts.json").add(nick or "Contact", pk, secret, auto=hub.auto, limit=hub.auto_limit)
                    hub.qr_used = True
                    hub.status = f"Saved contact {nick or 'Contact'}."
                    self._html(contact_page(self.path, hub, saved=True))
                except ValueError as exc:
                    hub.status = str(exc)
                    self._html(contact_page(self.path, hub, saved=False, error=str(exc)))
                return
            if path == "/api/share":
                raw_name = str(payload.get("name") or "file.pdf")
                data = base64.b64decode(payload.get("b64") or b"")
                row = hub.add_share(raw_name, data, limit=payload.get("limit"))
                hub.status = f"QR ready for {row['name']}. It does not expire."
                self._json({"ok": True, "file": {"id": row["id"], "name": row["name"], "url": row["url"], "size": row["size"], "downloads": 0, "limit": row["limit"]}})
                return
            if path == "/api/share/limit":
                ok = hub.set_share_limit(str(payload.get("id") or ""), payload.get("limit"))
                hub.status = "Download limit updated." if ok else "That share was not found."
                self._json({"ok": ok})
                return
            elif path == "/api/decision":
                hub.decide(bool(payload.get("accept")), bool(payload.get("danger_ok")))
            elif path == "/api/demo":
                hub.demo()
            elif path == "/api/send":
                files = payload.get("files")
                if not isinstance(files, list):
                    files = [{"name": payload.get("name") or "upload.bin", "b64": payload.get("b64") or ""}]
                decoded = [
                    (item.get("name") or "upload.bin", base64.b64decode(item.get("b64") or b""))
                    for item in files
                ]
                if not decoded or not str(payload.get("to") or "").strip():
                    hub.status = "Choose a file and an address like 127.0.0.1:5000."
                else:
                    hub.status = "Sending. Compare the code, then wait for the other side to accept."
                    hub.send_upload(payload.get("to") or "", decoded, str(payload.get("contact") or ""))
            elif path == "/api/send/cancel":
                hub.send_cancel.set()
                hub.status = "Cancelled. Partial files removed."
            elif path == "/api/web":
                hub.start_web(payload.get("name") or "download.bin", base64.b64decode(payload.get("b64") or b""))
            elif path == "/api/web/approve":
                hub.approve_web()
            elif path == "/api/settings":
                hub.nick = str(payload.get("nick") or hub.nick)[:32]
                hub.max_size = int(payload.get("maxSize") or hub.max_size)
                chosen = str(payload.get("visibility") or hub.visibility)
                if chosen != hub.visibility:
                    hub.previous_visibility = hub.visibility
                    hub.visible_since = time.monotonic()
                hub.visibility = chosen
                hub.language = "hi" if payload.get("language") == "hi" else "en"
                hub.relay = bool(payload.get("relay"))
                hub.auto = bool(payload.get("auto"))
                if payload.get("autoLimit"):
                    hub.auto_limit = int(payload.get("autoLimit"))
                book = Contacts(hub.directory / ".netdrive" / "contacts.json")
                for row in book.data["contacts"]:
                    row["auto"] = hub.auto
                    row["limit"] = hub.auto_limit
                if book.data["contacts"]:
                    book.save()
                from netdrive.sim import mesh
                mesh.RELAY = hub.relay
                hub.apply_visibility()
                hub.status = "Settings saved."
            elif path == "/api/mesh":
                from netdrive.sim.mesh import run_mesh
                hub.status = run_mesh()
            elif path == "/api/contact/show":
                hub.refresh_contact_qr(force=True)
                self._json({"ok": True, "uri": hub.qr_uri})
                return
            elif path == "/api/contact/add":
                try:
                    pk, secret = parse_contact_uri(str(payload.get("link") or ""))
                except ValueError as exc:
                    hub.status = str(exc)
                else:
                    Contacts(hub.directory / ".netdrive" / "contacts.json").add(
                        str(payload.get("nick") or "Contact"),
                        pk,
                        secret,
                        auto=hub.auto,
                        limit=hub.auto_limit,
                    )
                    hub.qr_used = True
                    hub.status = "Contact saved. That QR picture is now retired."
            elif path == "/api/history/clear":
                hub.history.clear()
            elif path == "/api/history/delete":
                index = int(payload.get("index", -1))
                if 0 <= index < len(hub.history):
                    hub.history.pop(index)
            self._json({"ok": True})

        def _html(self, body: str) -> None:
            raw = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _bytes(self, body: bytes, kind: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, body: dict) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args) -> None:
            return

    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    hub.http_port = httpd.server_address[1]
    hub.refresh_contact_qr(force=True)
    hub.load_saved_shares()
    if not block:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd
    shown = httpd.server_address[1]
    print(f"NetDrive UI at http://127.0.0.1:{shown}/", flush=True)
    print(f"Anyone can open {share_root(shown)}/f/course", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return httpd
