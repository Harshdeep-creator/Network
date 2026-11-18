"""One-shot HTTPS download. The token dies after one fetch or five minutes."""

from __future__ import annotations

import datetime
import hmac
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from netdrive.crypto import browser_code, spki_der
from netdrive.sanitize import sanitize_filename


def make_cert() -> tuple[bytes, bytes, bytes]:
    """A certificate that lives only for this process. Returns (cert pem, key pem, spki)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "netdrive.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem, spki_der(cert)


class WebDrop:
    """Serves one file on 127.0.0.1 until it is taken or it expires."""

    def __init__(self, path: Path, ttl: float = 300.0, host: str = "127.0.0.1", port: int = 0, advertise: str | None = None) -> None:
        self.path = Path(path)
        self.ttl = ttl
        self.host = host
        self.advertise = advertise or host
        self.token = __import__("secrets").token_hex(16)
        self.created = time.monotonic()
        self.approved = threading.Event()
        self.used = False
        self.cert_pem, self.key_pem, self.spki = make_cert()
        self.code = browser_code(self.spki, self.token.encode("ascii"))
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def url(self) -> str:
        """The single URL encoded by the QR image."""
        shown = self.advertise if self.advertise != "0.0.0.0" else "127.0.0.1"
        return f"https://{shown}:{self.port}/{self.token}"

    def start(self) -> None:
        """Bind and serve in a background thread."""
        drop = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                token = self.path.strip("/").split("/", 1)[0]
                if not drop._token_ok(token):
                    self.send_error(404)
                    return
                if drop.used or time.monotonic() - drop.created > drop.ttl:
                    self.send_error(404)
                    return
                if self.path.rstrip("/").endswith("/file"):
                    if not drop.approved.is_set():
                        body = b"The sender has not released this file yet."
                        self.send_response(403)
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    data = drop.path.read_bytes()
                    drop.used = True
                    name = sanitize_filename(drop.path.name)
                    self.send_response(200)
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                page = drop._page().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)

            def log_message(self, fmt: str, *args) -> None:
                return

        self._httpd = ThreadingHTTPServer((self.host, 0), Handler)
        self.port = self._httpd.server_address[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_path = self.path.parent / f".netdrive-cert-{self.port}.pem"
        key_path = self.path.parent / f".netdrive-key-{self.port}.pem"
        cert_path.write_bytes(self.cert_pem)
        key_path.write_bytes(self.key_pem)
        context.load_cert_chain(cert_path, key_path)
        self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the temporary server."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    def approve(self) -> None:
        """The person at the keyboard allowed the download."""
        self.approved.set()

    def _token_ok(self, presented: str) -> bool:
        if len(presented) != len(self.token):
            return False
        return hmac.compare_digest(presented, self.token)

    def _page(self) -> str:
        name = sanitize_filename(self.path.name)
        size = self.path.stat().st_size
        digest = __import__("hashlib").sha256(self.path.read_bytes()).hexdigest()
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>NetDrive</title>
<style>
body {{ margin: 0; background: #f3f0e8; color: #1c1915; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; }}
main {{ max-width: 640px; margin: 48px auto; padding: 0 24px; }}
h1 {{ font-family: "Source Serif 4", Palatino, Georgia, serif; font-weight: 500; font-size: 32px; }}
.code {{ font-family: Consolas, monospace; font-size: 40px; letter-spacing: 0.12em; margin: 12px 0 24px; }}
a {{ display: inline-block; background: #0e6b52; color: #f3f0e8; text-decoration: none; padding: 10px 16px; }}
p {{ line-height: 1.5; }}
</style></head>
<body><main>
<p>NetDrive</p>
<h1>Check the code, then download.</h1>
<p>Compare this with the sender's screen before you take the file.</p>
<div class="code">{self.code}</div>
<p>{name}<br>{size} bytes<br>SHA-256 {digest}</p>
<p><a href="/{self.token}/file">Download</a></p>
</main></body></html>"""


def qr_png_bytes(url: str) -> bytes:
    """PNG bytes for a QR picture a phone camera can scan."""
    import io

    import qrcode
    from qrcode.constants import ERROR_CORRECT_M
    from qrcode.image.pure import PyPNGImage

    code = qrcode.QRCode(error_correction=ERROR_CORRECT_M, box_size=8, border=2)
    code.add_data(url)
    code.make(fit=True)
    image = code.make_image(image_factory=PyPNGImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue()


def write_qr(url: str, dest: Path) -> None:
    """Write a PNG QR for the one-shot URL."""
    dest.write_bytes(qr_png_bytes(url))
