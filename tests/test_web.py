import ssl
import urllib.error
import urllib.request
from pathlib import Path

from netdrive.webreceiver import WebDrop, write_qr


def _open(url: str) -> bytes:
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(url, context=context) as response:
        return response.read()


def test_web_token(tmp_path: Path):
    src = tmp_path / "lab.txt"
    src.write_text("lab notes")
    drop = WebDrop(src, ttl=300)
    drop.start()
    try:
        page = _open(drop.url()).decode("utf-8")
        assert drop.code in page
        try:
            _open(drop.url() + "/file")
            assert False
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        try:
            _open(f"https://127.0.0.1:{drop.port}/" + "ab" * 16)
            assert False
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        drop.approve()
        assert _open(drop.url() + "/file") == b"lab notes"
        try:
            _open(drop.url() + "/file")
            assert False
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        write_qr(drop.url(), tmp_path / "web-qr.png")
        assert (tmp_path / "web-qr.png").stat().st_size > 20
    finally:
        drop.stop()

    expired = WebDrop(src, ttl=0)
    expired.created -= 5
    expired.start()
    try:
        try:
            _open(expired.url())
            assert False
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        expired.stop()
