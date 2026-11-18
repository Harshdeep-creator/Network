import json
import time
import urllib.request
from pathlib import Path

from netdrive.ui.server import serve


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url) as response:
        return response.read()


def test_ui_routes_and_decline(tmp_path: Path):
    httpd = serve(tmp_path, 0, block=False)
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"
    page = _get(base + "/").decode("utf-8")
    assert "NetDrive" in page and "Nearby" in page
    state = json.loads(_get(base + "/api/state"))
    assert "status" in state
    request = urllib.request.Request(
        base + "/api/demo",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(request).read()
    incoming = None
    for _ in range(40):
        incoming = json.loads(_get(base + "/api/state")).get("incoming")
        if incoming:
            break
        time.sleep(0.1)
    assert incoming and incoming["code"]
    request = urllib.request.Request(
        base + "/api/decision",
        data=json.dumps({"accept": False}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(request).read()
    time.sleep(0.4)
    assert not any(path.name == "session-note.txt" for path in tmp_path.rglob("*"))
    httpd.shutdown()
