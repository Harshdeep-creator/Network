"""Path choice for the simulated radio. LAN, then hotspot, then Wi-Fi Direct, then BLE."""

from __future__ import annotations

ORDER = ("lan", "hotspot", "wifi-direct", "ble-l2cap", "ble-gatt")
LABELS = {
    "lan": "Wi-Fi LAN (TCP, encrypted)",
    "hotspot": "simulated hotspot",
    "wifi-direct": "simulated Wi-Fi Direct",
    "ble-l2cap": "simulated BLE L2CAP",
    "ble-gatt": "simulated BLE GATT",
}


def choose_path(down: set[str] | None = None) -> str:
    """First link that was not failed. Raises if every link is down."""
    blocked = down or set()
    for name in ORDER:
        if name not in blocked:
            return name
    raise RuntimeError("No path is available.")


def path_label(name: str) -> str:
    """The sentence shown next to a transfer."""
    return "Path: " + LABELS.get(name, name)


def exchange_upgrade(down: set[str] | None = None) -> str:
    """Send UPGRADE_OFFER and UPGRADE_ACCEPT on a real encrypted channel."""
    import json
    import socket
    import threading

    from netdrive.channel import SecureChannel
    from netdrive.protocol import MSG_UPGRADE_ACCEPT, MSG_UPGRADE_OFFER

    chosen = choose_path(down)
    left, right = socket.socketpair()
    box: dict = {}

    def accept() -> None:
        box["b"] = SecureChannel.accept(right)

    thread = threading.Thread(target=accept)
    thread.start()
    box["a"] = SecureChannel.connect(left)
    thread.join(timeout=5)
    body = json.dumps({"path": chosen, "host": "127.0.0.1", "port": 9, "token": "demo"}).encode()
    box["a"].send(MSG_UPGRADE_OFFER, body)
    kind, _payload = box["b"].recv(timeout=5)
    if kind != MSG_UPGRADE_OFFER:
        raise RuntimeError("The upgrade offer did not arrive.")
    box["b"].send(MSG_UPGRADE_ACCEPT, b"")
    kind, _payload = box["a"].recv(timeout=5)
    if kind != MSG_UPGRADE_ACCEPT:
        raise RuntimeError("The upgrade was not accepted.")
    box["a"].close()
    box["b"].close()
    return f"upgrade {chosen} accepted"


def path_report(wait: float = 10.0, sleeper=None) -> str:
    """One line per failure case. A failed link waits 10 seconds, then the next is tried."""
    cases = [
        (set(), "lan"),
        ({"lan"}, "hotspot"),
        ({"lan", "hotspot"}, "wifi-direct"),
        ({"lan", "hotspot", "wifi-direct"}, "ble-l2cap"),
        ({"lan", "hotspot", "wifi-direct", "ble-l2cap"}, "ble-gatt"),
    ]
    lines = []
    for down, expected in cases:
        got = ""
        for name in ORDER:
            if name in down:
                if sleeper is not None:
                    sleeper(wait)
                lines.append(f"waited {int(wait)}s after {name}")
                continue
            got = name
            break
        if got != expected:
            raise RuntimeError(f"Path choice returned {got}, expected {expected}.")
        label = ",".join(sorted(down)) or "none"
        lines.append(f"{label} -> {got}")
    lines.append(exchange_upgrade({"lan"}))
    return "\n".join(lines)
