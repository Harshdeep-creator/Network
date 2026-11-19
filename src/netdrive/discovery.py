"""UDP beacons on port 47821, plus a manual HOST:PORT fallback."""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass

PORT = 47821
BEACON_LIMIT = 512


def broadcast_targets() -> tuple[str, ...]:
    """Limited broadcast, this machine, and the /24 broadcast Wi-Fi usually needs."""
    targets = ["255.255.255.255", "127.0.0.1"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except OSError:
        ip = ""
    finally:
        sock.close()
    parts = ip.split(".")
    if len(parts) == 4 and not ip.startswith("127."):
        directed = ".".join(parts[:3] + ["255"])
        if directed not in targets:
            targets.append(directed)
    return tuple(targets)


@dataclass(frozen=True)
class Peer:
    """A receiver heard on the LAN. `sid` changes every process run."""

    nick: str
    ip: str
    port: int
    sid: str
    last_seen: float


def parse_hostport(text: str) -> tuple[str, int]:
    """Parse an IPv4 host and port. The message is safe to show the user."""
    if text.count(":") != 1:
        raise ValueError("Use an address like 192.168.1.20:5000.")
    host, port_text = text.split(":")
    try:
        ipaddress.IPv4Address(host)
        port = int(port_text)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValueError("Use an IPv4 address and a port, like 192.168.1.20:5000.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("The port has to be between 1 and 65535.")
    return host, port


def parse_beacon(data: bytes, source_ip: str, now: float, own_sid: str = "") -> Peer | None:
    """Return a peer, or None when the datagram must be ignored."""
    if len(data) > BEACON_LIMIT:
        return None
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(body, dict):
        return None
    if body.get("app") != "netdrive" or body.get("v") != 1:
        return None
    nick, sid, port = body.get("nick"), body.get("sid"), body.get("port")
    if not isinstance(nick, str) or not isinstance(sid, str) or not isinstance(port, int):
        return None
    if sid == "" or (own_sid and sid == own_sid):
        return None
    if not 1 <= port <= 65535 or len(nick) > 32:
        return None
    return Peer(nick=nick, ip=source_ip, port=port, sid=sid, last_seen=now)


def expire_peers(peers: list[Peer], now: float, ttl: float = 15.0) -> list[Peer]:
    """Drop peers that have been quiet for `ttl` seconds."""
    return [peer for peer in peers if now - peer.last_seen <= ttl]


def merge_peer(peers: list[Peer], heard: Peer) -> list[Peer]:
    """Replace the previous row with the same ip and sid."""
    kept = [peer for peer in peers if not (peer.ip == heard.ip and peer.sid == heard.sid)]
    kept.append(heard)
    return kept


class Beacon:
    """Broadcasts a receiver advertisement until `stop`."""

    def __init__(self, nick: str, tcp_port: int, sid: str, interval: float = 2.0, allow=None, broadcast: bool = True) -> None:
        self.nick = nick
        self.tcp_port = tcp_port
        self.sid = sid
        self.interval = interval
        self.allow = allow or (lambda _data: True)
        self.broadcast = broadcast
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.error = ""

    def payload(self) -> bytes:
        """The beacon JSON. It has no stable device id."""
        body = {
            "app": "netdrive",
            "v": 1,
            "nick": self.nick,
            "port": self.tcp_port,
            "sid": self.sid,
        }
        return json.dumps(body, separators=(",", ":")).encode("utf-8")

    def start(self) -> None:
        """Start the broadcast thread. A failure is stored on `error` and does not raise."""
        self._thread = threading.Thread(target=self._run, name="netdrive-beacon", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Ask the broadcast thread to exit."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listening = False
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("", PORT))
                sock.settimeout(0.2)
                listening = True
            except OSError as exc:
                self.error = str(exc)
            next_send = 0.0
            while not self._stop.is_set():
                now = time.monotonic()
                if self.broadcast and now >= next_send:
                    packet = self.payload()
                    for target in broadcast_targets():
                        try:
                            sock.sendto(packet, (target, PORT))
                        except OSError as exc:
                            self.error = str(exc)
                    next_send = now + self.interval
                if not listening:
                    self._stop.wait(self.interval)
                    continue
                try:
                    data, addr = sock.recvfrom(BEACON_LIMIT + 64)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if is_who(data) and self.allow(data):
                    try:
                        sock.sendto(self.payload(), addr)
                    except OSError as exc:
                        self.error = str(exc)
        finally:
            sock.close()


def is_who(data: bytes) -> bool:
    """True for a plain WHO datagram or a JSON who query."""
    if data.strip() == b"WHO":
        return True
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(body, dict) and body.get("app") == "netdrive" and body.get("op") == "who"


def discover(window: float = 3.0, own_sid: str = "", now=time.monotonic) -> list[Peer]:
    """Listen for beacons. If the port cannot be opened, return an empty list."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("", PORT))
        except OSError:
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("0.0.0.0", 0))
            for target in broadcast_targets():
                try:
                    sock.sendto(b"WHO", (target, PORT))
                except OSError:
                    pass
        sock.settimeout(0.2)
        peers: list[Peer] = []
        deadline = now() + window
        while now() < deadline:
            try:
                data, addr = sock.recvfrom(BEACON_LIMIT + 64)
            except TimeoutError:
                continue
            except OSError:
                break
            heard = parse_beacon(data[:BEACON_LIMIT], addr[0], now(), own_sid)
            if heard:
                peers = merge_peer(peers, heard)
        return expire_peers(peers, now())
    finally:
        sock.close()
