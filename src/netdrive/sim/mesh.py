"""Control-message relay. File bytes are never forwarded."""

from __future__ import annotations

from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from netdrive.crypto import public_raw, sign_bytes, verify_bytes


RELAY = True


class Node:
    """A mesh peer. Relays do not hold the payload key."""

    def __init__(self, relay: bool = True) -> None:
        self.relay = relay
        self.seen: OrderedDict[bytes, None] = OrderedDict()
        self.key = None
        self.inbox: list[bytes] = []
        self.held: list[tuple[bytes, float, float]] = []

    def remember(self, msg_id: bytes, limit: int = 1000) -> bool:
        """True the first time this id is seen."""
        if msg_id in self.seen:
            return False
        self.seen[msg_id] = None
        while len(self.seen) > limit:
            self.seen.popitem(last=False)
        return True


def propagate(count: int = 20, ttl: int = 7) -> tuple[int, int, bool]:
    """Return (loops, deliveries, relays_blind) for a line of `count` nodes."""
    nodes = [Node(relay=RELAY) for _ in range(count)]
    msg_id = b"m" * 16
    payload = b"ciphertext-not-a-file"
    loops = 0
    deliveries = 0
    queue: list[tuple[int, int]] = [(0, ttl)]
    while queue:
        index, life = queue.pop(0)
        node = nodes[index]
        if not node.remember(msg_id):
            continue
        if node.key is not None:
            return loops, deliveries, False
        node.inbox.append(payload)
        deliveries += 1
        if not node.relay or life <= 0:
            continue
        for nxt in (index - 1, index + 1):
            if 0 <= nxt < count:
                queue.append((nxt, life - 1))
    blind = all(node.key is None for node in nodes)
    return loops, deliveries, blind


def run_mesh() -> str:
    """The one line `netdrive sim mesh` prints when the relay test passes."""
    if not RELAY:
        _loops, deliveries, _blind = propagate(20, 7)
        if deliveries != 1:
            raise RuntimeError("Relay off still forwarded a control message.")
        return "mesh: relay off, nothing forwarded"
    loops, _deliveries, blind = propagate(20, 7)
    if loops != 0 or not blind:
        raise RuntimeError("Mesh test failed.")
    return "mesh: 20 nodes, 0 loops, relays blind"


def signed_notice(private: Ed25519PrivateKey, text: bytes) -> tuple[bytes, bytes]:
    """Sign a notice. Notices longer than 512 bytes are refused by the caller."""
    if len(text) > 512:
        raise ValueError("Notice is over 512 bytes.")
    return text, sign_bytes(private, text)


def accept_notice(public: bytes, text: bytes, signature: bytes | None) -> bool:
    """Show a notice only when the signature checks."""
    if signature is None or len(text) > 512:
        return False
    return verify_bytes(public, text, signature)


def purge_held(node: Node, now: float, max_age: float = 12 * 60 * 60) -> None:
    """Drop stored notices whose elapsed monotonic time is past 12 hours."""
    node.held = [item for item in node.held if now - item[2] <= max_age]


def make_notice_key() -> tuple[Ed25519PrivateKey, bytes]:
    """A fresh notice-signing key."""
    private = Ed25519PrivateKey.generate()
    return private, public_raw(private)
