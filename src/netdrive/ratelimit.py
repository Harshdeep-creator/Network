"""Five offers a minute, then a mute after three declines in a row."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class _PeerWindow:
    events: list[float] = field(default_factory=list)
    declines: int = 0
    muted_until: float = 0.0


class RateLimiter:
    """Per-peer token bucket. `now` is monotonic seconds supplied by the caller."""

    def __init__(self, limit: int = 5, window: float = 60.0, mute_after: int = 3, mute_for: float = 15 * 60) -> None:
        self.limit = limit
        self.window = window
        self.mute_after = mute_after
        self.mute_for = mute_for
        self._peers: dict[str, _PeerWindow] = {}

    def allow(self, peer: str, now: float) -> bool:
        """Record an offer when it is allowed. A refused offer is not recorded."""
        state = self._peers.setdefault(peer, _PeerWindow())
        if now < state.muted_until:
            return False
        state.events = [stamp for stamp in state.events if now - stamp < self.window]
        if len(state.events) >= self.limit:
            return False
        state.events.append(now)
        return True

    def declined(self, peer: str, now: float) -> None:
        """Count a refusal. Three in a row mute the peer."""
        state = self._peers.setdefault(peer, _PeerWindow())
        state.declines += 1
        if state.declines >= self.mute_after:
            state.muted_until = now + self.mute_for
            state.declines = 0

    def accepted(self, peer: str) -> None:
        """A successful accept clears the decline streak."""
        state = self._peers.setdefault(peer, _PeerWindow())
        state.declines = 0
