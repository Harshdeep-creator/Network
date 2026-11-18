"""One-line progress: percent, sizes, a 3-second speed, and ETA."""

from __future__ import annotations

import time
from collections import deque


def format_bytes(size: int) -> str:
    """A short size. Uses one decimal past bytes."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if unit == "B" or value < 1024:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def format_eta(seconds: float) -> str:
    """MM:SS, or --:-- when the speed is zero."""
    if seconds == float("inf") or seconds < 0:
        return "--:--"
    whole = int(seconds)
    if whole >= 100 * 60:
        whole = 99 * 60 + 59
    return f"{whole // 60:02d}:{whole % 60:02d}"


class Progress:
    """Byte counter with a moving average over the last 3 seconds."""

    def __init__(self, total: int, label: str, clock=time.monotonic) -> None:
        self.total = max(0, int(total))
        self.label = label
        self.clock = clock
        self.done = 0
        self.samples: deque[tuple[float, int]] = deque()
        self.samples.append((self.clock(), 0))
        self.last_render = 0.0

    def update(self, n_bytes: int) -> None:
        """Record that `n_bytes` more have moved."""
        self.done += n_bytes
        now = self.clock()
        self.samples.append((now, self.done))
        cutoff = now - 3.0
        while len(self.samples) > 1 and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def speed(self) -> float:
        """Bytes per second over the samples still inside the window."""
        if len(self.samples) < 2:
            return 0.0
        start_t, start_b = self.samples[0]
        end_t, end_b = self.samples[-1]
        span = end_t - start_t
        if span <= 0:
            return 0.0
        return max(0.0, (end_b - start_b) / span)

    def due(self, minimum: float = 1.0) -> bool:
        """True at the first call and at least once per `minimum` seconds."""
        now = self.clock()
        if self.last_render == 0.0 or now - self.last_render >= minimum:
            self.last_render = now
            return True
        return False

    def render(self) -> str:
        """The single status line."""
        if self.total <= 0:
            percent = 100 if self.done > 0 or self.total == 0 else 0
        else:
            percent = min(100, int(self.done * 100 / self.total))
        rate = self.speed()
        if rate <= 0 or self.done >= self.total:
            eta = "00:00" if self.total and self.done >= self.total else "--:--"
            if self.total == 0:
                eta = "00:00"
        else:
            eta = format_eta((self.total - self.done) / rate)
        mb = rate / (1024 * 1024)
        return (
            f"{self.label} {percent}% {format_bytes(self.done)} / {format_bytes(self.total)} "
            f"{mb:.1f} MB/s ETA {eta}"
        )

    def finish(self) -> str:
        """Force the line to 100% when the byte count already arrived."""
        self.done = max(self.done, self.total)
        return self.render()
