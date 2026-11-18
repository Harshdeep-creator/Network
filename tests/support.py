"""Shared listener for the transfer tests."""

from __future__ import annotations

import threading
from pathlib import Path

from netdrive.receiver import Receiver


def listen(directory: Path, prompt=lambda summary, offer: True, **kwargs) -> Receiver:
    """Start a receiver on an ephemeral local port."""
    receiver = Receiver(directory, kwargs.pop("nick", "Maya"), 0, host="127.0.0.1", prompt=prompt, **kwargs)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    return receiver
