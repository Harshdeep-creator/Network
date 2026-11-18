"""Verified contacts and the block list. Stored beside the receive folder."""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_LIMIT = 10 * 1024 * 1024


class Contacts:
    """A small JSON book. Public keys are hex. Nothing here is a server."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = {"contacts": [], "blocked": []}
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data["contacts"] = list(loaded.get("contacts") or [])
                self.data["blocked"] = list(loaded.get("blocked") or [])

    def save(self) -> None:
        """Write the book. The parent directory is created when needed."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def by_nick(self, nick: str) -> dict | None:
        """The contact row with this nickname, if any."""
        for row in self.data["contacts"]:
            if row.get("nick") == nick:
                return row
        return None

    def add(self, nick: str, pk_hex: str, secret_hex: str, auto: bool = False, limit: int = DEFAULT_LIMIT) -> None:
        """Store a verified contact, replacing an older row with the same name."""
        self.data["contacts"] = [row for row in self.data["contacts"] if row.get("nick") != nick]
        self.data["contacts"].append(
            {
                "nick": nick,
                "pk": pk_hex,
                "secret": secret_hex,
                "verified": True,
                "auto": auto,
                "limit": limit,
            }
        )
        self.save()

    def block(self, pk_hex: str) -> None:
        """Drop offers from this public key before the prompt."""
        if pk_hex not in self.data["blocked"]:
            self.data["blocked"].append(pk_hex)
            self.save()

    def is_blocked(self, pk_hex: str) -> bool:
        """True when the key was blocked from the offer dialog."""
        return pk_hex in self.data["blocked"]

    def key_changed(self, nick: str, presented_hex: str) -> bool:
        """True when a known contact shows a different key."""
        row = self.by_nick(nick)
        return bool(row and row.get("pk") and row["pk"] != presented_hex)

    def may_auto(self, nick: str, total: int) -> bool:
        """Auto-accept only a verified contact, and only under that contact's limit."""
        row = self.by_nick(nick)
        if not row or not row.get("verified") or not row.get("auto"):
            return False
        return total <= int(row.get("limit", DEFAULT_LIMIT))
