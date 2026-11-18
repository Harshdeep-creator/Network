"""Typed failures. The CLI turns each one into a single sentence."""


class NetDriveError(Exception):
    """Base error for anything the user can act on."""


class HandshakeError(NetDriveError):
    """The two sides never agreed on a session key."""


class AuthError(NetDriveError):
    """A frame failed its authentication tag."""


class ProtocolError(NetDriveError):
    """A frame or offer was not valid."""


class DeclinedError(NetDriveError):
    """The receiver refused the offer."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class IntegrityError(NetDriveError):
    """The file hash did not match."""


class CancelledError(NetDriveError):
    """Someone cancelled the transfer."""
