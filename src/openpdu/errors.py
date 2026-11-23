"""Errors raised by OpenPDU. Messages are English; `code` carries the VCI's own status code where there is one."""

from __future__ import annotations


class OpenPduError(Exception):
    """Base class. `code` is the VCI's 16-bit status code when the VCI itself refused something, else None."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class ProtocolError(OpenPduError):
    """The VCI sent something that does not parse, or not what the session expects at this point."""


class ConnectionLost(OpenPduError):
    """The TCP session to the VCI ended (closed by the VCI, a network error, or closed here)."""


class VciTimeout(OpenPduError, TimeoutError):
    """The VCI did not answer in time."""


class Refused(OpenPduError):
    """The VCI answered with a non-zero status code (see `code`)."""
