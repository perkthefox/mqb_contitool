"""OpenPDU: a portable client for the VAS 6154 diagnostic interface (VCI), without the vendor D-PDU driver.

Talks to the VCI over its own TCP protocol (port 4500), so it runs wherever Python does. Layers, bottom up:

- `wire`      frames and messages
- `comparams` the ComParam blocks a link is configured with
- `session`   `Vci`: one TCP session (greet, clock sync, request/reply routing)
- `links`     `MonitorLink`, `RawLink`, `IsoTpLink`
- `can_bus`   `OpenPduBus`, a python-can bus (imported on demand: the rest needs only the standard library)

    with Vci.connect("192.168.0.10") as vci:
        with vci.isotp_link(0x710, 0x77A) as uds:
            print(uds.request(bytes.fromhex("22F187")).hex())
"""

from .errors import ConnectionLost, OpenPduError, ProtocolError, Refused, VciTimeout
from .links import IsoTpLink, MonitorLink, RawLink
from .session import Vci
from .wire import CanRecord

__all__ = [
    "CanRecord", "ConnectionLost", "IsoTpLink", "MonitorLink", "OpenPduError", "ProtocolError", "RawLink",
    "Refused", "Vci", "VciTimeout",
]
