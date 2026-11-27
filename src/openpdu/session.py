"""One TCP session with a VCI: greet, clock sync, the request/reply engine and the reader thread.

The VCI speaks first (greet with its firmware version). The PC then syncs the VCI clock and configures its
firmware; after that links are created and primitives run. Replies are routed by the reader thread:

- a link create/connect/disconnect/destroy or an IOCTL is answered synchronously, one request at a time; a request
  left unanswered, or answered with something that does not belong to it, ends the session (as in the reference
  driver: replies carry no request id, so after that none could be matched any more);
- acks and results of a primitive carry (link id, hCop) and go to whoever subscribed that pair;
- pings are answered right away, log lines and link events go to the "openpdu" logger, a malformed message is
  dropped with a warning (the reference driver drops those too).
"""

from __future__ import annotations

import contextlib
import itertools
import logging
import queue
import socket
import struct
import threading
import time
from typing import Any

from . import wire
from .errors import ConnectionLost, OpenPduError, ProtocolError, Refused, VciTimeout
from .links import IsoTpLink, MonitorLink, RawLink

log = logging.getLogger("openpdu")

GREET_TIMEOUT = 15.0  # as the reference driver
SYNC_TIMEOUT = 12.0
KEEPALIVE = 5  # s: TCP keepalive idle time and interval, as the reference driver
KEEPALIVE_PROBES = 3
MAX_FRAME_BYTES = 1_048_576  # 1 MiB cap on incoming frames to prevent unbounded allocation
PONG_QUEUE_SIZE = 16

Replies = queue.Queue  # of wire.Message, or the OpenPduError that ended the session


class Vci:
    """A connected VCI. Use `Vci.connect(host)`; close it (or use `with`) to free every link it holds."""

    def __init__(self, sock: socket.socket, greet: wire.Greet, host: str) -> None:
        self.host = host
        self.greet = greet
        self._sock = sock
        self._send_lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self._sync_replies: Replies = queue.Queue()
        self._subscribers: dict[tuple[int, int], Replies] = {}
        self._routes_lock = threading.Lock()  # subscribing and failing the session must not interleave
        self._hcops = itertools.count()
        self._hcop_lock = threading.Lock()
        self._error: OpenPduError | None = None
        self._closing = False
        self._pong_queue: queue.Queue[int | None] = queue.Queue(maxsize=PONG_QUEUE_SIZE)
        self._pong_thread: threading.Thread | None = None
        self._reader = threading.Thread(target=self._read_loop, name=f"openpdu-{host}", daemon=True)
        self._reader.start()

    # -- lifetime ----------------------------------------------------------------------------------------------

    @classmethod
    def connect(cls, host: str, port: int = wire.PORT, *, timeout: float = GREET_TIMEOUT,
                remote_logging: bool = False) -> Vci:
        """Open the session: TCP connect, greet, clock sync, firmware configuration. Any firmware version is taken."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise ConnectionLost(f"cannot reach VCI at {host}:{port}: {exc}") from exc
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            _keepalive(sock)
            greet = _read_greet(sock, timeout=timeout)
            sock.settimeout(None)
        except BaseException as exc:
            sock.close()
            if isinstance(exc, OSError) and not isinstance(exc, OpenPduError):  # VciTimeout is an OSError too
                raise ConnectionLost(f"VCI at {host}:{port} dropped the connection: {exc}") from exc
            raise
        vci = cls(sock, greet, host)
        try:
            now = time.time()
            vci.ioctl(wire.IOCTL_SYNC_TIME, int(now), int(now % 1 * 1_000_000))
            vci.ioctl(wire.IOCTL_CONFIGURE_FIRMWARE, int(remote_logging))
        except BaseException:
            vci.close()
            raise
        log.info("connected to VCI %s, firmware %s", host, ".".join(map(str, greet.version)))
        return vci

    def close(self) -> None:
        """End the session. The VCI frees every link of a closed session itself. Idempotent."""
        with self._routes_lock:
            self._closing = True
            pong_thread = self._pong_thread
        self._wake_pong_worker()
        with contextlib.suppress(OSError):  # already down
            self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()
        if self._reader is not threading.current_thread():
            self._reader.join(timeout=2.0)
        if pong_thread is not None and pong_thread is not threading.current_thread():
            pong_thread.join(timeout=2.0)

    def __enter__(self) -> Vci:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def alive(self) -> bool:
        return self._error is None and not self._closing

    # -- links -------------------------------------------------------------------------------------------------

    def monitor(self, **blocks: Any) -> MonitorLink:
        return MonitorLink.open(self, **blocks)

    def raw_link(self, **blocks: Any) -> RawLink:
        return RawLink.open(self, **blocks)

    def isotp_link(self, tx_id: int, rx_id: int, **blocks: Any) -> IsoTpLink:
        return IsoTpLink.open(self, tx_id, rx_id, **blocks)

    # -- requests ----------------------------------------------------------------------------------------------

    def send(self, payload: bytes) -> None:
        self._check()
        try:
            with self._send_lock:
                self._sock.sendall(wire.frame(payload))
        except OSError as exc:
            raise self._fail(ConnectionLost(f"VCI connection lost while sending: {exc}")) from exc

    def request(self, payload: bytes, what: str, timeout: float = SYNC_TIMEOUT) -> wire.Ack | wire.IoctlReply:
        """Send a synchronous request and return its reply; a non-zero ack code raises Refused.

        No reply within `timeout`, or a reply that cannot be this request's, ends the session (see the module doc)."""
        with self._sync_lock:
            self.send(payload)
            reply = self.next_reply(self._sync_replies, time.monotonic() + timeout)
            if reply is None:
                raise self._abort(VciTimeout(f"VCI did not answer {what} within {timeout:g} s"))
            if not _answers(payload, reply):
                raise self._abort(ProtocolError(f"VCI answered {what} with {reply!r}"))
        if isinstance(reply, wire.Ack) and reply.code != wire.DONE:
            raise Refused(f"VCI refused {what}: code {reply.code:#06x}", reply.code)
        return reply

    def ioctl(self, code: int, in1: int = 0, in2: int = 0, link: int = wire.MODULE,
              timeout: float = SYNC_TIMEOUT) -> wire.IoctlReply:
        reply = self.request(wire.ioctl(link, code, in1, in2), f"IOCTL {code:#04x}", timeout)
        if isinstance(reply, wire.Ack):  # some IOCTLs are acknowledged without values
            return wire.IoctlReply(reply.link, code, 0, 0)
        return reply

    def next_hcop(self) -> int:
        with self._hcop_lock:
            return next(self._hcops) & 0x7FFFFFFF  # never SYNC / EVENT

    def subscribe(self, link: int, hcop: int) -> Replies:
        """Route every ack and result of (link, hcop) into the returned queue until `unsubscribe`."""
        replies: Replies = queue.Queue()
        with self._routes_lock:
            self._check()
            self._subscribers[(link, hcop)] = replies
        return replies

    def unsubscribe(self, link: int, hcop: int) -> None:
        with self._routes_lock:
            self._subscribers.pop((link, hcop), None)

    def next_reply(self, replies: Replies, deadline: float | None) -> wire.Message | None:
        """The next routed message, None once `deadline` (monotonic) passes; raises if the session ended."""
        try:
            item = replies.get(timeout=None if deadline is None else max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            return None
        if isinstance(item, OpenPduError):
            replies.put(item)  # every later wait on this queue must fail the same way
            raise item
        return item

    # -- reader ------------------------------------------------------------------------------------------------

    def _read_loop(self) -> None:
        try:
            while True:
                payload = _read_frame(self._sock)
                if not payload:
                    continue
                try:
                    msg = wire.parse(payload)
                except ProtocolError as exc:
                    log.warning("dropped a malformed VCI message (%s): %s", exc, payload.hex())
                    continue
                self._dispatch(msg)
        except OpenPduError as exc:
            self._fail(ConnectionLost("VCI session closed") if self._closing else exc)
        except OSError as exc:
            self._fail(ConnectionLost("VCI session closed" if self._closing else f"VCI connection lost: {exc}"))
        except Exception as exc:  # a bug here must not leave every waiter hanging
            log.exception("VCI reader failed")
            self._fail(ConnectionLost(f"VCI reader failed: {exc!r}"))

    def _dispatch(self, msg: wire.Message) -> None:
        if isinstance(msg, wire.Ping):
            self._enqueue_pong(msg.seq)
        elif isinstance(msg, wire.Info):
            log.info("VCI: %s", msg.text)
        elif isinstance(msg, wire.IoctlReply) or (isinstance(msg, wire.Ack) and msg.hcop == wire.SYNC):
            self._sync_replies.put(msg)
        elif isinstance(msg, (wire.Ack, wire.Result)) and (replies := self._subscribers.get((msg.link, msg.hcop))):
            replies.put(msg)
        elif isinstance(msg, wire.Ack) and msg.hcop == wire.EVENT and msg.code not in wire.PROGRESS:
            log.warning("VCI event on link %#x: code %#06x", msg.link, msg.code)
        else:
            log.debug("unrouted VCI message %r", msg)

    def _enqueue_pong(self, seq: int) -> None:
        """Queue a pong reply on a dedicated sender thread so a stalled send buffer never blocks the reader."""
        with self._routes_lock:
            if self._closing or self._error is not None:
                return
            if self._pong_thread is None:
                self._pong_thread = threading.Thread(
                    target=self._pong_loop, name=f"openpdu-{self.host}-pong", daemon=True,
                )
                self._pong_thread.start()
        try:
            self._pong_queue.put_nowait(seq)
        except queue.Full:
            with contextlib.suppress(queue.Empty):
                self._pong_queue.get_nowait()
            with contextlib.suppress(queue.Full):
                self._pong_queue.put_nowait(seq)
            log.warning("VCI pong queue full; dropped oldest pending pong")

    def _wake_pong_worker(self) -> None:
        while True:
            try:
                self._pong_queue.put_nowait(None)
                return
            except queue.Full:
                with contextlib.suppress(queue.Empty):
                    self._pong_queue.get_nowait()

    def _pong_loop(self) -> None:
        while not self._closing and self._error is None:
            seq = self._pong_queue.get()
            if seq is None:
                return
            try:
                self.send(wire.pong(seq))
            except OpenPduError:
                return

    def _fail(self, error: OpenPduError) -> OpenPduError:
        """Mark the session dead and wake every waiter with `error`. Returns the error that ended it."""
        with self._routes_lock:
            if self._error is None:
                self._error = error
                for replies in [self._sync_replies, *self._subscribers.values()]:
                    replies.put(error)
                self._wake_pong_worker()
            return self._error

    def _abort(self, error: OpenPduError) -> OpenPduError:
        """End the session with `error` and close its socket. Returns the error that ended it."""
        error = self._fail(error)
        self.close()
        return error

    def _check(self) -> None:
        if self._error is not None:
            raise self._error
        if self._closing:
            raise ConnectionLost("VCI session closed")


def _keepalive(sock: socket.socket) -> None:
    """TCP keepalive, so a VCI that vanishes (power, Wi-Fi or USB gone) errors the socket instead of hanging it."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):  # Windows, as the reference driver
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, KEEPALIVE * 1000, KEEPALIVE * 1000))
        return
    idle = getattr(socket, "TCP_KEEPIDLE", getattr(socket, "TCP_KEEPALIVE", None))  # Linux / macOS
    for option, value in ((idle, KEEPALIVE), (getattr(socket, "TCP_KEEPINTVL", None), KEEPALIVE),
                          (getattr(socket, "TCP_KEEPCNT", None), KEEPALIVE_PROBES)):
        if option is not None:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)


def _answers(request: bytes, reply: wire.Message) -> bool:
    """Whether `reply` can be the answer to `request`: an IOCTL gets its own IOCTL reply or a bare ack, a link
    request an ack, for the same link unless the request creates it."""
    kind, link = request[0], struct.unpack_from(">H", request, 1)[0]
    if kind == wire.IOCTL:
        return isinstance(reply, wire.Ack) or (isinstance(reply, wire.IoctlReply) and reply.code == request[3])
    return isinstance(reply, wire.Ack) and (kind == wire.CREATE or reply.link == link)


def _recv_exact(sock: socket.socket, n: int, *, deadline: float | None = None) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out reading from VCI")
            sock.settimeout(remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionLost("VCI closed the connection")
        buf += chunk
    return bytes(buf)


def _read_frame(sock: socket.socket, *, deadline: float | None = None) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4, deadline=deadline))
    if length > MAX_FRAME_BYTES:
        raise ProtocolError(f"VCI frame too large: {length} bytes (max {MAX_FRAME_BYTES})")
    return _recv_exact(sock, length, deadline=deadline)


def _read_greet(sock: socket.socket, timeout: float | None = None) -> wire.Greet:
    prev_timeout = sock.gettimeout()
    if timeout is None:
        timeout = GREET_TIMEOUT if prev_timeout is None else prev_timeout
    deadline = time.monotonic() + timeout
    try:
        msg = wire.parse(_read_frame(sock, deadline=deadline))
    except TimeoutError:
        raise VciTimeout("VCI sent no greet") from None
    finally:
        with contextlib.suppress(OSError):
            sock.settimeout(prev_timeout)
    if isinstance(msg, wire.GreetRefused):
        raise Refused(f"VCI refused the session: {msg.reason}")
    if not isinstance(msg, wire.Greet):
        raise ProtocolError(f"expected the VCI greet, got {msg!r}")
    return msg
