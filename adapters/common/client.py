"""Reusable broker client for Python adapters (IDA, Ghidra, Binary Ninja, ...).

Blocking-socket + background reader thread, using only the stdlib so it runs
inside IDA's embedded CPython without installing anything. The transport speaks
the newline-delimited JSON protocol in ``shared/schema.json``.

Threading model: incoming messages are delivered on the reader thread via the
``on_message`` callback. GUI-bound adapters (IDA) must marshal any tool-API work
onto their main thread themselves (e.g. ``ida_kernwin.execute_sync``); this
client stays framework-agnostic.
"""

from __future__ import annotations

import itertools
import json
import socket
import threading
from typing import Callable, Dict, Optional

OnMessage = Callable[[Dict], None]


class BrokerClient:
    def __init__(
        self,
        host: str,
        port: int,
        client_id: str,
        tool: str,
        on_message: OnMessage,
        on_disconnect: Optional[Callable[[], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.client_id = client_id
        self.tool = tool
        self.on_message = on_message
        self.on_disconnect = on_disconnect

        self._sock: Optional[socket.socket] = None
        self._reader: Optional[threading.Thread] = None
        self._send_lock = threading.Lock()
        self._seq = itertools.count(1)
        self._running = False

    # -- lifecycle ------------------------------------------------------------

    def connect(self, timeout: float = 5.0) -> None:
        """Open the socket, announce ourselves, and start the reader thread."""
        self._sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self._sock.settimeout(None)  # blocking reads in the reader thread
        self._running = True
        self.send({"type": "hello", "client_id": self.client_id, "tool": self.tool})
        self._reader = threading.Thread(
            target=self._read_loop, name=f"symbridge-{self.client_id}", daemon=True
        )
        self._reader.start()

    def close(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def connected(self) -> bool:
        return self._running and self._sock is not None

    # -- sending --------------------------------------------------------------

    def send(self, msg: Dict) -> None:
        if self._sock is None:
            raise ConnectionError("not connected")
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        with self._send_lock:
            self._sock.sendall(data)

    def send_update(self, record: str, data: Dict, origin: Optional[str] = None) -> None:
        """Send a single changed record (symbol/comment/type) to the broker."""
        self.send(
            {
                "type": "update",
                "origin": origin or self.client_id,
                "seq": next(self._seq),
                "record": record,
                "data": data,
            }
        )

    # -- receiving ------------------------------------------------------------

    def _read_loop(self) -> None:
        assert self._sock is not None
        try:
            with self._sock.makefile("rb") as f:
                for raw in f:
                    if not self._running:
                        break
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    try:
                        self.on_message(msg)
                    except Exception:  # noqa: BLE001 - never let a handler kill the reader
                        pass
        except OSError:
            pass  # socket closed under us
        finally:
            self._running = False
            if self.on_disconnect is not None:
                try:
                    self.on_disconnect()
                except Exception:  # noqa: BLE001
                    pass
