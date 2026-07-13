"""symbridge broker.

A standalone localhost hub that holds canonical annotation state and relays
changes between tool adapters (IDA, x64dbg, ...). Transport is newline-delimited
JSON over TCP -- zero third-party dependencies, so IDA's embedded Python and a
C++ socket client can both speak it without installing anything.

Message types (see shared/schema.json):

  hello    client -> broker : announce identity; broker replies with a snapshot
  snapshot broker -> client : full current state as a list of records
  update   both ways        : a single changed record (symbol/comment/type)
  ack      broker -> client : optional receipt for an update

Echo/loop prevention: an ``update`` carries an ``origin`` client id. The broker
never sends an update back to the connection it came from. Adapters additionally
guard with an ``applying_remote`` flag on their side.

Run:  python -m broker.symbridge_broker --host 127.0.0.1 --port 9100
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Dict, Optional

from .model import Store, record_from_wire

log = logging.getLogger("symbridge.broker")


class _Client:
    """Per-connection state held by the broker."""

    __slots__ = ("writer", "client_id", "tool", "peer")

    def __init__(self, writer: asyncio.StreamWriter, peer: str) -> None:
        self.writer = writer
        self.peer = peer
        self.client_id: str = peer  # replaced by the id sent in `hello`
        self.tool: str = "unknown"


class Broker:
    """Owns the canonical :class:`Store` and the set of connected clients."""

    def __init__(self, persist_path: Optional[str] = None) -> None:
        self.store = Store()
        self.persist_path = persist_path
        self._clients: Dict[asyncio.StreamWriter, _Client] = {}
        if persist_path:
            loaded = self.store.load(persist_path)
            if loaded:
                log.info("loaded %d record(s) from %s", loaded, persist_path)

    # -- connection lifecycle -------------------------------------------------

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        peer = f"{peername[0]}:{peername[1]}" if peername else "?"
        client = _Client(writer, peer)
        self._clients[writer] = client
        log.info("client connected: %s", peer)
        try:
            while True:
                line = await reader.readline()
                if not line:  # EOF
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("bad JSON from %s: %r", peer, line[:120])
                    continue
                await self._dispatch(client, msg)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._clients.pop(writer, None)
            log.info("client disconnected: %s (%s)", client.client_id, peer)
            try:
                writer.close()
            except Exception:  # noqa: BLE001 - best-effort close
                pass

    # -- message dispatch -----------------------------------------------------

    async def _dispatch(self, client: _Client, msg: Dict) -> None:
        mtype = msg.get("type")
        if mtype == "hello":
            await self._on_hello(client, msg)
        elif mtype == "update":
            await self._on_update(client, msg)
        else:
            log.warning("ignoring message of unknown type %r from %s", mtype, client.peer)

    async def _on_hello(self, client: _Client, msg: Dict) -> None:
        client.client_id = str(msg.get("client_id") or client.peer)
        client.tool = str(msg.get("tool") or "unknown")
        log.info("hello from %s (tool=%s)", client.client_id, client.tool)
        # Send the full current state so a late joiner catches up.
        await self._send(
            client.writer,
            {"type": "snapshot", "records": self.store.snapshot_wire()},
        )

    async def _on_update(self, client: _Client, msg: Dict) -> None:
        origin = str(msg.get("origin") or client.client_id)
        try:
            rec = record_from_wire(msg)
        except (ValueError, TypeError) as exc:
            log.warning("dropping bad update from %s: %s", client.client_id, exc)
            return
        if not rec.origin:
            rec.origin = origin
        changed = self.store.apply(rec)
        # Always ack so the sender knows the message was processed.
        await self._send(client.writer, {"type": "ack", "seq": msg.get("seq")})
        if not changed:
            return  # stale/duplicate: nothing to propagate
        self._persist()
        await self._broadcast(msg, exclude_origin=origin)

    def _persist(self) -> None:
        if not self.persist_path:
            return
        try:
            self.store.save(self.persist_path)
        except OSError as exc:
            log.warning("could not persist state: %s", exc)

    # -- outbound helpers -----------------------------------------------------

    async def _broadcast(self, msg: Dict, exclude_origin: Optional[str]) -> None:
        """Relay ``msg`` to every client except the one that originated it."""
        for writer, client in list(self._clients.items()):
            if client.client_id == exclude_origin:
                continue
            await self._send(writer, msg)

    async def _send(self, writer: asyncio.StreamWriter, msg: Dict) -> None:
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionError, RuntimeError):
            # Peer went away mid-write; connection cleanup handles removal.
            pass


async def serve(
    host: str = "127.0.0.1", port: int = 9100, persist_path: Optional[str] = None
) -> None:
    broker = Broker(persist_path=persist_path)
    server = await asyncio.start_server(broker.handle_connection, host, port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("symbridge broker listening on %s", addrs)
    async with server:
        await server.serve_forever()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="symbridge annotation broker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument(
        "--persist",
        metavar="FILE",
        help="JSON file to load state from on start and save to on every change",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="debug-level logging"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(serve(args.host, args.port, args.persist))
    except KeyboardInterrupt:
        log.info("shutting down")


if __name__ == "__main__":
    main()
