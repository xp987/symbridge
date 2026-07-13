"""Integration tests for the broker: real TCP, two fake clients.

Each test spins the broker up on an ephemeral port and drives it with plain
asyncio socket clients, so it exercises the exact newline-JSON framing that the
IDA/x64dbg adapters will use.
"""

import asyncio
import json

from broker.symbridge_broker import Broker


async def _send(writer, msg):
    writer.write((json.dumps(msg) + "\n").encode("utf-8"))
    await writer.drain()


async def _recv(reader, timeout=1.0):
    line = await asyncio.wait_for(reader.readline(), timeout)
    if not line:
        raise EOFError("connection closed")
    return json.loads(line)


async def _start_broker():
    broker = Broker()
    server = await asyncio.start_server(broker.handle_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return broker, server, port


async def _hello(port, client_id):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await _send(writer, {"type": "hello", "client_id": client_id, "tool": "test"})
    snap = await _recv(reader)
    assert snap["type"] == "snapshot"
    return reader, writer, snap


async def _scenario_broadcast_excludes_origin():
    _, server, port = await _start_broker()
    async with server:
        ra, wa, _ = await _hello(port, "A")
        rb, wb, _ = await _hello(port, "B")

        update = {
            "type": "update",
            "origin": "A",
            "seq": 1,
            "record": "symbol",
            "data": {"module": "t.exe", "rva": 0x1000, "name": "main", "ts": 1.0},
        }
        await _send(wa, update)

        # Origin A receives an ack, never the echoed update.
        ack = await _recv(ra)
        assert ack["type"] == "ack" and ack["seq"] == 1

        # Peer B receives the update.
        got = await _recv(rb)
        assert got["type"] == "update"
        assert got["data"]["name"] == "main"

        # A must not receive the update back (origin exclusion).
        try:
            leaked = await _recv(ra, timeout=0.25)
            raise AssertionError(f"origin A unexpectedly got: {leaked}")
        except asyncio.TimeoutError:
            pass

        for w in (wa, wb):
            w.close()


async def _scenario_snapshot_to_late_joiner():
    broker, server, port = await _start_broker()
    async with server:
        ra, wa, _ = await _hello(port, "A")
        await _send(
            wa,
            {
                "type": "update",
                "origin": "A",
                "record": "comment",
                "data": {
                    "module": "t.exe",
                    "rva": 0x2000,
                    "text": "entry point",
                    "kind": "regular",
                    "ts": 5.0,
                },
            },
        )
        await _recv(ra)  # ack

        # Late joiner C should receive the already-known comment in its snapshot.
        rc, wc, snap = await _hello(port, "C")
        assert len(snap["records"]) == 1
        rec = snap["records"][0]
        assert rec["record"] == "comment"
        assert rec["data"]["text"] == "entry point"

        wa.close()
        wc.close()


async def _scenario_stale_update_not_rebroadcast():
    _, server, port = await _start_broker()
    async with server:
        ra, wa, _ = await _hello(port, "A")
        rb, wb, _ = await _hello(port, "B")

        newer = {
            "type": "update",
            "origin": "A",
            "record": "symbol",
            "data": {"module": "t.exe", "rva": 0x1000, "name": "new", "ts": 10.0},
        }
        await _send(wa, newer)
        await _recv(ra)  # ack
        await _recv(rb)  # B gets the update

        stale = {
            "type": "update",
            "origin": "A",
            "record": "symbol",
            "data": {"module": "t.exe", "rva": 0x1000, "name": "old", "ts": 1.0},
        }
        await _send(wa, stale)
        await _recv(ra)  # ack still sent

        # B must NOT receive the stale update.
        try:
            leaked = await _recv(rb, timeout=0.25)
            raise AssertionError(f"stale update leaked to B: {leaked}")
        except asyncio.TimeoutError:
            pass

        wa.close()
        wb.close()


async def _scenario_type_broadcast_and_late_snapshot():
    _, server, port = await _start_broker()
    async with server:
        ra, wa, _ = await _hello(port, "IDA")
        rb, wb, _ = await _hello(port, "X64DBG")
        decl = "struct Foo {\n    unsigned int a;\n    char b[8];\n};"
        data = {
            "module": "t.exe",
            "name": "Foo",
            "decl": decl,
            "origin": "IDA",
            "ts": 20.0,
        }
        await _send(
            wa,
            {
                "type": "update",
                "origin": "IDA",
                "seq": 7,
                "record": "type",
                "data": data,
            },
        )

        ack = await _recv(ra)
        assert ack == {"type": "ack", "seq": 7}
        live = await _recv(rb)
        assert live["record"] == "type"
        assert live["data"] == data

        rc, wc, snapshot = await _hello(port, "LATE")
        snapshot_data = dict(data, deleted=False)
        assert snapshot["records"] == [{"record": "type", "data": snapshot_data}]

        try:
            leaked = await _recv(ra, timeout=0.25)
            raise AssertionError(f"origin IDA unexpectedly got: {leaked}")
        except asyncio.TimeoutError:
            pass

        for w in (wa, wb, wc):
            w.close()


async def _scenario_type_tombstone_is_broadcast_and_persisted_in_snapshot():
    _, server, port = await _start_broker()
    async with server:
        ra, wa, _ = await _hello(port, "IDA")
        rb, wb, _ = await _hello(port, "X64DBG")
        tombstone = {
            "module": "t.exe",
            "name": "OldFoo",
            "decl": "",
            "deleted": True,
            "origin": "X64DBG",
            "ts": 30.0,
        }
        await _send(
            wb,
            {
                "type": "update",
                "origin": "X64DBG",
                "record": "type",
                "data": tombstone,
            },
        )
        await _recv(rb)  # ack
        assert (await _recv(ra))["data"] == tombstone

        _, wc, snapshot = await _hello(port, "LATE")
        assert snapshot["records"] == [{"record": "type", "data": tombstone}]
        for w in (wa, wb, wc):
            w.close()


def test_broadcast_excludes_origin():
    asyncio.run(_scenario_broadcast_excludes_origin())


def test_snapshot_to_late_joiner():
    asyncio.run(_scenario_snapshot_to_late_joiner())


def test_stale_update_not_rebroadcast():
    asyncio.run(_scenario_stale_update_not_rebroadcast())


def test_type_broadcast_and_late_snapshot():
    asyncio.run(_scenario_type_broadcast_and_late_snapshot())


def test_type_tombstone_is_broadcast_and_persisted_in_snapshot():
    asyncio.run(_scenario_type_tombstone_is_broadcast_and_persisted_in_snapshot())


if __name__ == "__main__":
    # Allow running without pytest: python -m tests.test_broker
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"running {name} ...", end=" ")
            fn()
            print("ok")
    print("all broker tests passed")
