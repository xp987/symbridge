"""End-to-end test for the reusable BrokerClient over a real socket.

Runs the asyncio broker in a background thread and drives it with two blocking
BrokerClients (the same class the IDA adapter uses), proving the transport,
hello/snapshot, update send, and origin-exclusion all work together.
"""

import asyncio
import threading
import time

from adapters.common.client import BrokerClient
from broker.symbridge_broker import Broker


class _BrokerThread:
    def __init__(self):
        self.port = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        assert self._ready.wait(5), "broker did not start"
        return self.port

    def stop(self):
        self._stop.set()
        self._thread.join(2.0)

    def _run(self):
        async def main():
            broker = Broker()
            server = await asyncio.start_server(broker.handle_connection, "127.0.0.1", 0)
            self.port = server.sockets[0].getsockname()[1]
            self._ready.set()
            async with server:
                while not self._stop.is_set():
                    await asyncio.sleep(0.05)

        asyncio.run(main())


def test_client_update_roundtrip_and_origin_exclusion():
    bt = _BrokerThread()
    port = bt.start()

    a_msgs, b_msgs = [], []
    b_got_update = threading.Event()

    a = BrokerClient("127.0.0.1", port, "A", "test", a_msgs.append)
    b = BrokerClient(
        "127.0.0.1",
        port,
        "B",
        "test",
        lambda m: (b_msgs.append(m), b_got_update.set() if m.get("type") == "update" else None),
    )
    try:
        a.connect()
        b.connect()
        time.sleep(0.3)  # let both hellos + snapshots settle

        a.send_update(
            "symbol",
            {"module": "t.exe", "rva": 0x1000, "name": "main", "ts": 1.0},
            origin="A",
        )

        assert b_got_update.wait(2.0), "B never received the update"
        updates_b = [m for m in b_msgs if m.get("type") == "update"]
        assert updates_b and updates_b[0]["data"]["name"] == "main"

        # Origin A must not receive its own update echoed back.
        time.sleep(0.3)
        updates_a = [m for m in a_msgs if m.get("type") == "update"]
        assert not updates_a, f"origin A got its own update back: {updates_a}"
    finally:
        a.close()
        b.close()
        bt.stop()


def test_client_type_update_preserves_large_multiline_decl():
    bt = _BrokerThread()
    port = bt.start()

    a_msgs, b_msgs = [], []
    a_snapshot = threading.Event()
    a_ack = threading.Event()
    b_snapshot = threading.Event()
    b_update = threading.Event()

    def on_a(msg):
        a_msgs.append(msg)
        if msg.get("type") == "snapshot":
            a_snapshot.set()
        elif msg.get("type") == "ack":
            a_ack.set()

    def on_b(msg):
        b_msgs.append(msg)
        if msg.get("type") == "snapshot":
            b_snapshot.set()
        elif msg.get("type") == "update":
            b_update.set()

    a = BrokerClient("127.0.0.1", port, "IDA", "ida", on_a)
    b = BrokerClient("127.0.0.1", port, "X64DBG", "x64dbg", on_b)
    try:
        a.connect()
        b.connect()
        assert a_snapshot.wait(2.0)
        assert b_snapshot.wait(2.0)

        decl = (
            "struct BigFoo {\n"
            "    unsigned int a;\n"
            "    char b[8];\n"
            "};\n/* " + ("padding " * 800) + "*/"
        )
        data = {
            "module": "target.exe",
            "name": "BigFoo",
            "decl": decl,
            "origin": "IDA",
            "ts": 30.0,
        }
        a.send_update("type", data, origin="IDA")

        assert a_ack.wait(2.0), "IDA never received the type ack"
        assert b_update.wait(2.0), "x64dbg peer never received the type update"
        updates = [m for m in b_msgs if m.get("type") == "update"]
        assert len(updates) == 1
        assert updates[0]["record"] == "type"
        assert updates[0]["data"] == data
        assert len(decl.encode("utf-8")) > 4096

        time.sleep(0.2)
        assert not [m for m in a_msgs if m.get("type") == "update"]
    finally:
        a.close()
        b.close()
        bt.stop()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"running {name} ...", end=" ")
            fn()
            print("ok")
    print("all client tests passed")
