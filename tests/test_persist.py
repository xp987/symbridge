"""Tests for broker state persistence (Store.save/load + broker wiring)."""

import asyncio
import json
import os
import tempfile

from broker.model import Comment, Store, Symbol, TypeDef
from broker.symbridge_broker import Broker


def test_store_save_load_roundtrip():
    store = Store()
    store.apply(Symbol("t.exe", 0x1000, "main", origin="A", ts=1.0))
    store.apply(Comment("t.exe", 0x1000, "entry", kind="regular", origin="A", ts=1.0))
    decl = "struct Foo {\n    int a;\n    char b[8];\n};"
    store.apply(TypeDef("t.exe", "Foo", decl, origin="A", ts=2.0))

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "state.json")
        store.save(path)
        assert os.path.exists(path)

        reloaded = Store()
        n = reloaded.load(path)
        assert n == 3
        names = {getattr(r, "name", None) for r in reloaded.records()}
        assert {"main", "Foo"}.issubset(names)
        loaded_type = next(r for r in reloaded.records() if isinstance(r, TypeDef))
        assert loaded_type.decl == decl


def test_store_load_missing_file_is_noop():
    store = Store()
    assert store.load(os.path.join(tempfile.gettempdir(), "does-not-exist-xyz.json")) == 0
    assert len(store) == 0


def test_store_load_skips_malformed_entries():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "state.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                [
                    {"record": "symbol", "data": {"module": "t.exe", "rva": 1, "name": "ok", "ts": 1.0}},
                    {"record": "bogus", "data": {}},  # unknown type -> skipped
                ],
                f,
            )
        store = Store()
        assert store.load(path) == 1


def test_broker_persists_on_update():
    async def scenario():
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")

            broker = Broker(persist_path=path)
            # Simulate an applied update by driving the store + persist directly.
            broker.store.apply(Symbol("t.exe", 0x2000, "decrypt", ts=5.0))
            broker._persist()

            assert os.path.exists(path)
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert any(r["data"].get("name") == "decrypt" for r in data)

            # A fresh broker pointed at the same file loads it on construction.
            broker2 = Broker(persist_path=path)
            assert len(broker2.store) == 1

    asyncio.run(scenario())


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"running {name} ...", end=" ")
            fn()
            print("ok")
    print("all persist tests passed")
