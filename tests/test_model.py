"""Unit tests for the canonical data model (pure, no I/O)."""

from broker.model import (
    Comment,
    Store,
    Symbol,
    TypeDef,
    record_from_wire,
    record_to_wire,
)


def test_wire_roundtrip_symbol():
    sym = Symbol(module="t.exe", rva=0x1000, name="main", origin="A", ts=1.0)
    wire = record_to_wire(sym)
    assert wire["record"] == "symbol"
    assert record_from_wire(wire) == sym


def test_wire_roundtrip_comment_and_type():
    c = Comment(module="t.exe", rva=0x1000, text="hi", kind="repeatable", ts=2.0)
    decl = "struct Foo {\n    int a;\n    char b[8];\n};"
    t = TypeDef(module="t.exe", name="Foo", decl=decl, ts=3.0)
    assert record_from_wire(record_to_wire(c)) == c
    assert record_from_wire(record_to_wire(t)) == t


def test_type_store_last_write_wins_per_module_and_name():
    store = Store()
    assert store.apply(TypeDef("a.exe", "Foo", "struct Foo { int a; };", ts=1.0))
    assert store.apply(TypeDef("a.exe", "Foo", "struct Foo { int b; };", ts=2.0))
    assert not store.apply(TypeDef("a.exe", "Foo", "struct Foo { int old; };", ts=1.5))
    assert store.apply(TypeDef("b.exe", "Foo", "struct Foo { char c; };", ts=1.0))

    held = {(r.module, r.name): r.decl for r in store.records()}
    assert held == {
        ("a.exe", "Foo"): "struct Foo { int b; };",
        ("b.exe", "Foo"): "struct Foo { char c; };",
    }


def test_type_tombstone_roundtrip_and_prevents_stale_resurrection():
    store = Store()
    assert store.apply(TypeDef("a.exe", "Foo", "struct Foo {};", ts=1.0))
    deleted = TypeDef("a.exe", "Foo", "", deleted=True, origin="B", ts=2.0)
    assert record_from_wire(record_to_wire(deleted)) == deleted
    assert store.apply(deleted)
    assert not store.apply(
        TypeDef("a.exe", "Foo", "struct Foo { int stale; };", ts=1.5)
    )
    held = store.records()[0]
    assert held.deleted is True and held.decl == ""


def test_equal_timestamp_conflict_converges_independent_of_arrival_order():
    left = TypeDef("a.exe", "Foo", "struct Foo { int a; };", origin="A", ts=5.0)
    right = TypeDef("a.exe", "Foo", "struct Foo { int b; };", origin="B", ts=5.0)
    store_ab = Store()
    store_ba = Store()
    for rec in (left, right):
        store_ab.apply(rec)
    for rec in (right, left):
        store_ba.apply(rec)
    assert store_ab.snapshot_wire() == store_ba.snapshot_wire()


def test_store_accepts_new_record():
    store = Store()
    assert store.apply(Symbol("t.exe", 0x1000, "main", ts=1.0)) is True
    assert len(store) == 1


def test_store_last_write_wins():
    store = Store()
    store.apply(Symbol("t.exe", 0x1000, "old", ts=1.0))
    # Newer ts overwrites and reports change.
    assert store.apply(Symbol("t.exe", 0x1000, "new", ts=2.0)) is True
    # Older ts is rejected.
    assert store.apply(Symbol("t.exe", 0x1000, "stale", ts=0.5)) is False
    held = {s.name for s in store.records()}
    assert held == {"new"}


def test_store_duplicate_same_ts_is_noop():
    store = Store()
    rec = Symbol("t.exe", 0x1000, "main", origin="A", ts=1.0)
    assert store.apply(rec) is True
    # Exact duplicate at same ts should not re-broadcast.
    assert store.apply(Symbol("t.exe", 0x1000, "main", origin="A", ts=1.0)) is False


def test_comment_kinds_are_distinct_keys():
    store = Store()
    store.apply(Comment("t.exe", 0x1000, "reg", kind="regular", ts=1.0))
    store.apply(Comment("t.exe", 0x1000, "rep", kind="repeatable", ts=1.0))
    # Regular and repeatable comments coexist at the same address.
    assert len(store) == 2
