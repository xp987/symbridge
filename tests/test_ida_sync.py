"""Unit tests for the IDA adapter's pure logic (no IDA required)."""

from adapters.ida import ida_sync


def test_rva_roundtrip():
    base = 0x140000000
    ea = 0x140001500
    rva = ida_sync.rva_from_ea(ea, base)
    assert rva == 0x1500
    assert ida_sync.ea_from_rva(rva, base) == ea


def test_make_symbol_record():
    rec = ida_sync.make_symbol_record(
        "t.exe", 0x140001500, 0x140000000, "main", "ida:1", ts=1.0
    )
    assert rec == {
        "module": "t.exe",
        "rva": 0x1500,
        "name": "main",
        "origin": "ida:1",
        "ts": 1.0,
    }


def test_make_comment_record_kind():
    rec = ida_sync.make_comment_record(
        "t.exe", 0x140001000, 0x140000000, "hi", True, "ida:1", ts=2.0
    )
    assert rec["kind"] == "repeatable"
    assert rec["rva"] == 0x1000
    assert rec["text"] == "hi"


def test_make_type_record_preserves_c_declaration():
    decl = "struct Foo {\n    unsigned int a;\n    char b[8];\n};"
    rec = ida_sync.make_type_record(
        "TARGET.EXE", "Foo", decl, "ida:1", ts=3.0
    )
    assert rec == {
        "module": "target.exe",
        "name": "Foo",
        "decl": decl,
        "deleted": False,
        "origin": "ida:1",
        "ts": 3.0,
    }
    assert "rva" not in rec


def test_plan_apply_symbol():
    plan = ida_sync.plan_apply(
        "symbol", {"module": "t.exe", "rva": 0x1500, "name": "main"}, 0x140000000
    )
    assert plan == ("symbol", 0x140001500, "main")


def test_plan_apply_comment():
    plan = ida_sync.plan_apply(
        "comment",
        {"module": "t.exe", "rva": 0x1000, "text": "x", "kind": "repeatable"},
        0x140000000,
    )
    assert plan == ("comment", 0x140001000, "x", True)


def test_plan_apply_type_and_unknown():
    plan = ida_sync.plan_apply(
        "type",
        {"module": "t.exe", "name": "Foo", "decl": "struct Foo{int a;};"},
        0,
    )
    assert plan == ("type", "Foo", "struct Foo{int a;};")
    assert ida_sync.plan_apply(
        "type", {"module": "t.exe", "name": "Foo", "decl": "", "deleted": True}, 0
    ) == ("type_delete", "Foo")
    assert ida_sync.plan_apply("bogus", {}, 0) is None


def test_make_type_tombstone():
    rec = ida_sync.make_type_record(
        "T.EXE", "OldName", "", "ida:1", ts=4.0, deleted=True
    )
    assert rec["module"] == "t.exe"
    assert rec["name"] == "OldName"
    assert rec["decl"] == ""
    assert rec["deleted"] is True


def test_belongs_to():
    assert ida_sync.belongs_to({"module": "t.exe"}, "t.exe")
    assert not ida_sync.belongs_to({"module": "other.dll"}, "t.exe")


def test_glue_module_imports_without_ida():
    # The plugin file must import cleanly outside IDA (glue stays dormant).
    from adapters.ida import symbridge_ida

    assert symbridge_ida._IDA is False
