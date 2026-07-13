"""symbridge IDA adapter (IDAPython plugin).

Install: copy the ``symbridge`` repo somewhere, then either
  * drop this file (with the repo on disk beside it) into IDA's ``plugins/`` dir, or
  * run it as a script from IDA (File > Script file...).
Then run the "symbridge" plugin (Ctrl-Alt-S) to connect/disconnect.

Config via env vars: ``SYMBRIDGE_HOST`` (default 127.0.0.1), ``SYMBRIDGE_PORT`` (9100).

Design: local renames/comments are captured with ``IDB_Hooks`` and pushed to the
broker; remote updates are applied on IDA's main thread via ``execute_sync`` with
an ``applying_remote`` guard so applying a remote change never re-broadcasts it.
All address math and record shaping lives in :mod:`ida_sync` (unit tested).
"""

from __future__ import annotations

import os
import sys
import time

# Make the repo packages importable when this file is dropped into IDA's plugins dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from adapters.common.client import BrokerClient  # noqa: E402
from adapters.ida import ida_sync  # noqa: E402

try:
    import idaapi
    import idc
    import ida_idp
    import ida_nalt
    import ida_bytes
    import ida_kernwin
    import ida_typeinf

    _IDA = True
except ImportError:  # imported outside IDA (e.g. for tests) -- glue stays dormant
    _IDA = False


if _IDA:

    class _IDBHooks(ida_idp.IDB_Hooks):
        """Forwards local IDB edits to the adapter.

        Hook signatures gained extra trailing args across IDA versions (8.x vs
        9.x), so we accept ``*args`` and read positionally -- the same file then
        works on both without a signature-mismatch crash.
        """

        def __init__(self, adapter: "SymbridgeIDA") -> None:
            super().__init__()
            self._adapter = adapter

        def renamed(self, *args):
            ea, new_name = args[0], args[1]
            self._adapter.on_local_rename(ea, new_name or "")
            return 0

        def cmt_changed(self, *args):
            ea, repeatable = args[0], bool(args[1])
            text = ida_bytes.get_cmt(ea, repeatable) or ""
            self._adapter.on_local_comment(ea, text, repeatable)
            return 0

        def local_types_changed(self, ltc, ordinal, name):
            # IDA 9.x: (local_type_change_t ltc, uint32 ordinal,
            # const char *name). Unlike rename/comment callbacks, IDA 9.4's
            # SWIG director does not marshal this event into a ``*args``
            # override; the exact signature is required or args arrives empty.
            self._adapter.on_local_type(ltc, int(ordinal), name or "")
            return 0

    class SymbridgeIDA:
        """Owns the broker client + IDB hooks and bridges the two directions."""

        def __init__(self, host: str, port: int) -> None:
            self.module = ida_nalt.get_root_filename()
            self.imagebase = ida_nalt.get_imagebase()
            self.origin = f"ida:{os.getpid()}"
            self.applying_remote = False
            self._local_type_names_by_ordinal = {}
            self._hooks = _IDBHooks(self)
            self._client = BrokerClient(
                host, port, self.origin, ida_sync.TOOL, self._on_broker_message
            )

        # -- lifecycle --------------------------------------------------------

        def start(self) -> None:
            self._client.connect()
            self._remember_local_type_names()
            self._hooks.hook()
            ida_kernwin.msg(
                f"[symbridge] connected as {self.origin} (module={self.module})\n"
            )

        def stop(self) -> None:
            try:
                self._hooks.unhook()
            finally:
                self._client.close()
            ida_kernwin.msg("[symbridge] disconnected\n")

        # -- local IDA -> broker ---------------------------------------------

        def _remember_local_type_names(self) -> None:
            """Seed ordinal/name state so the first rename can tombstone old name."""
            qty = ida_typeinf.get_ordinal_limit(ida_typeinf.get_idati())
            for ordinal in range(1, qty):
                name = ida_typeinf.idc_get_local_type_name(ordinal) or ""
                if name:
                    self._local_type_names_by_ordinal[ordinal] = name

        def on_local_rename(self, ea: int, new_name: str) -> None:
            if self.applying_remote:
                return
            # `renamed` also fires for struct/enum members etc.; only sync real
            # addresses that live in the image.
            if not ida_bytes.is_mapped(ea):
                return
            rec = ida_sync.make_symbol_record(
                self.module, ea, self.imagebase, new_name, self.origin
            )
            self._client.send_update("symbol", rec, origin=self.origin)

        def on_local_comment(self, ea: int, text: str, repeatable: bool) -> None:
            if self.applying_remote:
                return
            rec = ida_sync.make_comment_record(
                self.module, ea, self.imagebase, text, repeatable, self.origin
            )
            self._client.send_update("comment", rec, origin=self.origin)

        def on_local_type(self, change_kind: int, ordinal: int, name: str) -> None:
            """Export a changed IDA local type as canonical C text.

            M5 represents delete/rename with persistent tombstones. IDA reports
            a rename as an edited ordinal, so the ordinal/name cache identifies
            the old key and emits old-name deletion plus new-name definition at
            one timestamp.
            """
            if self.applying_remote:
                return
            if change_kind == ida_idp.LTC_DELETED:
                known_name = self._local_type_names_by_ordinal.pop(ordinal, "")
                deleted_name = name or known_name
                if deleted_name:
                    rec = ida_sync.make_type_record(
                        self.module,
                        deleted_name,
                        "",
                        self.origin,
                        deleted=True,
                    )
                    self._client.send_update("type", rec, origin=self.origin)
                return
            exportable = {
                ida_idp.LTC_ADDED,
                ida_idp.LTC_EDITED,
                ida_idp.LTC_ALIASED,
            }
            if change_kind not in exportable:
                return

            if ordinal <= 0 and name:
                ordinal = ida_typeinf.get_type_ordinal(
                    ida_typeinf.get_idati(), name
                )
            if ordinal <= 0:
                return

            # PRTYPE_DEF is essential for named UDTs: without it IDA may emit
            # only ``struct Foo;`` instead of the member-bearing definition.
            flags = (
                ida_typeinf.PRTYPE_MULTI
                | ida_typeinf.PRTYPE_TYPE
                | ida_typeinf.PRTYPE_SEMI
                | ida_typeinf.PRTYPE_DEF
            )
            decl = ida_typeinf.idc_get_local_type(ordinal, flags) or ""
            type_name = ida_typeinf.idc_get_local_type_name(ordinal) or name
            if not type_name or not decl:
                ida_kernwin.msg(
                    f"[symbridge] cannot export local type ordinal {ordinal}\n"
                )
                return

            changed_at = time.time()
            old_name = self._local_type_names_by_ordinal.get(ordinal, "")
            if old_name and old_name != type_name:
                tombstone = ida_sync.make_type_record(
                    self.module,
                    old_name,
                    "",
                    self.origin,
                    ts=changed_at,
                    deleted=True,
                )
                self._client.send_update("type", tombstone, origin=self.origin)

            self._local_type_names_by_ordinal[ordinal] = type_name
            rec = ida_sync.make_type_record(
                self.module, type_name, decl, self.origin, ts=changed_at
            )
            self._client.send_update("type", rec, origin=self.origin)

        # -- broker -> local IDA (reader thread; marshal to main thread) ------

        def _on_broker_message(self, msg: dict) -> None:
            mtype = msg.get("type")
            if mtype == "snapshot":
                for wire in msg.get("records", []):
                    self._apply_wire(wire)
            elif mtype == "update":
                self._apply_wire(msg)

        def _apply_wire(self, wire: dict) -> None:
            record = wire.get("record")
            data = wire.get("data", {})
            if not ida_sync.belongs_to(data, self.module):
                return
            plan = ida_sync.plan_apply(record, data, self.imagebase)
            if plan is None:
                return
            # IDA APIs must run on the main thread.
            ida_kernwin.execute_sync(
                lambda: self._apply_plan(plan), ida_kernwin.MFF_WRITE
            )

        def _apply_plan(self, plan) -> int:
            self.applying_remote = True
            try:
                kind = plan[0]
                if kind == "symbol":
                    _, ea, name = plan
                    idc.set_name(ea, name, idc.SN_NOWARN)
                elif kind == "comment":
                    _, ea, text, repeatable = plan
                    ida_bytes.set_cmt(ea, text, repeatable)
                elif kind == "type":
                    _, name, decl = plan
                    # Parse into a real tinfo_t and replace by canonical name.
                    # The legacy idc_set_local_type wrapper can create a slot,
                    # but IDA 9.4 may reject replacement of an existing UDT.
                    tif = ida_typeinf.tinfo_t(decl)
                    result = tif.set_named_type(
                        None, name, ida_typeinf.NTF_REPLACE
                    )
                    if result != ida_typeinf.TERR_OK:
                        ida_kernwin.msg(
                            f"[symbridge] failed to apply remote type {name!r}: "
                            f"{ida_typeinf.tinfo_errstr(result)}\n"
                        )
                    else:
                        ordinal = ida_typeinf.get_type_ordinal(
                            ida_typeinf.get_idati(), name
                        )
                        if ordinal > 0:
                            self._local_type_names_by_ordinal[ordinal] = name
                elif kind == "type_delete":
                    _, name = plan
                    if not ida_typeinf.del_named_type(
                        None, name, ida_typeinf.NTF_TYPE
                    ):
                        # Deleting an already-absent type is idempotent.
                        ordinal = ida_typeinf.get_type_ordinal(
                            ida_typeinf.get_idati(), name
                        )
                        if ordinal > 0:
                            ida_kernwin.msg(
                                f"[symbridge] failed to delete remote type {name!r}\n"
                            )
                    for ordinal, known_name in list(
                        self._local_type_names_by_ordinal.items()
                    ):
                        if known_name == name:
                            del self._local_type_names_by_ordinal[ordinal]
            finally:
                self.applying_remote = False
            return 0

    class SymbridgePlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_KEEP
        comment = "Live name/comment/type sync with x64dbg via the symbridge broker"
        help = comment
        wanted_name = "symbridge"
        wanted_hotkey = "Ctrl-Alt-S"

        def init(self):
            self.adapter = None
            return idaapi.PLUGIN_KEEP

        def run(self, arg):
            if self.adapter is None:
                host = os.environ.get("SYMBRIDGE_HOST", "127.0.0.1")
                port = int(os.environ.get("SYMBRIDGE_PORT", "9100"))
                try:
                    self.adapter = SymbridgeIDA(host, port)
                    self.adapter.start()
                except OSError as exc:
                    ida_kernwin.warning(f"symbridge: cannot reach broker: {exc}")
                    self.adapter = None
            else:
                self.adapter.stop()
                self.adapter = None

        def term(self):
            if self.adapter is not None:
                self.adapter.stop()
                self.adapter = None

    def PLUGIN_ENTRY():  # noqa: N802 - IDA entry point name
        return SymbridgePlugin()

    # Convenience: when run via IDA's "File > Script file...", this block runs
    # (as __main__) and toggles the adapter on/off. Run the file once to start,
    # again to stop. (When imported as a package module -- e.g. tests -- it is
    # skipped.) Global name is kept in IDA's persistent script namespace.
    if __name__ == "__main__":
        _g = globals()
        if _g.get("SYMBRIDGE") is not None:
            _g["SYMBRIDGE"].stop()
            _g["SYMBRIDGE"] = None
        else:
            _host = os.environ.get("SYMBRIDGE_HOST", "127.0.0.1")
            _port = int(os.environ.get("SYMBRIDGE_PORT", "9100"))
            try:
                _g["SYMBRIDGE"] = SymbridgeIDA(_host, _port)
                _g["SYMBRIDGE"].start()
                ida_kernwin.msg(
                    "[symbridge] adapter started (run this script again to stop)\n"
                )
            except OSError as _exc:
                _g["SYMBRIDGE"] = None
                ida_kernwin.warning(f"symbridge: cannot reach broker: {_exc}")
