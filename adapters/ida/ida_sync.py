"""Pure, IDA-free sync logic for the IDA adapter.

Everything address- and record-shaped lives here so it can be unit tested
without IDA installed. The IDA glue in ``symbridge_ida.py`` only does two things
this module can't: subscribe to IDB hooks and call the IDA name/comment APIs.

Address model: on the wire we only ever carry an RVA (``ea - imagebase``). IDA
gives us absolute effective addresses (``ea``); convert at the boundary.
"""

from __future__ import annotations

import time
from typing import Dict, Optional, Tuple

TOOL = "ida"

COMMENT_REGULAR = "regular"
COMMENT_REPEATABLE = "repeatable"


def norm_module(module: str) -> str:
    """Normalize a module name for cross-tool keying.

    IDA (``get_root_filename``) and x64dbg (``LabelInfo.mod``) can differ in
    case; lowercasing on both sides guarantees the ``(module, rva)`` key lines
    up so sync doesn't silently no-op. Kept as a single shared rule.
    """
    return module.lower()


# -- address conversion -------------------------------------------------------

def rva_from_ea(ea: int, imagebase: int) -> int:
    return ea - imagebase


def ea_from_rva(rva: int, imagebase: int) -> int:
    return imagebase + rva


# -- building outbound records (local change -> wire ``data`` payload) --------

def make_symbol_record(
    module: str, ea: int, imagebase: int, name: str, origin: str, ts: Optional[float] = None
) -> Dict:
    return {
        "module": norm_module(module),
        "rva": rva_from_ea(ea, imagebase),
        "name": name,
        "origin": origin,
        "ts": time.time() if ts is None else ts,
    }


def make_comment_record(
    module: str,
    ea: int,
    imagebase: int,
    text: str,
    repeatable: bool,
    origin: str,
    ts: Optional[float] = None,
) -> Dict:
    return {
        "module": norm_module(module),
        "rva": rva_from_ea(ea, imagebase),
        "text": text,
        "kind": COMMENT_REPEATABLE if repeatable else COMMENT_REGULAR,
        "origin": origin,
        "ts": time.time() if ts is None else ts,
    }


def make_type_record(
    module: str,
    name: str,
    decl: str,
    origin: str,
    ts: Optional[float] = None,
    deleted: bool = False,
) -> Dict:
    """Build a canonical local-type payload.

    Types are scoped by module and name rather than by address, so unlike
    symbol/comment records this payload intentionally contains no ``rva``.
    ``decl`` is kept verbatim: newlines, packing pragmas, and array syntax are
    meaningful input to the receiving tool's C declaration parser.
    """
    return {
        "module": norm_module(module),
        "name": name,
        "decl": decl,
        "deleted": deleted,
        "origin": origin,
        "ts": time.time() if ts is None else ts,
    }


# -- planning inbound changes (wire record -> concrete local action) ----------

def belongs_to(data: Dict, module: str) -> bool:
    """Whether an incoming record targets the module this adapter has open."""
    return norm_module(data.get("module", "")) == norm_module(module)


def plan_apply(record: str, data: Dict, imagebase: int) -> Optional[Tuple]:
    """Translate an incoming wire record into a concrete local action tuple.

    Returns one of:
      ``("symbol", ea, name)``
      ``("comment", ea, text, repeatable_bool)``
      ``("type", name, decl)``
    or ``None`` if the record type is unknown.
    """
    if record == "symbol":
        return ("symbol", ea_from_rva(data["rva"], imagebase), data["name"])
    if record == "comment":
        repeatable = data.get("kind") == COMMENT_REPEATABLE
        return ("comment", ea_from_rva(data["rva"], imagebase), data["text"], repeatable)
    if record == "type":
        if data.get("deleted", False):
            return ("type_delete", data["name"])
        return ("type", data["name"], data["decl"])
    return None
