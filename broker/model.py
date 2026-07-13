"""Canonical data model for symbridge.

Everything is keyed by ``(module, rva)`` so annotations line up across tools
regardless of the runtime image base (ASLR). This module knows nothing about
transport or asyncio -- it is pure data + last-write-wins merge logic, which
makes it trivial to unit test.

Wire representation of a single annotation is a ``record``: a dict with a
``"record"`` discriminator (``"symbol" | "comment" | "type"``) and a ``"data"``
payload. See ``shared/schema.json`` for the full protocol.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Tuple

# Record type discriminators used on the wire.
SYMBOL = "symbol"
COMMENT = "comment"
TYPE = "type"

# Comment kinds (IDA distinguishes these; x64dbg has a single comment slot and
# maps both onto it).
COMMENT_REGULAR = "regular"
COMMENT_REPEATABLE = "repeatable"


@dataclass
class Symbol:
    """A name applied to an address (function / data label)."""

    module: str
    rva: int
    name: str
    origin: str = ""
    ts: float = 0.0

    def key(self) -> Tuple:
        return (SYMBOL, self.module, self.rva)


@dataclass
class Comment:
    """A comment at an address. ``kind`` is regular or repeatable."""

    module: str
    rva: int
    text: str
    kind: str = COMMENT_REGULAR
    origin: str = ""
    ts: float = 0.0

    def key(self) -> Tuple:
        return (COMMENT, self.module, self.rva, self.kind)


@dataclass
class TypeDef:
    """A struct/type definition, carried as canonical C-declaration text."""

    module: str
    name: str
    decl: str
    origin: str = ""
    ts: float = 0.0
    deleted: bool = False

    def key(self) -> Tuple:
        return (TYPE, self.module, self.name)


_RECORD_CLASSES = {SYMBOL: Symbol, COMMENT: Comment, TYPE: TypeDef}


def record_to_wire(rec) -> Dict:
    """Serialize a dataclass record to its ``{"record", "data"}`` wire form."""
    for disc, cls in _RECORD_CLASSES.items():
        if isinstance(rec, cls):
            return {"record": disc, "data": asdict(rec)}
    raise TypeError(f"not a symbridge record: {type(rec)!r}")


def record_from_wire(wire: Dict):
    """Parse a ``{"record", "data"}`` wire dict back into a dataclass record."""
    disc = wire.get("record")
    cls = _RECORD_CLASSES.get(disc)
    if cls is None:
        raise ValueError(f"unknown record type: {disc!r}")
    data = wire.get("data", {})
    return cls(**data)


class Store:
    """In-memory canonical state with last-write-wins merge.

    Keyed by each record's ``key()``. An incoming record is accepted only if it
    is at least as new as what we already hold (``ts`` comparison), so replays
    and out-of-order deliveries are safe/idempotent.
    """

    def __init__(self) -> None:
        self._records: Dict[Tuple, object] = {}

    def apply(self, rec) -> bool:
        """Merge ``rec`` into the store.

        Returns ``True`` if the store changed (record was new or newer than the
        held one) and therefore should be broadcast; ``False`` if it was stale
        or an exact duplicate.
        """
        key = rec.key()
        existing = self._records.get(key)
        if existing is not None:
            incoming_data = asdict(rec)
            existing_data = asdict(existing)
            if incoming_data == existing_data:
                return False

            # Timestamp is the primary LWW clock. Equal timestamps can occur
            # during coarse/frozen-clock tests or genuinely simultaneous
            # edits, so use stable record content as a deterministic tie-break.
            # Every broker therefore converges regardless of arrival order.
            incoming_version = (
                rec.ts,
                getattr(rec, "origin", ""),
                json.dumps(incoming_data, sort_keys=True, separators=(",", ":")),
            )
            existing_version = (
                existing.ts,
                getattr(existing, "origin", ""),
                json.dumps(existing_data, sort_keys=True, separators=(",", ":")),
            )
            if incoming_version <= existing_version:
                return False
        self._records[key] = rec
        return True

    def records(self) -> List:
        """All held records (order not guaranteed)."""
        return list(self._records.values())

    def snapshot_wire(self) -> List[Dict]:
        """All records in wire form, for sending to a freshly connected client."""
        return [record_to_wire(r) for r in self._records.values()]

    def __len__(self) -> int:
        return len(self._records)

    # -- persistence ----------------------------------------------------------

    def save(self, path: str) -> None:
        """Write the whole store to ``path`` as JSON (atomic replace).

        Lets annotations survive a broker restart -- reopen tomorrow and the
        names/comments are still there.
        """
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.snapshot_wire(), f)
        os.replace(tmp, path)

    def load(self, path: str) -> int:
        """Load records from ``path`` if it exists. Returns how many were loaded."""
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        count = 0
        for wire in data:
            try:
                if self.apply(record_from_wire(wire)):
                    count += 1
            except (ValueError, TypeError):
                continue  # skip malformed entries rather than fail startup
        return count
