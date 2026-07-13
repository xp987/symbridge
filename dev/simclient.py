"""Interactive fake adapter for demoing/verifying the broker without IDA/x64dbg.

Open a broker and two of these in separate terminals to watch annotations sync
live. It uses the same :class:`BrokerClient` the real adapters use, so it also
exercises the exact wire protocol.

Example
-------
Terminal 1:  python -m broker.symbridge_broker -v
Terminal 2:  python -m dev.simclient --id A --tool ida
Terminal 3:  python -m dev.simclient --id B --tool x64dbg

Then in terminal 2 type:
    sym 1000 decrypt_string
    cmt 1000 xor loop, key in ecx
and watch terminal 3 print the incoming updates (and vice versa).

Commands (one per line):
    sym <rva_hex> <name...>      send a symbol (name) update
    cmt <rva_hex> <text...>      send a regular comment update
    rcmt <rva_hex> <text...>     send a repeatable comment update
    type <name> <c-decl...>      send a struct/type update
    quit                         disconnect and exit
"""

from __future__ import annotations

import argparse
import sys
import threading
import time

from adapters.common.client import BrokerClient


def _fmt(msg: dict) -> str:
    t = msg.get("type")
    if t == "snapshot":
        return f"[snapshot] {len(msg.get('records', []))} record(s)"
    if t == "update":
        d = msg.get("data", {})
        rec = msg.get("record")
        if rec == "symbol":
            return f"[update:symbol] rva={d.get('rva'):#x} name={d.get('name')!r} (from {msg.get('origin')})"
        if rec == "comment":
            return f"[update:comment/{d.get('kind')}] rva={d.get('rva'):#x} text={d.get('text')!r} (from {msg.get('origin')})"
        if rec == "type":
            return f"[update:type] {d.get('name')} = {d.get('decl')!r} (from {msg.get('origin')})"
    if t == "ack":
        return f"[ack] seq={msg.get('seq')}"
    return f"[{t}] {msg}"


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="symbridge fake adapter (demo/verify)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--id", dest="client_id", required=True, help="client id / origin")
    parser.add_argument("--tool", default="test", help="tool label (ida/x64dbg/...)")
    parser.add_argument("--module", default="target.exe", help="module name to key by")
    args = parser.parse_args(argv)

    def on_message(msg: dict) -> None:
        # Printed from the reader thread; fine for a console demo.
        sys.stdout.write("\r" + _fmt(msg) + "\n> ")
        sys.stdout.flush()

    client = BrokerClient(args.host, args.port, args.client_id, args.tool, on_message)
    client.connect()
    print(f"connected as {args.client_id} (tool={args.tool}, module={args.module})")
    print("type 'help' for commands, 'quit' to exit")

    try:
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                break
            if not line:
                continue
            cmd, _, rest = line.partition(" ")
            cmd = cmd.lower()

            if cmd in ("quit", "exit"):
                break
            if cmd == "help":
                print(__doc__)
                continue

            try:
                if cmd == "sym":
                    rva_s, _, name = rest.partition(" ")
                    client.send_update(
                        "symbol",
                        {"module": args.module, "rva": int(rva_s, 16), "name": name, "ts": time.time()},
                        origin=args.client_id,
                    )
                elif cmd in ("cmt", "rcmt"):
                    rva_s, _, text = rest.partition(" ")
                    client.send_update(
                        "comment",
                        {
                            "module": args.module,
                            "rva": int(rva_s, 16),
                            "text": text,
                            "kind": "repeatable" if cmd == "rcmt" else "regular",
                            "ts": time.time(),
                        },
                        origin=args.client_id,
                    )
                elif cmd == "type":
                    name, _, decl = rest.partition(" ")
                    client.send_update(
                        "type",
                        {"module": args.module, "name": name, "decl": decl, "ts": time.time()},
                        origin=args.client_id,
                    )
                else:
                    print(f"unknown command: {cmd!r} (try 'help')")
            except ValueError as exc:
                print(f"bad argument: {exc}")
    finally:
        client.close()
        print("disconnected")


if __name__ == "__main__":
    main()
