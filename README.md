# symbridge

**Live annotation sync between IDA Pro and x64dbg.** Rename a function, drop a
comment, or define a struct in one tool — it shows up in the other within a
second. No more re-doing your analysis when you switch from static to dynamic.

> Status: working, cross-verified live on **IDA Pro 9.4 ↔ x64dbg**. Names,
> comments, and C struct/type definitions all sync bidirectionally.

---

## The problem

Reverse engineers work on the same binary in more than one tool: IDA for static
analysis, x64dbg for debugging. You spend hours naming functions, writing
comments, and rebuilding structs in IDA — then you open x64dbg and none of it is
there. Existing tools either only sync the cursor position (`ret-sync`) or are
Ghidra-centric and rough (`BinSync`). There was no drop-in, *live* bridge that
carries **names + comments + types** between IDA and x64dbg. symbridge is that
bridge.

## What it syncs

| Annotation | IDA → x64dbg | x64dbg → IDA |
|---|---|---|
| Symbol names (labels) | ✅ | ✅ |
| Comments (regular / repeatable) | ✅ | ✅ |
| Structs / types (C declarations) | ✅ | ✅ |

- **Address-independent:** everything is keyed by `(module, RVA)`, so ASLR and
  different image bases never matter — a function at RVA `0x1500` lines up in
  both tools automatically.
- **Live:** local edits are captured via IDA's `IDB_Hooks` and an x64dbg polling
  thread, relayed instantly through a broker.
- **Loop-free:** every change carries an `origin`; the broker never echoes it
  back, and adapters guard with an "applying remote" flag.
- **Persistent:** run the broker with `--persist state.json` and your
  annotations survive restarts — reopen tomorrow and everything is still there.

## Architecture

A small hub-and-spoke design. A standalone **broker** holds the canonical state;
each tool runs a thin **adapter** that pushes local edits and applies remote
ones. Transport is newline-delimited JSON over localhost TCP — zero third-party
dependencies, so IDA's embedded Python and a native C++ plugin both speak it
without installing anything.

```
   IDA (IDAPython plugin) ──┐
                            ├──►  Broker (localhost TCP, canonical state)
   x64dbg (C++ .dp64) ──────┘
```

Adding a third tool (Ghidra, Binary Ninja) later means writing one more adapter
against the same fixed protocol — the broker and data model don't change.

## Quick start

### 1. Run the broker
```bash
python -m broker.symbridge_broker -v            # or: --persist state.json
```

### 2. Try it with no tools installed (recommended first step)
Two fake adapters in separate terminals let you watch the sync happen:
```bash
python -m dev.simclient --id A --tool ida      --module target.exe
python -m dev.simclient --id B --tool x64dbg   --module target.exe
```
Type `sym 1000 decrypt_string` in one and watch it appear in the other.

### 3. IDA adapter
Load `adapters/ida/symbridge_ida.py` via **File → Script file…** (or drop it in
your `plugins/` folder). Run it (Ctrl-Alt-S) to connect. Rename a function (`N`)
or add a comment (`;`) and it flows to the broker. Details:
[adapters/ida/](adapters/ida/).

### 4. x64dbg adapter
Build the plugin and copy `symbridge.dp64` into x64dbg's `x64\plugins\`, then
**Plugins → symbridge → Connect**. Full build/use notes:
[adapters/x64dbg/README.md](adapters/x64dbg/README.md).

```bat
cd adapters\x64dbg\plugin
build.bat "C:\path\to\pluginsdk"
```

Broker host/port are configurable via `SYMBRIDGE_HOST` / `SYMBRIDGE_PORT`
(default `127.0.0.1:9100`).

## How it works

- **Canonical model** (`broker/model.py`): `Symbol{module,rva,name}`,
  `Comment{module,rva,text,kind}`, `TypeDef{module,name,decl,deleted}`. Types are
  carried as **C-declaration text** — the common denominator both tools parse.
- **Merge:** last-write-wins by timestamp, so replays and out-of-order delivery
  are idempotent. Type deletes/renames travel as tombstones.
- **Protocol** (`shared/schema.json`): `hello` → broker replies with a full
  `snapshot`; `update` carries one changed record; `ack` confirms receipt.

## Project layout

```
broker/            standalone broker + canonical data model (pure Python)
adapters/
  common/client.py reusable socket client (used by Python adapters)
  ida/             IDAPython plugin + unit-tested pure sync logic
  x64dbg/          native C++ plugin (plugin SDK) + its own README
shared/schema.json wire protocol (single source of truth across tools)
dev/simclient.py   fake adapter for a no-tools live demo
tests/             broker/model/client/persist/ida-sync test suites
```

## Testing

No dependencies required (Python 3.11+; `pytest` optional):
```bash
python -m tests.test_broker
python -m tests.test_client
python -m tests.test_persist
python -c "import tests.test_model as m, tests.test_ida_sync as i; [getattr(x,n)() for x in (m,i) for n in dir(x) if n.startswith('test_')]; print('ok')"
```
The C++ type-diff logic has its own tests under `tests/type_sync_tests.cpp`.

## Roadmap

- Ghidra and Binary Ninja adapters (same protocol, new spoke).
- Native x64dbg change events to replace polling if/when exposed.
- Richer type support beyond structs/unions/enums with primitive & array fields.

## License

[MIT](LICENSE) — free to use, modify, and distribute.
