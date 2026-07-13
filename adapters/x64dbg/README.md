# symbridge — x64dbg adapter

Native x64dbg plugin (`.dp64`) that syncs labels, comments, and C type
declarations with the symbridge broker, so annotations flow live between
x64dbg and IDA.

## What it does

- **Remote → x64dbg:** applies incoming `symbol`/`comment` updates via
  `Script::Label::Set` / `Script::Comment::Set` at `BaseFromName(module) + rva`.
- **Broker → x64dbg types:** batches canonical C declarations into a generated
  header and imports it with x64dbg's native `ParseTypes` command. Each reload
  replaces the preceding symbridge-owned type generation.
- **x64dbg → broker:** x64dbg emits no reliable label/comment-change event, so a
  background thread polls `Script::Label::GetList` / `Comment::GetList` every
  ~750 ms and sends whatever changed. Applied remote values are seeded into the
  same "last seen" maps, so they are never echoed back.
- **x64dbg → broker types:** watches an x64dbg-owned C header, diffs its named
  `struct`/`union`/`enum` definitions, imports the aggregate through `ParseTypes`,
  and publishes create/edit/delete records. A rename is delete+create.
- Keys labels/comments by `(module, rva)` and types by `(module, name)`;
  module names are lowercased to match the IDA side.

## Build

Needs the x64dbg **plugin SDK** (the `pluginsdk` folder from an x64dbg snapshot)
and MSVC (Visual Studio Build Tools).

### Quick (batch)

```bat
cd adapters\x64dbg\plugin
build.bat "C:\path\to\pluginsdk"
```

Produces `symbridge.dp64`. (If you omit the SDK path it falls back to the path
baked into `build.bat` — edit it for your machine.)

### CMake

```bat
cd adapters\x64dbg\plugin
cmake -B build -DX64DBG_SDK="C:/path/to/pluginsdk" -A x64
cmake --build build --config Release
```

> 32-bit target: link `x32dbg.lib` / `x32bridge.lib` / `jansson_x86.lib` and use
> a `.dp32` suffix. Only x64 is wired up right now.

## Install

Copy `symbridge.dp64` into your x64dbg `x64\plugins\` folder and (re)start x64dbg.
You should see `[symbridge] plugin loaded` in the log and a **symbridge** menu
under Plugins.

## Use

1. Start the broker:  `python -m broker.symbridge_broker -v`
2. In x64dbg, open (debug) your target so the main module is loaded.
3. Plugins → symbridge → **Connect to broker**
   (broker address via `SYMBRIDGE_HOST` / `SYMBRIDGE_PORT`, default 127.0.0.1:9100).
4. Rename via a label or add a comment → it appears on the other tool within ~1 s.
   Menu **Push all annotations** force-sends the current state.
5. Add or edit a named Local Type in IDA → its C declaration is imported into
   x64dbg's type system through `ParseTypes`.
6. To edit types from x64dbg, register a local canonical header once per
   x64dbg session:

   ```text
   symbridgewatchtypes "C:\path\target_types.h"
   ```

   Save that file after adding/editing/renaming/deleting a named aggregate.
   The plugin notices it within ~750 ms, reloads x64dbg, and sends the diff to
   IDA. `symbridgetypesync` forces an immediate rescan.

The same menu actions are available from x64dbg's command bar/scripts:

```text
symbridgeconnect
symbridgepush
symbridgedisconnect
symbridgewatchtypes "C:\path\target_types.h"
symbridgetypesync
```

## Notes / limits (MVP)

- Only the **main debuggee module** is synced. Load the target before Connect so
  incoming updates resolve (`BaseFromName` needs the module present).
- Poll latency is ~750 ms (not instant). Native change events can replace polling
  later if x64dbg exposes them.
- Type edits made through x64dbg's built-in `AddStruct`/`AddMember` commands
  cannot be reconstructed through the public plugin SDK: `EnumStructs` exposes
  names only. Use the watched canonical header for outbound type changes.
- Complex IDA-specific C extensions
  may exceed x64dbg's header parser; ordinary structs, primitive fields, and
  arrays are the supported baseline.
- x64dbg has a single comment slot, so both IDA regular & repeatable comments map
  onto it; x64dbg → IDA comments are sent as `regular`.
