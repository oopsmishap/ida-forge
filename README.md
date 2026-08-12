# ida-forge

IDA Pro plugin for recovering C structure layouts from decompiler output.
Forge scans decompiled function bodies, groups variable accesses by byte
offset, and builds editable structure models that can be written back to the
IDA type system — including nested ("child") structures reached through
pointer members.

- **License / origin**: community/side-project codebase (`@oopsmishap`).
- **Host**: IDA Pro ≥ 9.0 with the Hex-Rays decompiler; Python ≥ 3.9 (IDA 9.x
  bundles 3.12).

## Features

- **Structure Builder** (`Alt+Shift+F9`) — the main workbench:
  - **Deep Scan** (`Shift+Alt+S`) / **Shallow Scan** (`Alt+S`) on the selected
    decompiler expression;
  - member recovery by byte offset with per-member scan evidence, scores,
    provenance, and deduplication;
  - **child structures** — when a member holds a pointer, Forge scans the
    pointed-to layout and links the recovered structure back to the parent
    member (with offset propagation across callers);
  - global-root deep scans (xref-driven), configurable recursion depth;
  - editable member table: nudge offsets, merge/duplicate rows, disable,
    "auto-resolve" overlapping members (with a dry-run confirm), convert a row
    to a virtual table, create new members inline;
  - finalize a model into a real IDA type (`#pragma pack(push, 1)` editor →
    `set_cdecl`, with overwrite confirmation and an IDA undo snapshot).
- **Create new field** (`Ctrl+F`) on a gap/pointer member inside the
  Hex-Rays popup.
- **Convert to __usercall** on a function in the Hex-Rays popup (maps
  cdecl/stdcall/fastcall/thiscall/pascal/ellipsis to the `__usercall`
  family).
- **Guess allocation** helpers, **Swap if/else** inversions, and
  **Templated types** generation.

## Installation

The plugin is a single package under `src/forge` with an IDA entry point
(`src/ida_forge_plugin.py`).

- Install-ID: copy/symlink `src/` into `%APPDATA%\Hex-Rays\IDA Pro\plugins`
  (Windows) or `~/.idapro/plugins` so `ida_forge_plugin.py` is importable at
  `ida-forge`.
- Dependencies: `pip install -r <repo>/requirements.txt` (or
  `pip install -e .[dev]` for development) — the runtime `toml` package is
  used for config writes (`tomllib` handles reads on Python 3.11+).

## Configuration

Runtime options live in `<ida-user>/cfg/forge.toml` and are merged with the
defaults in `src/forge/**/config.py`:

| Key | Default | Meaning |
| --- | --- | --- |
| `log_level` | `INFO` | `DEBUG` for scan machinery, `TRACE` for per-expression walk noise |
| `StructureBuilder.enabled` | `true` | toggle the feature |
| `StructureBuilder.show_structure_form_hotkey` | `Alt+Shift+F9` | open the form |
| `StructureBuilder.shallow_scan_hotkey` | `Alt+S` | shallow scan |
| `StructureBuilder.deep_scan_hotkey` | `Shift+Alt+S` | deep scan |
| `StructureBuilder.default_deep_scan_depth` | `3` | default recursion depth (0 = unlimited) |
| `CreateNewField.hotkey` | `Ctrl+F` | create-field popup |
| `ConvertToUsercall.enabled` | `true` | toggle the feature |

## Development

```bash
pip install -e ".[dev]" ruff
python -m pytest            # full unit suite (IDA modules are stubbed)
python -m ruff check src tests
```

- The test suite stubs all `ida_*` modules; anything exercised only through
  those stubs needs a live-IDA check (`ida MCP` worker / a real session).
- `plugins/ida-forge` is often a symlink to `src/`, so repo edits are live
  after an IDA-side plugin reload (`Forge reload` action).
- Windows: git may warn about LF→CRLF for a few files; that is expected.

See `TODO.md` for the full work plan and known limitations.
