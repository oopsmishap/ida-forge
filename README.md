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
- **Headless forge_api facade** (2026-08) — a flat, self-describing API for
  automation/LLM use (`forge_api.help()` catalogs every call):
  - store + persistence: structures live in one shared `StructureCatalog` (used by the GUI form and the facade alike) and are
    written through to IDA netnodes (`Storage("Structures")`), so recovered models survive plugin reloads and worker restarts.
    Persistence is best-effort: catalog mutations remain usable in memory when a write fails, and the failure is recorded for
    diagnostics. `storage_status()` reports detached recovery counters
    (`load_failures`, `corrupt_entries`, `write_failures`) and a `health` flag
    (`healthy` or `degraded`), with detached `last_error` details (`operation`,
    exception `type`, and `message`) when recovery has failed.
  - diagnostics: `domain_status()` reports `ida_domain.health` (`available`, `incompatible`,
    or `unavailable`), ordered `fallbacks`, grouped `fallback_summary`, and integer
    `fallback_counts`; `fallback_counts` counts retained evidence records per component.
    `domain_status(clear_fallbacks=True)` performs an explicit destructive read-and-clear and
    reports `fallback_clear_requested` plus the number removed in `fallbacks_cleared`.
    The storage `health` (`healthy` or `degraded`) is independent of `ida_domain.health`.
  - scanning: successful `deep_scan` and `shallow_scan` responses include `ok: true`,
    `structure`, and `members`; failures include `ok: false` and an actionable `error`.
    Both operations support auto-created store structures and root-type retyping
    (`root_type=`); `scan_from_allocation` finds the heap allocation feeding a variable
    (`guess_allocation`, sizes folded from allocator args) and recovers the element layout
    in one call;
  - type mirror: `import_types` / `push_type` / `push_all` /
    `refresh_types` keep the store and IDA's local structs in sync
    (custom structs only; baseline tracked in `Storage("TypeMirror")`);
  - recon + edits: `function_info`/`callers_of`/`callees_of`,
    `vtable_entries`/`vtable_name`, `imports`, `is_type`, `type_of`,
    `apply_type(ea, decl)`, `set_func_proto`, `set_lvar_types`/
    `rename_local`, `to_vtable`, `create_type(overwrite=True)` (in-place
    `update_named_type` — the ordinal survives and applied consumers keep
    referencing the type; delete+recreate is only the fallback when the
    in-place update is unavailable), headless `finalize`.
  - introspection: `help()` returns a deterministic catalog under
    `functions`, with each public operation's group, signature, parameters,
    return contract, example, and docstring.
## Installation

The plugin is a single package under `src/forge` with an IDA entry point
(`src/ida_forge_plugin.py`).

- Install-ID: copy/symlink `src/` into `%APPDATA%\Hex-Rays\IDA Pro\plugins`
  (Windows) or `~/.idapro/plugins` so `ida_forge_plugin.py` is importable at
  `ida-forge`.
- Dependencies: `pip install -e .` (runtime — the `toml` package is used for
  config writes; `tomllib` handles reads on Python 3.11+) or
  `pip install -e ".[dev]"` for development (adds pytest).

## IDA API policy

ida-forge uses the [IDA Domain API](https://ida-domain.docs.hex-rays.com/) as
its preferred IDA interface. Install it with `pip install -e ".[ida]"` or
install `ida-domain` in the IDA Python environment. SDK calls remain only for
capabilities not exposed by Domain, including netnode persistence, GUI actions,
and selected Hex-Rays mutation operations. Those paths are isolated,
documented, and visible through `forge_api.domain_status()`.
### Clean-binary verification

The two scripts below and their fixture are local scratch tooling, not part
of the tracked test surface: only `scripts/r3_gap_probe.py` is tracked, while
`scripts/domain_integration_scenario.py`, `scripts/domain_performance_probe.py`,
and the `.scratch_probe_cold/` fixture directory are gitignored — run them
only from a local checkout.

For deterministic headless analysis, open the input binary through
`ida_domain.Database.open(path=..., save_on_close=False)` rather than attaching
to a warm `.i64`. Forge's lazy adapter exposes the same lifecycle as
`forge.api.domain.open_database(path)`. This keeps the Domain database handle
explicit and makes clean-binary smoke tests reproducible.

### Reusable live-IDB integration matrix

Run the non-destructive scenario against a clean binary from an IDA Python environment:

```bash
python scripts/domain_integration_scenario.py .scratch_probe_cold/pure_c_struct_fixture.exe
```

The JSON report covers `open`, `inspect`, `scan_type`, `persist`, `reopen`, and `close`.
`phase_matrix` preserves that order and contains per-phase `ok`/`available` rows plus a
`complete` flag. Top-level `ok` reports persistence verification; `matrix_ok` mirrors full
lifecycle completion (`phase_matrix.complete`). The scenario discovers scan addresses from
`forge_api.functions()` and does not guess fixture addresses; hosted CI runs syntax/unit gates,
while the live matrix requires IDA/ida-domain.

### Performance baseline probe

Run bounded timing measurements with `scripts/domain_performance_probe.py` from an IDA Python
environment (`domain_performance_probe.py`):

```bash
python scripts/domain_performance_probe.py .scratch_probe_cold/pure_c_struct_fixture.exe --repetitions 3 --warmup 1
```

The report measures `domain_status`, `storage_status`, `functions`, `shallow_scan`, and
`deep_scan`. Scan timing uses the first valid `start_ea` discovered by `forge_api.functions()`
(`session.scan_target`); no target is guessed. With no valid row, scans are marked skipped.
Each scan reports `last_ok`; failed final responses also expose bounded `last_error`. The
`last_error` value describes only the final measured invocation, while `session.scans.all_ok`
summarizes the final measured outcomes; top-level `ok` means the benchmark harness completed.
Timings are comparative evidence, not
performance gates, and scan operations may mutate forge state.

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
| `StructureBuilder.default_deep_scan_depth` | `10` | default recursion depth (0 = unlimited) |
| `CreateNewField.hotkey` | `Ctrl+F` | create-field popup |
| `ConvertToUsercall.enabled` | `true` | toggle the feature |

## Development
```bash
pip install -e ".[dev]" ruff
python -m compileall -q src tests scripts
python -m pytest            # full unit suite (IDA modules are stubbed)
python -m ruff check src tests
```

- CI runs the compile gate before Ruff and pytest so syntax errors fail fast.
- The test suite stubs all `ida_*` modules; anything exercised only through
  those stubs needs a live-IDA check (`ida MCP` worker / a real session).
- `plugins/ida-forge` is often a symlink to `src/`, so repo edits are live
  after an IDA-side plugin reload (`Forge reload` action).
- Windows: git may warn about LF→CRLF for a few files; that is expected.

See `TODO.md` for the full work plan and known limitations.
