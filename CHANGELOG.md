# Changelog

All notable changes are tracked here. Format: date — change set (branch/commit).

## 2026-08-13 — forge-api plan completion + O1/O2 verification pass

### Correctness
- `create_type(overwrite=True)` now truly overwrites: types are deleted by
  ordinal (`get_type_ordinal` → `del_numbered_type`) with a name-delete
  fallback; the facade reports three distinct error strings instead of
  masking every failure as "type already exists" (R10, live-reproduced).
- Headless `finalize`/`finalize_all` route through `build_cdecl` →
  `set_cdecl` like `create_type` and report a real reason instead of an
  empty `unresolved` list (R11, live-reproduced).
- `import_type` compat chain for IDA 9.4 (module → til → idc) (R8);
  headless `apply_type` no longer uses GUI-only `set_lvar_type` (R9).
- Recursive scans skip varargs callees (printf-style loggers) — the
  format-string member pollution guard (O2).
- `forge.toml` writes import `toml` lazily; reads use stdlib `tomllib` —
  the plugin now imports headless even without the `toml` package (I.6
  completion, found by the O1 live pass).

### Facade additions (branch forge-api)
- Scanning: `deep_scan(root_type=...)`, auto-created store structures,
  `scan_from_allocation(ea, var_name, name, commit)` — guess → HEAP row →
  scan the allocation result (typed roots auto-retyped to `void *` and
  restored); `guess_allocation` rows carry `size_hint`/`callee`, with
  constant folding for allocator sizes.
- Type mirror: `import_types` (custom structs only; system/compiler types
  excluded via base-til + name denylist), `push_type`/`push_all`/
  `refresh_types` with the `Storage("TypeMirror")` baseline.
- Recon/edits: `function_info`, `callers_of`/`callees_of`,
  `vtable_entries`/`vtable_name`, `imports(pattern)`, `is_type`,
  `decompile(max_lines/line_range/force)`, `signature`, `apply_type(ea,
  decl, redefine_range)`, `set_func_proto`, `set_lvar_types`/
  `rename_local`, `get_member(include_disabled)`, `link_child`,
  collision-aware `add_member`/`to_vtable`, `create_type` `skipped`
  reporting.
- Architecture: `forge.api.store.StructureCatalog` — the single shared,
  netnode-persisted structure store used by both the GUI form and the
  facade (I.28); type-library mirror (I.27); `Storage("TypeMirror")`.
- Scanner: named-symbol direct stores and strcpy/mem-family member
  synthesis (I.20); cross-function allocation discovery with lvar-index
  matching and ctree-walk fallback (I.25, O1); `cit_return=80`/`visit_insn`
  compatibility for IDA 9.4 ctree walks (O1 live findings).

### Tests / infra
- 554 passing; `ruff check src tests` clean.
- `tests/unit/test_stub_signatures.py` (T3.3); conftest hexrays stub
  completed (`is_legal_type`, `get_funcs_referencing_address`);
  regression tests for overwrite, finalize, scan_from_allocation typed
  roots, import filter, define-then-return callee matching, varargs
  skipping, signed-8 display canonicalization.

### Ops
- `ida-codemode` worker lease default patched to `keepalive=600`
  (`database.py`/`client.py` in the plugin install dir; takes effect on
  the next MCP server restart) — workers no longer die on a health-stream
  blip mid-session.

## 2026-08-11 — assessment fixes (pre-forge-api; see git history)

- R6 collision-paint KeyError, R7 child-scan gating, T1.x type-cache
  descriptors, T2.x structural debt, T3.x test infra + 19 gap tests,
  T4.x undo/state guards, I.1–I.7 logging/config/docs polish. 451 tests.
