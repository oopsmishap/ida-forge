# ida-forge TODO

Current state (2026-08-13): all planned work — the 2026-08-11 assessment
wave, the forge-api plan (R10/R11, I.8–I.28, T3.3), and the O1–O5
verification/fix pass — is **done**. The commit-level record lives in
`CHANGELOG.md`. This file holds only future ideas and operational notes.

Baselines: `python -m pytest -q` → 554 passing; `python -m ruff check src
tests` → clean; branch `forge-api` clean working tree.

## Known limitations (live-observed, not fixed by design)

- **I.25 cross-function allocation discovery** returns no row when the
  callee returns a non-local expression (`return (T *)ptr;` with an
  idx-less var) — lvar-index matching requires the returned value to be a
  local assigned from an allocator (2026-08-13 live finding on
  `grid_chain = build_grid_chain(...)`; `list_demo` verifies the mechanism
  works where the premise holds).
- **`cfunc.treeitems` is empty** on freshly decompiled functions on this
  IDA 9.4 build — any new treeitem-based code must use the ctree-visitor
  walk fallback (`visit_insn` hook, `apply_to(body, None)`,
  `cit_return=80`), per `guess_allocation`'s iterators.
- **Replay offset drift**: re-running curated scripts can shift committed
  absolute offsets vs a prior session (+64..168 B observed) — re-verify
  against disassembly, not the old store diff.

## Future capabilities (ideas, in value order — not committed scope)

### F.1 Implement member type application (closes the core loop)

- `ScannedStructureMemberObject.apply_type` is still a `# TODO` no-op —
  members of created structs never get their types rewritten in IDA
  (`scanner.py:246-250`). Use `get_udt_details`/`udt_member_t.set_type`
  or re-`set_cdecl` the affected member; gate behind a "rewrite types"
  toggle.

### F.2 Batch scans with progress UI

- `decompile` loops block the UI thread; use `replace_wait_box` +
  `decompile_many` with process-function chunking.

### F.3 Finish return-value scanning

- The deleted `DeepScanReturnVisitor` concept: "this function returns a
  `Foo*` — find every caller's use" — unlocks whole-interface recovery.

### F.4 IDA undo integration for type writes

- Wrap `create_type`/`set_cdecl`/`rename_created_type` in `ida_undo`
  snapshots (T4.1 already snapshots `set_cdecl`); de-risks all type
  writes.

### F.5 Scan-result exchange / portability

- Export/import the portable `Structure` descriptor (members,
  provenance, relationships, re-parsed type strings) as a `Storage`
  namespace or JSON file — lets recovered structures move between IDBs;
  in-IDB persistence already exists (the `StructureCatalog`).

### F.6 Generalize `swap_if` into a ctree-rewriting DSL

- `swap_if` persists inversions across re-decompilation via
  `SilentIfSwapper` maturity hooks — the skeleton for loop-hoisting
  helpers, struct-arg splitting, etc.

### F.7 Lumina metadata backfill

- `func_info_t`/lumina metadata (9.3: `calc_func_metadata`/
  `apply_metadata`) so recovered structure info survives into shared
  analysis.

### F.8 One-shot recovery pipeline (packaged session recipe)

- The type-recovery recipe is deterministic (replayed twice): retype
  root → create_structure → deep_scan → rename from decompile semantics →
  to_vtable → create_type → retype args → decompile to verify. A facade
  `recover(root_ea, var_name="a1", name="...")` orchestrates the whole
  loop on `deep_scan(root_type=...)` + auto-create + `set_lvar_types`.
- Acceptance: on a fresh DB, `recover(0x1400017A0, var_name="a1")`
  returns a committed named type whose re-decompile shows member names —
  no intermediate raw-IDA calls.

---

## Verification commands

```bash
python -m pytest -q            # 554 passing
python -m ruff check src tests # clean
git log --oneline main..HEAD   # pending commit list
```

## Replication notes

- Windows checkout: git warns "LF will be replaced by CRLF" for
  `src/forge/util/logging.py` — line endings are not a signal.
- The test temp config dir is auto-purged per test
  (`_purge_user_config_dir` in `tests/conftest.py`) — do not write test
  fixtures that persist under `%TEMP%\ida-forge-tests`.
- Real-IDA verification (T1.2, T3.3) requires IDA ≥ 9.0 with Hex-Rays;
  the structure-builder features need the decompiler.
- When touching `types.py`, re-read the leimurr comment — the canonical
  warning for the tinfo-handle class of bug.
- **Headless (ida-codemode / idalib) session notes, 2026-08-12/13**:
  - `importlib.reload(forge_api)` re-executes the module — the store
    catalog survives (it lives in `forge.api.store`), but module-level
    state like the guess visitor must be reloaded separately
    (`importlib.reload(forge.features.guess_allocation.guess_allocation)`).
  - Idle workers disconnect after ~20 s lease — the installed
    `ida-codemode` defaults are patched to `keepalive=600`
    (`database.py`/`client.py`); takes effect after the MCP server
    restarts. Keep curation scripts in one execute either way.
  - IDA 9.4 lvar API: `cfunc.set_lvar_type` gone; use
    `modify_user_lvar_info(func_ea, MLI_TYPE, lvar_saved_info_t)` and pass
    the flag (without `MLI_TYPE` it silently fails). `lvar.type` is a
    callable. `rename_lvar` exists, `set_lvar_name` does not;
    `lvar.is_arg_var` is a property.
  - IDA 9.4 ctree: `cfunc.treeitems` empty; statement traversal uses
    `ctree_visitor_t.apply_to(body, None)` with the `visit_insn` hook;
    `cit_return` is 80 (not the older SDK's 78).
  - The plugin dir (`%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-forge`) is a
    symlink to `src/`; source fixes reach a live worker only after DB
    close/reopen or a module reload.
  - WER dumps: crashed idalib workers drop ~370 MB dumps in the plugin
    dir — delete after a crash storm.