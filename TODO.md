# ida-forge TODO

Current state (2026-08-13): all planned work — the 2026-08-11 assessment
wave, the forge-api plan (R10/R11, I.8–I.28, T3.3), the O1–O5
verification/fix pass, the full-facade **evaluation review** (E section
below), and the **E.1–E.11 bug fixes** (see note under E-bug) — is in.
The commit-level record lives in `CHANGELOG.md`; this file holds findings,
future ideas, and operational notes.

Baselines: `python -m pytest -q` → 566 passing; `python -m ruff check src
tests` → clean; branch `forge-api` clean working tree.

## Evaluation findings — forge_api review, 2026-08-13

Full walk of `pure_c_struct_fixture.exe` headless via idalib
(`docs/forge_api_evaluation_output.md`). Usability verdict 6.5/10:
core loop good (store structs, headless commit, apply_type, retyping),
roughly a third of the session spent on API drift and silent failures.
The report's §7 priority: fix the IDA 9.x drift first, then renaming.
Standalone bugs first — all live-reproduced:

### E-bug — FIXED 2026-08-13 (commits `4372b94`, `97b9474`, `8d8bd3c`)

All eleven live-reproduced defects are fixed, unit-tested (14 new tests)
and live-verified on the pure_c fixture worker:

- **E.1** IDA 9.x drift — `ida_typeinf.parse_decl` cannot parse function
  prototypes; `idc.parse_decl` is the legacy **2-arg** `(decl, flags)`
  form returning `(ret, tp, fld)` → deserialize (live signature probe).
  `set_func_proto` applies via `apply_tinfo` (set_ti removed). Fixes
  `set_func_proto` (live: prototype applied) + `create_field` (no more
  AttributeError). **Live caveat**: `create_field` returned False with no
  reason on the fixture — the crash is gone, the silent-False needs a
  reason string (fold into E.20 tweaks).
- **E.2** unnamed tables → `vtbl_<addr>` fallback (live: to_vtable ok).
- **E.3** `create_structure` seeds the own-name placeholder before the
  member loop (live: `next/child/tag` all kept).
- **E.4** decl_src tracked on every string-authored member
  (add/set_member, link materialize); `rename_relationship_references`
  rewrites texts referencing the old name; `Member._resolve_pack_tinfo`
  re-parses fresh at pack, and **heals `#NN *` ordinal refs** from
  pre-decl_src catalog entries by current type name (live: rename →
  members show `EvalSelfRenamed *`, push ok).
- **E.5** `imports()` walks the real IAT (`get_import_module_qty` +
  `enum_import_names`), module+name filters (live: 50 rows, KERNEL32).
- **E.6** `inverse_if` ctree walk + nearest-`cit_if` pick (live: True on
  the fixture if). Also fixed the same `to_specific_type`-is-a-method
  normalization trap in guess_allocation's treeitems fallbacks.
- **E.7** templated types read via tomllib (lazy toml fallback) — no
  `toml` package needed headless (live: templated_keys listed).
- **E.8** `link_child` materializes the child pointer (decl_src set);
  retype actually lands at finalize via `refresh_linked_member_types`
  (a child must be committed first — that ordering is by design).
- **E.10** `create_type(overwrite=False)` auto-replaces forge
  placeholders (`_is_forge_placeholder_type`); a real pre-existing type
  still errors (live-verified both sides).
- **E.11** `get_member`/`set_member(member_name=…)` disambiguate
  collision offsets (live: `b`/`u64` picked).
- **E.9** `finalize_all` rows carry `created_names` + `error`
  (`create_subtree_types_postorder` returns `(ok, created, error)`).

Sandbox note: the pure_c fixture's shared catalog was refreshed during
the probes (clear_structures), so pre-decl_src entries (KV etc.) are no
longer in the store; the ordinal heal covers them if they reappear via
`import_types`.

> Dropped 2026-08-13: E.12 (function/global renaming — a leaf
> `ida_name.set_name` wrapper, added straight to `forge_api.py`) and
> E.15 (plain scan loop; its real work is F.2). This section tracks only
> items with real design/implementation.

### E-feat — ranked

- **E.13 `recover()` end-to-end pipeline — highest-value orchestration
  gap** (postmortem verdict): store-struct allocate → scan → commit type
  → re-scan with the fresh type → **rebind every recorded lvar/global to
  the canonical type** → re-apply globals after a type re-file → drop
  experiment/exhibit types. Nothing today re-applies when a better type
  arrives later; that is exactly why the saved IDB shows exhibit scan
  types painted over canonical ones (see F.8).
- **E.14 Member naming from constants/strings** — magic values
  (`1347703345`, `0x1300000012`) and `strcpy` targets are the strongest
  naming evidence the scanner ignores; everything lands `u32_10`/
  `u64_15`. Surface string-arg/store evidence as suggested names.
- **E.16 Array/stride detection** — `scan_from_allocation` on
  `calloc(9, 0xC)` returned 33 flat stride-12 members; propose `Cell[9]`
  from the element stride (visible in `cells + 12*(grid-1) + 8`).
- **E.17 Undo of type writes** — `create_type(overwrite=True)` has no
  revert; snapshot the previous cdecl and expose `undo_type(name)` (see
  F.4).
- **E.18 Bit/flag-field decode** — split a packed dword
  (`0x1300000012`, `0x4000`-family flags) into sized members at an
  offset; the store-struct analog of `create_field`.
- **E.19 IDB-type hygiene** — no IDB-type delete, no "reapply named
  type to its bound variables", no find-and-replace member names: the
  cleanup pass is a manual raw-API grind. Add `remove_type(name)` +
  reapply-all so a session can end clean.
- **E.20 Tweak batch** — `push_type` one-size error string (surface the
  underlying cause); `nudge_members` echo new offsets; `get_member`
  default `include_disabled=False`; `decompile(max_lines)` doc note that
  mid-declaration slicing is unreliable (`line_range` is the path);
  `vtable_entries` on a non-vtable should say "not a code-pointer array"
  rather than return bare `[]`; `import_types` needs an N/A hint when
  the til has no foreign UDTs.

## Future capabilities (ideas, in value order — not committed scope)

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
  writes. Concrete ask: snapshot the previous cdecl and expose
  `undo_type(name)` (E.17 — verified need: `create_type(overwrite=True)`
  has no revert today).

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
  no intermediate raw-IDA calls. The eval postmortem (E.13) extends the
  scope: the pipeline must also rebind recorded lvars/globals to the
  canonical type, re-apply globals after a re-file, and drop exhibit
  types — otherwise the DB ends up painted with scan-exhibit types
  (seen live).

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