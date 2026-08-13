# ida-forge TODO

Current state (2026-08-13): the 2026-08-11 assessment + the 2026-08-12
live type-recovery learnings were implemented on branch `forge-api`
(17 commits, R10/R11 + I.8–I.28 + T3.3). Suite: **533 passing**, ruff
clean. What remains is listed below under *Next work*; everything
resolved is archived at the bottom with one-line summaries and commit
hashes.

## How to use this file

- **Open work** is ordered: verification first (never trust an
  unverified facade), scanner leftovers, ops, docs. Each item is
  self-contained: **Issue / Plan / Acceptance**.
- Ground rules for fixes: run the specific test that covers the change;
  add a regression test for every bug fix (behavior assertions, no
  tautology); never touch `tests/conftest.py` stubs to make a test pass;
  anything that only works against the stubs is unverified against real
  IDA — mark with an explicit live-verify acceptance step.
- Baselines: `python -m pytest -q` → 533 passing; `python -m ruff check
  src tests` → clean.

---

## Open work

### O1 Live verification pass of the forge-api plan — DONE 2026-08-13

Verified live on the pure_c fixture DB (idalib worker, forge_api):
- **R10/R11** ✓ — `create_type(overwrite=True)` twice on the same store
  struct: second call committed the refined member (`a/b/c@0/4/8`);
  headless `finalize` → `{"ok": True, "type_name": ...}`.
- **I23/I24** ✓ — `scan_from_allocation(nested_dispatch_demo,
  var_name="cells")` returns the 17-member stride-12 lattice
  (0,2,12,…,100) with `size_hint: 108`; **deviation found + fixed**:
  a struct-pointer-typed root (`ArrayCell *cells`) collapsed to offset-0
  noise — `scan_from_allocation` now auto-retypes UDT-pointer roots to
  `void *` for the scan and restores the analyst's type afterwards
  (`_allocation_root_prior_type`; `lvar.type` is a callable on 9.4).
- **I27** ✓ — clean-catalog `import_types()` returns the custom structs
  and excludes BYTE/_CONTEXT/EXCEPTION_RECORD/UNWIND_INFO_HDR/
  C_SCOPE_TABLE; push/refresh round-trip verified (rename → `push_type`
  → IDB shows the rename → restore+push → `refresh_types` no-churn).
  **Deviation fixed**: compiler-generated locals (UNWIND_INFO_HDR,
  C_SCOPE_TABLE, …) live in the local til, so the base-til check alone
  cannot exclude them — added the `_SYSTEM_TYPE_NAMES` denylist.
- **I.25** — live: `grid_chain = build_grid_chain(2, 3u)` still returns
  no rows on this DB because the callee's returned expression is a
  non-local (`v.idx`-less cast node) — the define-then-return premise
  doesn't hold for that shape. The mechanism itself was verified live
  through `list_demo` (HEAP rows with correct sizes, incl. strlen+1 key/
  value copies) and requires lvar-index matching, `visit_insn` (not
  `visit_statement`), `apply_to(body, None)`, `cit_return = 80`, and
  cast-peeling of returned expressions — all fixed + unit-tested in
  `tests/unit/test_guess_allocation.py`.
- **I.17/I.13/I.14** ✓ — `is_type`, `function_info` (callers), and
  `vtable_entries` (tolerant non-vtable error) verified live.

Remaining defect from the pass: none known. `grid_chain`-style
non-local returns are documented as an I.25 limitation.

## O2 Scanner leftovers — DONE 2026-08-13

- Varargs callees (printf-style loggers) are no longer descended into —
  `_execute_visit` drops the visit when `cfunc.type.is_vararg_cc()`
  (regression: visitor test).
- Signed-8 display names canonicalize to `char` (`normalize_type_display`
  in `forge.api.members`; used by the facade's member type strings) —
  `i8 *`/`__int8`/`signed char *` all display as `char *` (table test).
- The double "Extracting member" debug log was deduplicated (the
  ptr-path log removed; the common-path one remains).

## O3 Idalib worker lease — DONE 2026-08-13 (patch applied)

`ida-codemode` `database.py`/`client.py` defaults patched to
`keepalive=600.0` in the plugin install dir (py_compile verified). Effect
after the MCP server restarts: workers survive health-stream blips
instead of dying mid-session. NOTE: the running MCP server still uses the
old default until restarted; the patch is on disk.

## O4 Facade documentation sync — DONE 2026-08-13

- root `README.md` gained a "Headless forge_api facade" feature block
  (store/catalog persistence, allocation workflow, type mirror, recon +
  edit surface).
- `src/README.md` rewritten to describe the 2026-08 package layout
  (store.py/storage.py mirror included).

## O5 Changelog + release follow-ups — DONE 2026-08-13

- `CHANGELOG.md` created covering the forge-api plan + O1/O2 fixes +
  the keepalive patch; `git log --oneline main..forge-api` referenced
  there. Branch still open for merge/tag at the maintainer's call.

## Future capabilities (ideas, in value order — not committed scope)

### F.1 Implement member type application (closes the core loop)

- `ScannedStructureMemberObject.apply_type` is still a `# TODO` no-op—
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
  in-IDB persistence already exists (I28 catalog).

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
  loop on I8 + I10/auto-create + I12.
- Acceptance: on a fresh DB, `recover(0x1400017A0, var_name="a1")`
  returns a committed named type whose re-decompile shows member names —
  no intermediate raw-IDA calls.

---

## Verification commands

```bash
python -m pytest -q            # 533 passing
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
  warning for the tinfo-handle class of bug (T1.1).
- **Replay caveat (2026-08-12)**: curated-offset scripts are
  deterministic per store, but a replay's committed absolute offsets can
  drift (+64..168 B in the World tail) — the script doesn't reproduce
  the original incremental disables of leftover scan members. Re-verify
  final offsets against disassembly, not the previous store diff.
- Headless (ida-codemode / idalib) session notes, 2026-08-12:
  - `importlib.reload(forge_api)` re-executes the module and **wipes the
    store** — plain `import forge_api` keeps state; reload only after
    editing plugin source.
  - Idle workers disconnect after ~20 s lease (keepalive=0) — keep
    curation scripts in one execute or the in-memory IDB is lost.
  - IDA 9.4 lvar API: `cfunc.set_lvar_type` gone; use
    `modify_user_lvar_info(func_ea, MLI_TYPE, lvar_saved_info_t)` and
    pass the flag — without `MLI_TYPE` it silently fails. `rename_lvar`
    exists, `set_lvar_name` does not; `lvar.is_arg_var` is a property.
  - The plugin dir (`%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-forge`) is a
    symlink to `src/`; source fixes reach a live worker only after DB
    close/reopen (or hot-patch the cached module attribute).
  - WER dumps: crashed idalib workers drop ~370 MB dumps in the plugin
    dir — delete after a crash storm.

---

## Archived

### 2026-08-11 waves (assessment fixes) — all resolved, tests green

- R6 collision-paint KeyError; R7 child-scan gating; R8 vtable
  `import_type` compat (IDA 9.4); R9 headless `set_lvar_type` crash.
- T1.1-tinfo cache → `_TypeEntry` descriptors; T1.2 `add_idc_func`
  verified; T1.3 `DeepScanReturnVisitor` deleted; T1.4/T1.5 `get_line`
  + `Iterator`; T2.1-T2.7 structural debt; T3.1-T3.5 test infra (CI,
  ruff, coverage, stub guard precursor, 19 gaps closed); T4.1-T4.4
  state/undo guards; I.1-I.7 logging/config/docs polish.

### 2026-08-13 forge-api plan (17 commits on branch forge-api)

- **R10** — `create_type(overwrite=True)` deletes by ordinal
  (`get_type_ordinal` → `del_numbered_type`), name-delete fallback,
  visible failure; facade distinguishes the three error strings. `e5e52f7`.
- **R11** — headless `finalize`/`finalize_all` route through
  build_cdecl → set_cdecl; failures report a reason, never empty
  `unresolved`. `e5e52f7`.
- **I.12** — `set_lvar_types` (scope arg/all) + `rename_local`, both on
  `modify_user_lvar_info(MLI_TYPE)` / `rename_lvar`. `d84448d`.
- **I.8** — `deep_scan(root_type=...)` persists root retypes; integral
  roots auto-retype to `void *` so `__int64 a1` recovers fully. `d84448d`.
- **I.10** — bare scans auto-create `Structure`/`Structure Copy`
  (`catalog.unique_name`). `d84448d`.
- **I.9** — `to_vtable` placeholder member + `skipped` reporting on
  disabled-only offsets. `d84448d`.
- **I.11** — `create_type` reports `skipped` collision-disabled members.
  `d84448d`.
- **I.18** — `get_member(include_disabled=True)`; `add_member`/
  `set_member` report `"collision"`. `d84448d`.
- **I.19** — `apply_type(ea, decl, redefine_range=False)`: store-aware
  parse, TINFO_DEFINITE, range redefinition via `del_items` +
  `del_global_name`. `d84448d`.
- **I.13** — `function_info`/`callers_of(ea, kind=...)`/`callees_of(ea)`
  (dref/code walk, cycle-guarded). `c66bfe8`.
- **I.14** — `vtable_entries(address)`/`vtable_name(address)`, tolerant
  of non-vtable targets. `c66bfe8`.
- **I.15** — `imports(pattern)` via `idautils.Entries()` (9.4-safe).
  `c66bfe8`.
- **I.16** — `decompile(max_lines/line_range/force)` + `signature(ea)`.
  `c66bfe8`.
- **I.17** — `is_type(name)`. `c66bfe8`.
- **I.22** — `set_func_proto(ea, declaration)`. `c66bfe8`.
- **I.23** — `scan_from_allocation` wires guess → HEAP row → auto store
  struct → `deep_scan` → `to_vtable` → `create_type(overwrite=True)`.
  `a923469`.
- **I.24** — allocator size folding (`mul`/`add`/`sub`), `size: None`
  for unknown, `size_hint`/`callee` rows. `a923469`.
- **I.25** — one-level callee decompile for allocator-returned locals.
  `a923469`.
- **I.26** — vtable-stored allocations offer the subobject scan with
  `to_vtable`. `a923469`.
- **I.21** — `link_child` + store-name placeholder resolution in
  `add_member`. `d84448d`.
- **I.20** — scanner: named-symbol direct stores (`span` + named heads)
  and strcpy/memory-writer member synthesis (allowlist,
  `char[N+1]` literals). `a538825`.
- **I.28** — `forge.api.store.StructureCatalog`: one shared, persisted
  store (`Storage("Structures")`), events, `unique_name`, `current`;
  form + forge_api share it. `71054db`.
- **I.27** — type-library mirror: `import_types` / `push_type` /
  `push_all` / `refresh_types` with the `Storage("TypeMirror")`
  baseline; 9.4 base-til via `idati.base(0)`. `71054db`, `7973bdd`.
- **T3.3** — `tests/unit/test_stub_signatures.py` pins the conftest
  stub surface to the real call shapes. `7f8d1b8`.