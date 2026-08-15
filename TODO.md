# ida-forge TODO

Current state (2026-08-15): all planned work is done — the assessment
wave, the forge-api plan (R10/R11, I.8–I.28, T3.3), the O1–O5 pass, the
E-series bug fixes, the round-2 review fixes, and both recovery evals
(round 1 baseline; round 2 = **99/100** on the cold fixture, 20/20
types, 5/5 globals, 10/10 flows). **`CHANGELOG.md` owns the completed
history** (E.1–E.11, round-2 review fixes `607c3ab`, recovery-eval gaps
1/3–6 `45b9d2a`, `clear_structures` removal `5a8da9e`, round-2 report
`e86ce8b`); this file tracks only open work.

Baselines: `python -m pytest -q` → 577 passing; `python -m ruff check src
tests` → clean; branch `forge-api` clean working tree.

## Open review findings (2026-08-13, report: `docs/forge_api_evaluation_output.md`)
— round-2 review of the facade (8/10, pain in attribution + missing verbs)

- **E.21 `deep_scan` merge hygiene — fresh vs accumulate mode.** Repeated
  scans into one store structure accumulate hypotheses + byte-granular
  junk (InlineParent 21 → 23 entries incl. offsets 1,5,6,7 from an
  `_OWORD`-wide store; PointerParent picked 5 collision variants at
  offset 0). Add `clear_first=True` kwarg (fresh mode) so re-scans
  produce a stable member set. Round-2 top-5 #5.
- **E.22 Helper-aware allocation tracking.** `v1 = grid_build(...)`
  (body calls `calloc(1,0x28)`) — `guess_allocation`/
  `scan_from_allocation` return []/error; the I.25 `callee` row exists
  for direct allocator calls but the walker never enters the helper
  body. Recover `GridNode` through wrappers. Round-2 top-5 #3. (R2.7
  confirms: `make_chain`/`kv_append`/`build_grid` all hit this.)
- **E.23 `callees_of` / `decompile()['calls']` IAT-slot resolution.**
  Rows contain `.idata` slot addresses (`0x140004b98` = puts) —
  resolve slots to import-target EAs (or mark them) so call-graph
  consumers don't need the dereference.
- **E.24 Duplicate-name member selection.** `member_name` disambiguates
  first match only; two members with the same name at one offset (name
  differs by type only) need `(offset, name, type)` matching or an
  index. (E.11 follow-up.)
- **E.25 `scan_global` exclusive-end span.** `DispatchTable.count` at
  start+0x60 fell outside span=0x60; either include the trailing qword
  when a data ref points there, or document exclusive-end in help().
- **E.26 Bidirectional mirror.** `refresh_types` pulls layouts only
  (no member-name renames); `import_types` skips store-known types with
  no skip-reason report. Doc line + adoption report. Round-2 top-5 #4.
- **E.27 `remove_type(name)`** — facade type deletion with the working
  ordinal-delete path (`del_named_type` name-form returns False live on
  9.4; `del_numbered_type(ordinal)` works). Placeholder materialization
  makes stray types inevitable; cleanup needs this verb.
- **E.28 Union member types (2026-08-15, from round-2 partial).** The
  store has no union member representation: `Variant.as` commits as
  `u64`, the four union tags (`as_u32/as_i32/as_f32/as_ptr`) are
  lost. Offsets/sizes are exact; needs a union member (or inline-anon
  cdecl) type in the store + pack path. Re-commit `ItemStack`/`Outer`
  afterwards for full member-type credit.
- **E.29 Non-UDT type creation (2026-08-15).** `DispatchFn` typedef
  (`int (__cdecl *)(void*, unsigned int)`) had to be created via
  ida-domain redeclare — forge's `create_type` handles structs only.
  Extend to function-pointer typedefs (+ unions = E.28) so a session
  never leaves the facade for a type verb.
- **E.14 update — printf-literal member naming.** The fixture's own
  format strings (`"first=%s id=%u flags=%u score=%u sample=%u"`) carry
  exact member names; a heuristic naming scan from the consuming printf
  signature would collapse the manual naming step (round-2 top-5 #5b).
- **E.16 update — array/stride evidence.** `Stack2[2]`, `u32[2]` dims
  and `u8[16]`/`xmmword` blobs were all hand-fixed in round 2;
  `scan_global` emitted the blobs, not the arrays.

## Recovery-eval round 2 — ranked gaps (2026-08-15, report:
`docs/forge_api_recovery_eval_output.md`)

- **R2.1 — placeholder-size poison at pack (highest priority).** A
  member whose store-name resolves only to the seed 1-byte
  `char _placeholder` packs the parent from that size and corrupts the
  layout (observed `Inline` first@16 → second@104; `Outer` bag 16→1 B
  shifting grid +0x10 / dispatch +0x20 / stacks +0x88).
  `create_type(parent)` re-pack does NOT resolve the -1 sizes after the
  child commits; workaround `set_member(parent, off, type=child)` +
  re-`create_type`. Fix target: resolve store names to committed types
  at pack time.
- **R2.2 — `apply_type(redefine_range=True)` suppressed on user-named
  heads.** A named global keeps a 1-byte head; the full-span struct item
  only materializes for unnamed heads. Workaround: apply before naming,
  or ida-domain `del_items(DELIT_DELNAMES)` + `apply_tinfo`.
- **R2.3 — struct-item lifetime race in idalib.** `create_struct` /
  `apply_type` items at global heads re-split to 1-byte items under
  deferred auto-analysis (even after `auto_wait`). Robust path:
  `del_items(DELIT_DELNAMES, span)` + `apply_tinfo(TINFO_DEFINITE)` +
  `set_name` — survives save/reopen (verified).
- **R2.4 — `apply_type` `del_items(ea, DELIT_SIMPLE, ea+size)` erodes
  the .data tail.** The 3rd arg is an absolute END offset, not a byte
  size: applying `char *[4]` at 0x6000 deleted items through
  0x6020+0x20 and sibling structs came back as 1-byte unknowns.
- **R2.5 — `int32`/`uintN` silently dropped** by the member-type
  parser (member vanishes, no error; `__int32` works). Alias or loud
  error for the C typedef family.
- **R2.6 — C-keyword member names silently dropped** from the cdecl
  (e.g. member `inline` — no message). Rename or loud error, mirroring
  the type-name keyword check.
- **R2.7 — E.22 confirmed (see above)** — no change; compensating
  `deep_scan` on the helper + manual construction from disassembly.

## E-feat — ranked feature gaps

- **E.13 `recover()` end-to-end pipeline — highest-value orchestration
  gap** (postmortem verdict): store-struct allocate → scan → commit
  type → re-scan with the fresh type → **rebind every recorded
  lvar/global to the canonical type** → re-apply globals after a type
  re-file → drop experiment/exhibit types. Nothing today re-applies
  when a better type arrives later; that is why the round-1 saved IDB
  showed exhibit scan types painted over canonical ones (see F.8).
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
- **E.19 IDB-type hygiene** — no "reapply named type to its bound
  variables", no find-and-replace member names: the cleanup pass is a
  manual raw-API grind. Add reapply-all so a session can end clean.
  (Type deletion itself is E.27.)
- **E.20 Tweak batch** — `push_type` one-size error string (surface the
  underlying cause); `nudge_members` echo new offsets; `get_member`
  default `include_disabled=False`; `decompile(max_lines)` doc note
  that mid-declaration slicing is unreliable (`line_range` is the path);
  `vtable_entries` on a non-vtable should say "not a code-pointer array"
  rather than return bare `[]`; `import_types` needs an N/A hint when
  the til has no foreign UDTs.

## Future capabilities (ideas, in value order — not committed scope)

- **I.25 cross-function allocation discovery** returns no row when the
  callee returns a non-local expression (`return (T *)ptr;` with an
  idx-less var) — lvar-index matching requires the returned value to be
  a local assigned from an allocator (2026-08-13 live finding on
  `grid_chain = build_grid_chain(...)`; `list_demo` verifies the
  mechanism where the premise holds).
- **`cfunc.treeitems` is empty** on freshly decompiled functions on
  this IDA 9.4 build — any new treeitem-based code must use the
  ctree-visitor walk fallback (`visit_insn` hook, `apply_to(body,
  None)`, `cit_return=80`), per `guess_allocation`'s iterators.
- **Replay offset drift**: re-running curated scripts can shift
  committed absolute offsets vs a prior session (+64..168 B observed) —
  re-verify against disassembly, not the old store diff.

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
  to_vtable → commit type → retype args → decompile to verify. A facade
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
python -m pytest -q            # 577 passing
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
- **Headless (ida-codemode / idalib) session notes, 2026-08-12/13/15**:
  - `importlib.reload(forge_api)` re-executes the module — the store
    catalog survives (it lives in `forge.api.store`), but module-level
    state like the guess visitor must be reloaded separately
    (`importlib.reload(forge.features.guess_allocation.guess_allocation)`);
    or delete the whole module group (`del sys.modules[...]` for
    `forge_api` + `forge*`) then re-import.
  - Idle workers disconnect after ~20 s lease — the installed
    `ida-codemode` defaults are patched to `keepalive=600`; takes effect
    after the MCP server restarts. Keep curation scripts in one execute
    either way.
  - IDA 9.4 lvar API: `cfunc.set_lvar_type` gone; use
    `modify_user_lvar_info(func_ea, MLI_TYPE, lvar_saved_info_t)` and
    pass the flag (without `MLI_TYPE` it silently fails). `lvar.type`
    is a callable. `rename_lvar` exists, `set_lvar_name` does not;
    `lvar.is_arg_var` is a property.
  - IDA 9.4 ctree: `cfunc.treeitems` empty; statement traversal uses
    `ctree_visitor_t.apply_to(body, None)` with the `visit_insn` hook;
    `cit_return` is 80 (not the older SDK's 78).
  - The plugin dir (`%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-forge`) is a
    symlink to `src/`; source fixes reach a live worker only after DB
    close/reopen or a module reload.
  - WER dumps: crashed idalib workers drop ~370 MB dumps in the plugin
    dir — delete after a crash storm.