# Changelog

All notable changes are tracked here. Format: date — change set (branch/commit).

## 2026-08-15 — R3.3 eval-task ground-truth gate

The eval agent was peeking at `tests/fixtures/c_pure_structs/` mid-run
(header-driven `add_member`, "because scanner output diverged from
fixture.h" — defeating the scan-first rules and making the gaps report
dishonest). The eval task doc now declares ground truth a HARD GATE:
- Rule 7: do not read `tests/fixtures/c_pure_structs/` (header, source,
  or any derived listing) during Recon/Recover/Apply — the header opens
  for the first time at Phase 4 (Score).
- Rule 5 / Phase 2: manual builds are a fallback only for scanner-blind
  spots proven from binary evidence (disassembly, decompilation, format
  strings, xrefs); "diverges from the header" is not a scanner failure —
  the header is the score sheet, not the analysis input.
- Scoring/Phase 4: the ground-truth table is built at Phase 4 only.

## 2026-08-15 — R3.2 recovery-eval gap-fix wave (F1–F7)

Recovery-eval round 2 gaps closed: four real fixes, one exercised-at-
probe feature, two documented IDA-inherent behaviors. 651 tests green
(baseline 632), ruff clean, live probe 7/7.

- **F1 pack**: store structures pack by default — every commit is
  `#pragma pack(push, 1)` (wrapped at the `Structure.set_cdecl` choke
  point; parse_decl gates strip the pragma, `idc_parse_types` accepts
  it). `create_structure(pack=N)` / new `set_pack(name, N≥1|None)` verb
  control the alignment; `pack` persists through the catalog
  serialize/deserialize round trip (legacy catalogs default packed) and
  `duplicate_structure` carries it.
- **F2 rename verb**: `rename_member(name, offset, new_name)` renames a
  COMMITTED IDB struct member (gap_* entries included) in place via
  `tinfo_t.rename_udm` — til-persistent, packed layout preserved (9.4
  live finding: there is no `update_named_type` on this build and
  `create_udt` re-aligns pack-derived offsets; older builds fall back
  to udt-rebuild + `update_named_type`, then the delete+re-file tail).
  Bit-unit udt offsets from `get_udt_details` are accepted. The store
  is untouched — rename after the last re-commit.
- **F3 function-pointer typedefs**: `create_typedef` write ladder now
  tries the declarator-name form (`typedef int (__cdecl *DispatchFn)
  (...);`) when `typedef <decl> <name>;` is rejected, before the
  hexrays fallback.
- **F4 scanner teleport**: `scan_from_allocation` on a helper-mediated
  row (callee set — the folded-size_hint shape included) decompiles the
  callee, resolves its returned-variable allocation through the E.22
  alias-chain machinery, deep-scans the callee, and merges both
  evidence sets by byte offset (higher score wins, ties to the callee).
- **F5/F6 documented**: Hex-Rays `lea`-only global member rendering and
  apply-span erosion notes added to the eval doc's "Forge state" list;
  the probe's double-apply reproduced no erosion — no code change.
- **F7 aliases completed**: the intN/uintN map now lands on IDA-native
  tokens in one pass (`u32`→`unsigned __int32`, `_DWORD`→
  `unsigned __int32`, ...); add_member accepts the shorthand.

## 2026-08-15 — R3.1 update-not-delete wave (eval round 3)

Agent-facing delete paths removed; committed types are updated in place.

- `remove_type` deleted from the facade (E.27 reverted): a committed
  type is the end state — fix layouts with `remove_members`/`add_member`/
  `set_member` and re-commit `create_type(overwrite=True)`.
- `undo_type` refuses when the commit created the type (no prior
  declaration) instead of calling `remove_type` — nothing deletes a
  committed type anymore.
- `remove_structure` raises ForgeApiError for structures committed to
  the IDB (store purge only for uncommitted WIP).
- `create_type(..., overwrite=True)` updates the til IN PLACE via
  `update_named_type` (fallback: old delete+recreate) — the ordinal
  survives, so applied globals and retyped locals never reference a
  deleted type (delete+recreate by ordinal dangled applied items on the
  9.4 idalib worker).

## 2026-08-15 — ALL-forge-TODOs closure wave (`726dd8b`, `01cee06`, `91b95a6`, `b93eaf1`, `cb55b3f`)

Every open item (R2.1–R2.6, E.13–E.29, F.1–F.8) implemented in the
facade + support modules; 632 tests green (was 577), ruff clean, eight
live probes green against the fixture worker.

### Parse / pack / apply (Phase A)
- `intN`/`uintN` member type aliases (R2.5); C-keyword member names
  fail loudly (`_validate_member_name`, R2.6).
- `Member.effective_size()` — pack-time sizes come from the FRESH pack
  tinfo; placeholder-size poison gone from `get_udt_member`,
  `build_cdecl`, `calculate_array_size` (R2.1, priority #1). Live:
  1-byte stored member packs at the child's real 40 B, no chain shift.
- `apply_type(redefine_range=True)` rewritten: DELIT_DELNAMES whole-
  span delete, `apply_tinfo(TINFO_DEFINITE)` + `auto_wait`, size
  verify/retry with an honest `warning`, base-name restore (R2.2/R2.3);
  3rd `del_items` argument pinned to the END ea (R2.4, recorder test).
  Live: `g_main_outer` 320 B / `g_static_grid` 16 B items persist over
  save/reopen; span-end sibling intact; `g_main_outer.name[16]` renders.
- `remove_type` (E.27, ordinal delete + TypeMirror cleanup).
- `undo_type` (E.17) with pre-commit cdecl snapshots in `create_type`/
  `finalize`/`push_type`.

### Non-UDT + unions (Phase B)
- `create_typedef` (E.29) — `typedef <decl> <name>;` via the pure IDB
  write, `ida_hexrays.create_typedef` fallback; live `DispatchFn` ok.
- Inline union member types (E.28) parse via the `<union> __forge_member;`
  branch; live `VariantT` 16 B with all four tags committed.
- Mirror honesty (E.26): `import_types` `skipped` is a
  `{name: reason}` dict; `refresh_types(include_names=)` adopts IDB
  names for synthesized store names.

### Scanning (Phase C)
- `deep_scan`/`shallow_scan(clear_first=)` (E.21).
- Helper-mediated allocation (E.22/I.25): callee-body alias chain
  (≤2 `v = w` hops) + pointer-return fallback row (`size_hint=None`,
  `callee` set); `scan_from_allocation` skips the void\* retype trick
  for helper rows. Live: `guess_allocation` on the fixture returns a
  HEAP row (calloc size folded to 40) and the scan commits.
- IAT-slot callee resolution (E.23) in `callees_of`/`function_info`;
  `scan_global` exclusive-tail extension (E.25); stride-run collapse to
  arrays (E.16); `name_members_from_printf` (E.14, live: PointerParent
  `parent`/`magic`/`count` from `log_msg` formats);
  `ScannedStructureMemberObject.apply_type` implemented (F.1).

### Orchestration + hygiene (Phase D)
- `recover()` (F.8+E.13) — scan → commit → root retype → reapply; live
  committed `DeepChainNodeR` and re-decompile renders member access.
- `reapply` (E.19); E.20 tweak batch (a–f); `decompile_many` (F.2);
  `scan_returned` (F.3, `iter_returned_exprs` moved to
  `forge.api.hexrays`); `export_store`/`import_store` (F.5);
  `forge.api.ctree_transform` DSL + `SilentIfSwapper` move (F.6);
  `backfill_lumina` (F.7); `split_flags` (E.18, byte-aligned only).
- Live 9.4 hardening found by the probes: treeitems statements expose
  no bodies — all statement walkers fall through to the ctree visit;
  `to_specific_type` is a property on live items (not a method) and
  `creturn.expr` carries the return value; printf format literals sit
  under casts and memptr bases carry lvar idx (name resolved from the
  lvar table).

## 2026-08-15 — recovery-eval round 2 (99/100) + skill/docs

### Evaluation
- Second full recovery pass on `pure_c_struct_fixture.exe` (cold-open,
  store never wiped): 20/20 types committed with exact layouts, 5/5
  globals rendering as structs, 10/10 function flows retyped —
  **99/100** vs `tests/fixtures/c_pure_structs/fixture.h` (report:
  `docs/forge_api_recovery_eval_output.md`). Scan half deliberately not
  used (E.22 wrapper shape + evidence-complete disassembly); store
  build / commit / apply / naming all ran through forge.
- Ranked gaps filed as R2.1–R2.7 in TODO.md: placeholder-size pack
  poison (R2.1, layout corruption when a member resolves to a 1-byte
  seed placeholder — re-commit does not recover it; `set_member`
  re-point + re-commit works), `apply_type(redefine_range)` silent skip
  on user-named heads (R2.2), idalib deferred-analysis re-split race
  (R2.3, robust path `del_items(DELIT_DELNAMES)` + `apply_tinfo` +
  `set_name`), `apply_type` del_items END-vs-size argument semantics
  eroding the .data tail (R2.4), `int32`/`uintN` silent parse drop
  (R2.5), C-keyword member names silently dropped (R2.6), E.22
  confirmed (R2.7). New open items E.28 (union member types — the
  `Variant` partial) and E.29 (non-UDT type creation — `DispatchFn`
  typedef needed an ida-domain redeclare).
- Task doc refreshed: cold-open determinism, post-`45b9d2a` forge
  state, explicit why/when for forge_api vs ida-domain
  (`docs/forge_api_recovery_eval.md`); skill published
  (`skills/ida-forge-api/SKILL.md`, mirrors `~/.agents/skills`).
- `g_banner` corrected `char[21]` → `char[22]` in the fixture IDB
  (only correction; everything else byte-exact vs source).

## 2026-08-13 — E-series bug fixes, round-2 review, recovery-eval gaps

### Correctness (E.1–E.11 — commits `4372b94`, `97b9474`, `8d8bd3c`)
- IDA 9.x drift: `idc.parse_decl` is the legacy 2-arg `(decl, flags)`
  form returning `(ret, tp, fld)` (live signature probe); `set_ti`
  removed → `apply_tinfo`; udt member offsets are BYTES (the `×8` bit
  convention broke create_field gap math); `cfunc.treeitems` empty on
  fresh 9.4 → ctree-visitor fallback (`visit_insn`, `apply_to`,
  `cit_return=80`) in guess_allocation's iterators; `tomllib` read-only
  (lazy `toml` import for writes).
- `to_vtable` → `vtbl_<addr>` fallback (no assert); `create_structure`
  seeds its own-name placeholder before the member loop (self/file refs
  survive); member decl_src tracked; pack heals `#NN *` ordinal refs +
  re-parses named-reference text (child size re-bind, inline parents);
  `imports()` walks the real IAT (module+name filters); `inverse_if`
  nearest-`cit_if` pick; `link_child` materializes child pointers;
  `finalize_all` rows carry `created_names` + `error`;
  `create_type(overwrite=False)` auto-replaces forge placeholders (real
  types still error); collision `member_name=` disambiguation.
- 14 new unit tests; all fixes live-verified on the fixture worker.

### Facade (round-2 review, commit `607c3ab`)
- `rename_ea(ea, name)` — the naming-core verb (`ida_name.set_name` +
  SN_NOCHECK, loud failure).
- `create_field` byte-offset + committed-til write via
  `idaapi.idc_set_local_type` (persists; live `type_of` shows the
  inserted member).
- Templated multi-arg keys: type-arg suffix synthesis
  (`std::vector<T>`/`std::map<K,V>` resolve to full cdecls).
- `nudge_members` loud unknown-offset errors.

### Safety / config
- **`clear_structures` removed from the facade** (`5a8da9e`) — the
  data-loss trap: eval agents wiped the shared netnode-persisted
  catalog the GUI structure-builder reads. Tests reset via the internal
  dict; guard test asserts no wipe verb exists.
- User config edit: `default_deep_scan_depth: 3 → 10` (`9bef000`).

### Recovery-eval gaps (commit `45b9d2a`, live-verified)
- Gap 1: keyword/parser commit errors are loud (`_commit_failure_reason`
  — `'inline' is a C keyword`).
- Gap 3: `deep_scan`/`shallow_scan` restore the root retype when a scan
  yields no evidence.
- Gap 4: `apply_type(redefine_range=True)` makes the WHOLE span one
  struct item (`create_struct` + `auto_wait`; 104-byte
  dispatch item confirmed live).
- Gap 5: pack re-parses named-reference text (inline-child size
  re-bind).
- Gap 6: `decompile(force=True)` already clears the cached cfuncs.
- Gap 2 = E.22 (helper-aware allocation) stays OPEN — see TODO.

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
