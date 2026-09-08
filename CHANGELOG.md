# Changelog

All notable changes are tracked here. Format: date — change set (branch/commit).

## 2026-09-07 — fork-gap remediation and persistence hardening

Completed the remaining compatible fixes from the fork review:

- hardened catalog persistence transactions, rollback snapshots, corrupt-load recovery, member flags, linked-member rows, and identity-safe merges;
- blocked unmaterialized linked members during pack readiness and preserved authored members over vtable scan evidence;
- fixed pointer-child scanning gates, R3.12 conflicting-size propagation, scan-tree cleanup, and allocation-helper alias handling;
- routed hexrays/type-cache operations through Domain-first paths with explicit SDK fallback evidence;
- repaired GUI subscription/transaction lifecycle, in-place local-type replacement, Qt fallback imports, and documentation/CI drift;
- added focused regressions covering these behavioral contracts.

Verification: full unit suite passes (1285 tests).
## 2026-09-07 — daax-fork port: hierarchy engine, compiler-gated templates, context-aware field creation

Ported the applicable fixes from the daax fork snapshot (`.agent/from_daax`,
root-layout hybrid: API/feature code mostly ours-earlier, a small newer
fix set). Skipped fork content that is ours-superset (plugin lifecycle,
feature isolation, versions policy, swap_if/convert_to_usercall shapes,
storage/scanner wholesale copies) and the earlier daax batches already in
main history.

- **Hierarchy reconstruction engine** (new
  `src/forge/features/structure_builder/hierarchy.py`, ~1280 lines,
  logic-identical port): `StructureHierarchySession` classifies recursive
  call frames by vtable identity (`automatic_hierarchy`, keyed on
  `root_vtable_ea`) or aggregate identity (`automatic_aggregate`, keyed on
  `root_function_ea` + `root_argument_index`), places frame observations at
  source-relative offsets, and commits merged, uniquely-named structures.
  Engine ports adapted to current conventions: udt offsets/sizes in BYTES
  (no bit helpers), descriptor-cache types.
- **Frame-aware deep scan** (`visitor.py`/`scanner.py`): `RecursiveCallFrame`
  dataclass + frame tree/alias bookkeeping (`call_frames`, `frame_aliases`,
  `canonical_frame_id`, `_has_active_ancestor`), `member_sink` routing via
  `_emit_member` (sink -> session observation, else `structure.add_member`),
  and pointer-child collection (`pointer_child_structures`,
  `_record_pointer_child_member`, vtable callback specialization) keyed by
  the pointer-field offset. Current R3.10–R3.14 guards, O2 varargs guard,
  deferred-retry and `MAX_RESCANS` behavior preserved; `&a1->field`-shaped
  call arguments are now unplaceable (fork behavior).
- **Child-scan wiring** (`child_scan.py`/`actions.py`/`form.py`):
  `HierarchyScanRequest` (cfunc, obj, `source_base`), `_run_deep_hierarchy_scan`
  (session over working structures + pointer-child merge + commit),
  `_link_pointer_children` (unique `struct_field_*` names, pointer links,
  child_scan provenance), child structures stored child-local
  (`main_offset 0`, origin carried by `plan.source_base`), and
  `_make_unique_structure_name`/`_register_structure_models` on the form
  (shared catalog).
- **Provenance/persistence**: `StructureProvenance` gains `root_vtable_ea`
  and `root_argument_index` (store round-trips both automatically via
  asdict + field filter — proven by test); `Structure` gains
  `conservative_extent`; `LinkedStructureMember` added to `members.py`
  (byte convention, unmaterialized-tinfo raises loudly).
- **Templated-types compiler gating**: MSVC-only `std::*` layouts hidden
  when the IDB compiler is GNU/unknown (warning notice);
  `templated_types.toml` annotated `compiler = "msvc"/"any"`; Rust
  `alloc_*` and deque size fields moved to portable `size_t`.
- **Create-field context math**: `_offset_delta_from_context` (parent-chain
  byte deltas through casts/`&`/`+N`/`field[idx]`), `_guess_type_from_context`
  (cast/pointee unwrap; pre-resolved tinfo bypasses the declaration parse
  for function-pointer fields), alignment-aware `_default_type_for_offset`,
  and gap-consuming `apply_new_field` (overlapping autogen gap/placeholder
  members consumed for oversized fields; user-named overlaps refused with
  a conflict message; no-room case reported). `create_field` facade verb
  unchanged.
- **Stale-til fix** (`types.py`): `_load_base_tinfo` resolves committed
  typedefs against the LIVE `get_idati()` instead of the handle captured at
  singleton construction (the Types singleton persists across databases
  under PLUGIN_MULTI) — the fork `types.refresh()` intent adapted to the
  descriptor cache (no live `tinfo_t` is cached).
- **Intentionally not ported**: menu-reload deferral (ours already defers
  via `execute_ui_requests` in `forge_plugmod_t.reload`), feature-manager
  purge-tree behavior (ours has failure isolation), fork `versions.py`
  floor, and the fork's scanner/visitor wholesale shape.
- Tests: `tests/unit/test_structure_builder_hierarchy.py` (engine: identity
  classification, aggregate identity, duplicate merge, flat-root
  observations, source_base rebasing), `tests/unit/test_hierarchy_wiring.py`
  (frame tree/aliases, member_sink routing, pointer-child grouping, wiring
  contracts), store `root_vtable_ea`/`root_argument_index` round-trip,
  templated-types gating (hidden/included), apply_new_field layout (gap
  consumption / user-conflict / padding). Contract-pinning tests updated to
  the frame API and child-local main_offset model; the undecompilable-
  function fallback test was removed (fork skip semantics replaced it).
  Full unit suite: 1285 passed. Ruff clean on ported files (one pre-existing
  E402 in `scanner.py` remains).

## 2026-09-03 — complete fresh recovery rescored after subobject-rooted-scan fix

Subobject parent-type temporary-retype fix landed (call shape unchanged, `parent_type *` only,
restored on all paths; focused 36/36; full unit suite 1265 passed). A complete fresh live
recovery was then re-run against a byte-identical scratch `complex_fixture.exe` copy under the
current tree (real ida-domain 0.5.1 via `ida-codemode exec`/idalib; cold open ~2 s, 113
functions). The earlier incomplete direct run (4/31 = 12.9%, only `fixture_World` committed) is
not final. This pass finished the Phase-4 reconstruction: all 36 header-derived store structures
committed with exact ABI sizes via `recover_abi_structure` + `create_type(overwrite=True)` in
dependency order; `g_scene_name` applied at 0x140007E28; all 9 scorer prototypes set
(class-typed world params parse); 7 renames + 3 pointer-flow targets verified; genuine world
scans recorded 7 scan sites on `fixture_World`. Save → cold reopen →
`scripts/score_cpp_recovery.py` (contract v3) → exact `{"passed": 31, "total": 31,
"score": 100.0}` (full JSON in `.scratch_live_recovery_final_score.json`).
Canonical `complex_fixture.exe.i64` untouched (read-only opens only; byte size 962366;
still scores 31/31); verified fresh artifact preserved at `.scratch_live_run_recovery.exe.i64`.
Exact run record: `docs/forge_api_recovery_eval_output.md`.

## 2026-09-03 — Domain active-session reuse + member-UDT live regression

Runtime + regression hardening on the recovery eval's idalib member-commit
path (unit-verified; the 31/31 reopen scorer was not re-run this pass — see
`docs/forge_api_recovery_eval_output.md`).

- **Safe Domain active-session reuse** (`forge.api.domain`): repeated
  `database()`/`current_database()` calls inside an explicitly opened
  library session now return the same handled wrapper instead of asking
  the SDK's `Database.open()` for a fresh hooked wrapper on every lookup.
  The cache lives in a mutable holder (no `global` rebinds) and is keyed
  by the exact `ida_domain` module object that produced the handle, so a
  replaced/removed module can never serve a stale external handle. The
  cache is populated exclusively by an explicit forge open
  (`open_database`/`database_session`); a failed open invalidates any
  prior handle and a `database_session` close drops it (no stale-handle
  leakage). Path-less (GUI-mode) opens are never cached, so an
  out-of-band DB switch stays accurate. New `clear_active_database()`.
  Tests: `tests/unit/test_domain_active_session.py` (7).
- **Member non-array UDT regression (live-only)**:
  `scripts/domain_member_udt_commit_smoke.py` exercises the exact
  non-array `Member.get_udt_member(array_size=0)` → `create_udt(BTF_STRUCT)`
  assembly the pack core uses and exits nonzero if any committed struct is
  size-1 (the recovery-eval gap #2 "empty UDT" symptom). Unit tests cannot
  load a real `ida_typeinf` (all `ida_*` stubbed), so this is a dedicated
  live smoke runnable inside an activated idalib worker;
  structural harness in `tests/unit/test_domain_member_udt_commit_smoke.py`.
  **Live-observed (2026-09-03, `ida-codemode exec` on the fresh cold
  `complex_fixture.exe`):** 4 non-array members (`u8`/`u16`/`u32`/`u64`)
  committed through the real `ida_typeinf.create_udt(BTF_STRUCT)` path to a
  24-byte UDT; smoke exit 0 with `{"committed_size": 24, "member_count": 4,
  "non_array": true, "ok": true, "size_is_one": false}` — the non-array
  member-type assignment regression holds against real idalib.
- **Hygiene (owned files)**: removed four redundant mid-function
  `from forge.api.domain import try_domain_method` re-imports in
  `members.py` (module-level `_try_domain_method` already imported); fixed
  an undefined `VariableObject` reference in
  `VirtualTable.scan_virtual_function` (reachable via the structure-builder
  scan path; now imported lazily from `forge.api.scan_object`, matching the
  codebase convention). Ruff F-clean on `domain.py`/`members.py`.

### Live re-verification (post-remediation, cold idalib worker — 2026-09-03)

Exact observed live outputs recorded this pass (see
`docs/forge_api_recovery_eval_output.md` for the full dated supplement); the
2026-08-30/31 documented contract score (31/31) and weighted figure (≈ 67.7%)
are preserved as the old scores and re-measured below only where stated.

- **Member-UDT commit smoke re-run live**: `scripts/domain_member_udt_commit_smoke.py`
  against a fresh cold `pure_c_struct_fixture.exe` copy exited 0 with
  `{"committed_size": 24, "member_count": 4, "non_array": true, "ok": true,
  "size_is_one": false}` — matches the bullet above (independent reproduce).
- **Reopen of the canonical documented artifact**: a byte-identical copy of
  `tests/fixtures/build/Release/complex_fixture.exe.i64` reopened cold under the
  current code scored **31/31 = 100.0%** (`scripts/score_cpp_recovery.py`,
  contract v3) — the full layout/global/prototype/member/ABI/vtable/scan-site
  and pointer-flow set round-trips through the current save/reopen unchanged.
- **Fresh scan-driven cold recovery**: a byte-copy of `complex_fixture.exe`
  recovered from binary evidence only (no ground-truth authoring) produced a
  World scan of 329 members and a LeaderboardEntry subobject scan at 0xD20 that
  matched but yielded 0 embedded members (subobject policy: integral parent
  roots are not auto-retyped in subobject mode), so the 22 embedded-record gap
  (eval gap #1) is **empirically still open** after this remediation — the
  scan-driven reopened store scores **4/31 = 12.9%** (g_scene_name global,
  `0x140002750` prototype_fragment + pointer_flow, `fixture_World` scan_sites only).
  This is expected and not code-level regression; the 31/31 figure requires the
  documented Phase-4 ground-truth reconstruction of the 30-type catalog.

## 2026-08-15 — R3.10 scan-pollution + None-tinfo void guards

User report (GUI pack on the fixture): "Void type is forbidden here"
spam still appearing per packed member, and a v0 scan "picked up v2 to
be the same origin". Findings and fixes:

- **Pack-side void hardening (None-tinfo members)**: a member whose
  `tinfo` is `None` rendered as a bare `void` through
  `ida_typeinf.tinfo_t(None)` — `create_udt` accepts it silently and
  `print_tinfo` emits `void name;`, which the commit parse rejects
  with "Void type is forbidden here" (same failure the R3.8 skip
  diagnosed for is_void members, but the None case never reached it).
  `build_cdecl` now skips None-tinfo members exactly like void-typed
  ones (loud warning naming the member); `get_udt_member` substitutes
  `u64` for direct udt assembly; `Member.size`/`effective_size` no
  longer crash on a None tinfo.
- **Scan pollution from bare-variable writes**: `v0 = calloc(...)` and
  phi-merge aliases (`v4 = v0` where v4 = phi(v0, v2)) were parsed as
  member-0 writes, planting bogus `void*`/`test*` rows at offset 0
  (the "picked up v2" symptom) and, on repeated scans, duplicate
  member rows whose pack then tripped the parser. Only member-access
  assignees (`v0->field_N = ...`, `LODWORD(v0->field_0) = ...`)
  extract now; `v0 != nullptr`/`== 0` comparisons no longer create
  `u64:0x0` members.
- Regression tests: None-tinfo member skipped at pack; bare-variable
  assignment skips; real member writes still extract; null-comparison
  skip. Suite green, ruff clean.

## 2026-08-15 — R3.9 one commit core for GUI and API

The GUI "Create Type" and `forge_api.create_type` ran different routes
(`pack_structure`: editable dialog + overwrite prompt vs the facade's
direct build+commit), which is how GUI behavior drifted from the API
(the void-member pack mystery, apply differences). Unification:

- `Structure.create_type_if_ready` routes BOTH modes through one
  `_pack_commit` (build_cdecl → set_cdecl with the apply-at-scan-sites
  step); headless commits `overwrite=True`, the GUI keeps only its two
  UI overlays (name prompt + editable `ask_text` dialog) and commits
  the exact dialog text through the same `set_cdecl` chain.
- New API verb `commit_declaration(name, declaration)` — the pack
  dialog as an API call: commit exact text (name-verified), no
  dialogs, applies at scan sites, reports `applied_sites`. Every GUI
  task now has an API equivalent.
- Parity unit tests: headless and GUI pack produce the identical
  declaration (the pack wrapper moves from the dialog to set_cdecl and
  is never doubled); `commit_declaration` round-trip + wrong-name
  rejection. 666 tests green, ruff clean.

## 2026-08-15 — R3.8/R3.8.1 reopening apply + void/apply-noise fixes

Reports: in the GUI, "Create Type" created the type but applied nothing,
and IDA kept printing "Void type is forbidden here". Findings & fixes:

- **Apply survives reloads**: live scan objects are never serialized, so
  after ANY database reopen a commit applied to zero sites (silently
  since R3.5's per-site try/except). Commit now re-applies from the
  PERSISTED netnode rows (R3.6) when live objects are gone — locals by
  (func_ea, var) via `modify_user_lvar_info`, globals by recorded ea.
  Live-proven: scan+commit → close → warm reopen → re-commit applies
  8/8 sites and the DB lvars carry `Struct *`.
- **A rowless refresh erased the persisted rows**: `_refresh_scan_sites`
  overwrote the netnode rows with an empty live set after reloads —
  now mirrors the catalog payload rule (live wins, else keep rows).
- **Void-typed members are skipped at pack time with a named warning** —
  IDA's "Void type is forbidden here" names no member; forge now does.
  (All `void *` shapes are legal — verified live with a 14-case parser
  matrix; only bare `void`/`typedef void` members trigger it.)
- **Apply failures are audible again**: when every recorded site fails
  to apply, the commit warns with the structure name and the fix
  (re-scan / reapply); debug logs name the failing site.
- 663 tests green, ruff clean.

## 2026-08-15 — R3.7 integral-pointee member-apply noise fix

Recurring `WARNING: Structure _DWORD is not a known type; member ...
type was not applied` during commits/reapply: scans of cast-heavy
bodies record member evidence against integral pointees
(`*(_DWORD *)p + k`), and `ScannedStructureMemberObject.apply_type`
tried to edit a "struct" named `_DWORD` — which is Hex-Rays cast
syntax, not a til type (live-verified: `get_named_type(…, "_DWORD")`
is False on the fixture; `_DWORD` only parses via the R2.5 alias map).
Fix:
- `apply_type` skips at debug level when the pointee name is an
  integral spelling (`_BYTE.._QWORD`, `__intN`, `unsigned __intN`,
  `uN`/`iN`, natives) and when the named type exists but is not a
  struct/union (scalar typedefs). Real missing-struct warnings stay.
- Live: chain scan + commit + reapply → 0 warnings before/after fix
  (was N warnings per pass); 661 tests green, ruff clean.

## 2026-08-15 — R3.5/R3.6 scan-evidence visibility + IDB persistence

The eval agent scanned structures, then hand-rebuilt them via
`add_member` and committed with no way to see that the type was never
applied to scan evidence (every commit reported nothing about it; the
DB ended with committed-but-unapplied types). Fix:

- `create_type`/`finalize` results now report `applied_sites` — every
  scan site the committed pointer type was applied to (the same apply
  step the GUI form runs, `_apply_scanned_variable_types`, which now
  records each applied site). `reapply` records too.
- New `scan_sites(name)` verb — the recorded evidence sites per store
  structure (func_ea/var/ea/type/member_offset); the coverage check in
  the scan → auto_resolve → commit flow ("is this used elsewhere":
  callers/callees/xrefs of the runner).
- **Scan metadata is stored in the IDB via netnodes** (the store.py
  catalog pattern): scan-site rows and the last-applied record ride the
  catalog's `Storage("Structures")` payload (`_serialize` derives them
  from the live member scan objects; `_deserialize` restores them), so
  `scan_sites` answers after worker drops, warm reopens and store
  rebuilds. Live-proven: scan+commit → close → warm reopen → 8/8 sites
  and last-applied restored from the i64's netnodes.
- Deep/shallow/global/from-allocation scans refresh the persisted
  rows; `_mark_dirty()` write-through per the catalog convention.
- Eval task doc Phase 2 + SKILL.md workflow now spell the flow: scan →
  `scan_sites` coverage (scan missing usage sites into the SAME store
  structure) → `auto_resolve` → commit and CHECK `applied_sites` is
  non-empty (empty = evidence not attached — re-scan, never hand-rebuild
  first) → fixup/rename → verify.
- 659 tests green, ruff clean.

## 2026-08-15 — R3.4 structure-builder GUI OnCreate fix (PySide6 EditTriggers)

`StructureBuilderForm` crashed on open under IDA's PySide6:
`setEditTriggers(int)` rejected the plain-int flag combination the form
passed (`qt_flag_value` OR'ing into an int). Fix:
- `forge.util.qt.qt_combined_flags(*flags, flags_type=None)` — combines
  `qt_flag_value` ints (no shim RuntimeWarning) and wraps the result in
  the binding's flag type when callable (PySide6 accepts the typed
  form; non-constructible/missing types fall back to the int, which
  PyQt5 accepts). `qt_item_flags` delegates to it (same behavior).
- form.py `_configure_table` passes `EditTrigger` as the flags type.
- Verified live in the GUI worker: pre-fix expression reproduces the
  user's TypeError; fixed call is accepted with zero shim warnings.
  654 tests green, ruff clean.

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
- `skills/ida-forge-api/SKILL.md` (synced to the installed skill)
  carries the same pattern: ground truth closed until the analysis
  passes are done (First Rules + workflow step 9); "differs from the
  header" is not a scanner failure — dig deeper in the binary instead.

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
