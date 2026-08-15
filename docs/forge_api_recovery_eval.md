# Forge API recovery evaluation — recover and apply ALL types

## Mission

Reverse the fixture's **type surface, completely**: every struct, every
global, and every pointer type flowing through functions. The type work
goes through the **forge_api facade**; everything else is plain IDA
programming. The final score measures only what was recovered vs ground
truth.

## Why forge_api (and when to use it)

forge_api is a **headless facade for the structure-builder / type-recovery
workflow** — it packages the plugin's store and scanners into
deterministic, executable calls: build a struct in the store
(`create_structure`/`add_member`), scan evidence out of decompiled code
(`deep_scan`/`scan_global`/`scan_from_allocation`), resolve collisions,
name things (`set_lvar_types`/`rename_local`/`rename_ea`), commit to the
IDB (`create_type`/`finalize`), apply to globals
(`apply_type(..., redefine_range=True)`), and mirror between store and
til (`push_type`/`import_types`/`refresh_types`). That is its whole job.

**It is not a general-purpose IDA replacement.** It deliberately leaves
analysis to the platform: disassembly, xrefs, strings, function discovery,
data reads, undo — everything outside the type workflow — is
**ida-domain API** (the `db`/`ida_domain` objects, `idc`, and raw `ida_*`
modules). Use the right tool per action:

| Action | Tool |
|---|---|
| Build/edit a store structure, scan it, name members, commit its type, apply it to a global, retype locals, rename functions | **forge_api** verbs |
| Disassemble, walk xrefs, read strings/data, enumerate functions/segments, auto-analysis, output, file I/O, anything not type-shaped | **ida-domain** (normal IDA usage) |
| A type operation forge cannot do (or does wrong) | ida-domain, and note it in the report |

There is no "break-out" accounting and no penalty for ida-domain — the
report's interest is only whether *type* recovery had gaps.

## Target

`H:/re/_random/c_structs/pure_c_struct_fixture.exe` — open it **cold via
`ida_open_database` (the .exe, not any existing .i64)**. The cold .exe is
what gives you a deterministic, empty store and an unverified til — treat
every type in a reused .i64 as unverified and rebuild it anyway.

> There is **no store-wipe verb** — `clear_structures` was removed
> (2026-08-13: eval agents used it to erase the persisted catalog the GUI
> structure-builder reads). Determinism comes from opening the .exe cold,
> never from clearing. If you must run against a warm .i64, start by
> rebuilding the store from the til via `import_types()` and treat every
> imported structure as unverified.

> **HARD GATE — ground truth is OFF-LIMITS until Phase 4 (Score).**
> `tests/fixtures/c_pure_structs/` (`include/fixture.h` = the full type
> spec; `src/fixture.c` = how the types flow) is scored-against truth.
> It sits IN THIS REPO — do not open it for member lists, offsets,
> names, sizes, placements, or "what the scanner missed". Opening it
> before the final IDB state is committed invalidates the run: member
> sets found by peeking are not recovered evidence, and builds justified
> by the header must be recorded as gaps (type + "resolved from
> ground truth, not binary evidence"). Judge scanner weakness ONLY from
> the binary: disassembly, decompilation, format strings, xrefs.
> The header opens for the FIRST time at Phase 4, after Apply.

## Scoring

Build a ground-truth table from `fixture.h` — **at Phase 4, AFTER the
recovery+apply passes are committed** (the Phase 4 Score step; never
during 1-3): for each type — size, member offsets, member names, member
types; for each global — its type; for each function — parameter types
and the pointer types it passes around.

Score the final IDB state with an MCP script (read types via
`type_of`/`get_structure`/`decompile`, never by eyeballing):

- **Structs (60%)**: per struct — 40% layout (size + every member offset
  exact), 30% member names, 30% member types (pointer targets count: a
  `Kid *` member named `first` beats `u64` + `first`). All types from the
  header must be present and committed in the IDB. A struct whose
  recovery transcript shows NO scanner call (`deep_scan`/`shallow_scan`/
  `scan_global`/`scan_from_allocation`) before its manual work caps at
  50% of the struct bucket — the scanners are the builder, manual
  construction is the documented fallback, not the default.
- **Globals (20%)**: each global renders as its struct type
  (`apply_type(..., redefine_range=True)` — this now covers the WHOLE
  byte span as one struct item, no manual `create_struct` needed), arrays
  recognized (`u32[2]`, `Stack2[2]`), no stray qword/blob fallbacks in
  `decompile`.
- **Pointer flow (20%)**: locals/args carrying the recovered types are
  retyped (`set_lvar_types`) and the decompiled pseudocode shows member
  access (`parent->magic`, `node->payload[0]`) — sampled over the
  functions in `fixture.c`'s section runners.

Report per-item exact/partial/missing with evidence (call + output), and
a final percentage.

## Forge state at this run (2026-08-15 — R3.1 update-not-delete; earlier: post `45b9d2a`)

Working as intended — do not work around these:

- Commit failures are loud: `create_type`/`finalize` errors name C
  keywords and parser error counts (`'inline' is a C keyword — rename the
  structure`). A type tag `inline` cannot be created — rename it.
- `deep_scan`/`shallow_scan` restore the root's previous type when the
  scan yields no evidence, so a failed scan leaves no retype behind.
- Re-committing a parent after its child struct changed re-binds member
  types automatically (inline children included) — but ONLY when the
  parent pack already knew the child sizes. If a member was added while
  its type was still the 1-byte seed placeholder, the wrong size is
  baked into the layout and re-commit does NOT recover it: re-point the
  member (`set_member(parent, off, type=child)`), then re-`create_type`.
  (R2.1: this exact poisoning chain-shifted `Outer`'s grid/dispatch/
  stacks.)
- `apply_type(..., redefine_range=True)` skips the full-span item when
  the head already has a user name — apply before naming, or use
  ida-domain `del_items(DELIT_DELNAMES)` + `apply_tinfo(TINFO_DEFINITE)`
  + `set_name`, which also survives the idalib re-split race. (R2.2/R2.3.)
- `apply_type`'s `del_items` cleanup takes an END offset, not a size —
  overlapping spans can erode the .data tail; keep applications to
  non-overlapping ranges. (R2.4.)
- `int32`/`uintN`/`_DWORD` shorthand parses in member types — the
  R2.5 alias map now runs all the way to IDA-native tokens
  (`uint32` ≡ `unsigned __int32`, `_DWORD` ≡ `unsigned __int32`,
  `int64` ≡ `__int64`, ...). (R2.5 + R3.2 F7: aliases complete.)
- Store structures pack byte layouts by default (R3.2 F1): every commit
  is `#pragma pack(push, 1)`; `create_structure(..., pack=N)` or
  `set_pack(name, N)` (N ≥ 1) changes it, `set_pack(name, None)`
  restores natural alignment.
- Committed-member names — including the `gap_*` auto-fill entries the
  store never held — rename via `rename_member(name, offset, new_name)`
  (R3.2 F2). The store is NOT changed: rename AFTER the last
  `create_type(overwrite=True)` re-commit, or the rename is lost.
- Scan evidence is visible and persistent (R3.5/R3.6/R3.8):
  `scan_sites(name)` lists every recorded site (func_ea/var, stored in
  the IDB's netnodes — survives worker drops and warm reopens), and
  every `create_type`/`finalize` result reports `applied_sites` — the
  sites the pointer type was actually applied to on that commit. After
  a reopen the LIVE scan objects are gone but the rows survive, so the
  commit RE-APPLIES from the persisted rows (locals by func_ea+var,
  globals by ea) — the GUI's "apply across scanned locations" works
  across sessions. An `applied_sites: []` with sites recorded means the
  evidence is not attached — re-scan into the store structure, then
  commit; `reapply(name)` re-runs the apply step. Void-typed members
  are skipped at pack time with a named warning (IDA's "Void type is
  forbidden here" is undiagnosable), and per-site apply failures warn
  instead of vanishing silently.
- Hex-Rays only renders global member access when the reach is
  `lea reg, stru_xxx.field`; literal-address `qword_...` operands stay
  untyped (compiler artifact — workaround: apply the type at the
  instance EA used by the majority of accesses). (F5, IDA-inherent.)
- **Update, never delete (R3.1):** `remove_type` no longer exists;
  `undo_type` refuses when there is no prior declaration to restore;
  `remove_structure` raises for any structure committed to the IDB.
  Layout corrections are in-place edits (`remove_members`/`add_member`/
  `set_member`) followed by `create_type(..., overwrite=True)`, which
  now UPDATES the til in place (`update_named_type`) — the ordinal
  survives, so applied globals and retyped locals never dangle.
- The headless store IS the store the GUI structure-builder reads (one
  shared catalog, persisted in the DB's netnodes) — a structure created
  with `create_structure` shows in the builder on a warm GUI reopen; a
  headless run simply has no form open. Save the DB (`save_database`)
  before the worker drops or the last edits are lost.

Your primary grind: committing your recoveries in the IDB so globals
render and pseudocode shows real member access.

One known gap (tracked as E.22, closed by R3.2 F4): wrapper-helper
allocations (`v1 = chain_node_new(...)` — the `calloc` sits inside the
callee) are now followed: `scan_from_allocation` teleports into the
helper's body, finds the allocator feeding its first returned lvar, and
scans there too (both evidence sets merge by offset). The manual
`deep_scan` + disassembly compensation applies only to helpers whose
allocator cannot be proven statically (no returned-lvar allocation) —
report those as found gaps.

## Rules

1. Type workflow first: whatever the recovery task needs that forge
   already does, use forge's verbs. Stop short of fighting forge for
   things it genuinely lacks — the score counts the end state, not the
   purity of the toolchain.
2. ida-domain (`db`, `idc`, raw `ida_*`) is the general-purpose API and
   is in play at all times. Use it for recon, disassembly, strings, data
   reads, and for any type operation forge can't do (report those).
3. One script per execute — idle workers drop after ~20 s lease; a drop
   is a clean re-run (cold-open determinism), not a loss.
4. When forge gets a type wrong (wrong member set/offsets), fix it in the
   store and re-commit (`create_type(overwrite=True)`) — the point is the
   end state, not the path.
5. Scan tools are the builder: `deep_scan`/`scan_global`/
   `scan_from_allocation` are the primary mechanism for deriving layouts
   — run them first and record their output, whatever it produced.
   Manual member construction is a fallback ONLY for scanner-blind
   spots proven from binary evidence (disassembly, decompilation,
   format strings, xrefs) — never from the header — and each manual
   build must be listed in the report's gaps (type + missed-evidence
   reason). Divergence from the header is NOT a scanner failure: the
   header is the score sheet, not the analysis input.
6. **Update, never delete** (R3.1): there is no type-delete verb —
   `remove_type` is gone, `undo_type` refuses to delete a type the commit
   created, and `remove_structure` raises once the structure is committed
   to the IDB. Fix layouts in place (`remove_members`/`add_member`/
   `set_member`) and re-commit with `create_type(..., overwrite=True)` —
   overwrite is now an in-place til update, so applied globals and
   retyped locals keep referencing the type.
7. **Ground truth stays closed until Phase 4.** Do not read
   `tests/fixtures/c_pure_structs/` (header, source, or any derived
   listing of it) during Recon/Recover/Apply — not for names, offsets,
   sizes, member sets, or "what the scanner missed". Ground truth is
   the SCORE SHEET only; opening it mid-run makes every hand-built
   member a scored-against-self cheat and the report's gaps dishonest.
   If you find the analysis stuck, iterate on binary evidence; the
   header opens at Phase 4, and not before. (R3.3)

## Phases

1. **Recon** — map functions, globals, and every printf format string
   (they carry member name evidence). Plan which section runner feeds
   which struct. (ida-domain work.)
2. **Recover** — every layout MUST come from scanner evidence, in this
   ORDER per struct: (a) run the scanner first — `deep_scan` with a root
   type from the allocation site, or `scan_global`/`scan_from_allocation`
   where they fit; (b) record the call's output in the report, whatever
   it produced (even "no evidence" rows count as the attempt);
   (c) **check coverage** — `scan_sites(name)` lists every recorded
   evidence site (persisted in the IDB's netnodes, so it survives
   drops); when the struct is used elsewhere (other allocation sites,
   `callers_of`/`callees_of` of the runner, globals by xref) and the
   list misses them, scan those roots INTO the same store structure
   (`deep_scan(..., structure=name)`); (d) `auto_resolve` collisions,
   trim junk (`remove_members`/`set_member(enabled=False)`), name
   members from format-string evidence (`name_members_from_printf`);
   (e) only then hand-build/disassemble what the scanners genuinely
   cannot see (helper-allocated nodes, arrays, nested inlines), judged
   from the BINARY alone (disassembly, decompilation, format strings,
   xrefs — the header stays closed per Rule 7) and report each manual
   build — type, why the scanner missed it — in the gaps section;
   (f) **commit with the evidence attached** — `create_type` applies
   the pointer type at every recorded scan site (the same apply step
   the GUI form runs); its result's `applied_sites` must be non-empty
   when scans recorded evidence — a commit reporting `applied_sites:
   []` means the scans were NOT attached to this store structure
   (hand-rebuilt members carry no scan objects): re-scan into the
   structure before committing. `reapply(name)` re-runs the apply step
   after any re-commit. (R3.5/R3.6.)
3. **Apply** — `finalize`/`create_type` (children first), `apply_type(
   ..., redefine_range=True)` on every global region (one call covers the
   whole span),`set_lvar_types` on the section runners so the pseudocode
   renders struct access.
4. **Score** — the ground-truth table is built HERE, from
   `tests/fixtures/c_pure_structs/` — the FIRST time the header may be
   opened (Rule 7); score the final IDB state with the MCP script vs
   that table; fix anything fixable (recovery edits still count as
   recovery — re-commit before scoring again), re-score, re-commit.
5. **Report** — `docs/forge_api_recovery_eval_output.md` in this repo
   (round-1 lives at `H:/re/_random/c_structs/docs/forge_api_recovery_eval_output.md`)
   with: accuracy table (per struct/global/function + total %), every
   incorrect/missing item with the forge call that failed to produce it,
   the ranked forge gaps (these feed the TODO list), and a one-line
   attestation: "ground truth opened at Phase 4 only" (Rule 7) — any
   earlier opening must be named with the phase it happened in and the
   builds it influenced.

## Acceptance

- All `fixture.h` types committed in the IDB with exact layouts.
- All globals render as structs in `decompile`.
- ≥90% weighted accuracy overall — proven achievable: the instrumented
  run recovered 12/12 struct families (14 committed types), 14/14 user
  functions, and applied 3 global structs.
- Report ends with the ranked forge-gap list.