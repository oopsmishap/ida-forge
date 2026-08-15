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

Ground truth (for scoring ONLY, after the recovery pass is drafted):
`tests/fixtures/c_pure_structs/` — `include/fixture.h` is the full type
spec; `src/fixture.c` shows how the types flow. Do not open it during
recovery.

## Scoring

Build a ground-truth table from `fixture.h`: for each type — size, member
offsets, member names, member types; for each global — its type; for each
function — parameter types and the pointer types it passes around.

Score the final IDB state with an MCP script (read types via
`type_of`/`get_structure`/`decompile`, never by eyeballing):

- **Structs (60%)**: per struct — 40% layout (size + every member offset
  exact), 30% member names, 30% member types (pointer targets count: a
  `Kid *` member named `first` beats `u64` + `first`). All types from the
  header must be present and committed in the IDB.
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

## Forge state at this run (2026-08-13, post `45b9d2a`)

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
- `int32`/`uintN` shorthand does not parse in member types — use
  `__intN`/`unsigned __intN`. (R2.5.)

Your primary grind: committing your recoveries in the IDB so globals
render and pseudocode shows real member access.

One known gap (tracked as E.22): `guess_allocation`/`scan_from_allocation`
do **not** follow wrapper helper allocations (`v1 = chain_node_new(...)` —
the `calloc` sits inside the callee). Compensate with `deep_scan` +
disassembly of the helper, and report it as a found gap.

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
   `scan_from_allocation` are the primary mechanism for deriving layouts;
   manual member construction is a fallback for scanner-blind spots and
   must be listed in the report's gaps (type + missed-evidence reason).

## Phases

1. **Recon** — map functions, globals, and every printf format string
   (they carry member name evidence). Plan which section runner feeds
   which struct. (ida-domain work.)
2. **Recover** — every layout MUST come from scanner evidence: per
   section, drive `deep_scan` with a root type from the allocation site,
   or `scan_global`/`scan_from_allocation` where they fit; commit what
   the scanner derived. Hand-build/disassemble only what the scanners
   genuinely cannot see (helper-allocated nodes like `chain_node_new`,
   arrays, nested inlines) AND report each manual build — type, why the
   scanner missed it — in the gaps section. Name members from the
   format-string evidence (forge naming + idc reads).
3. **Apply** — `finalize`/`create_type` (children first), `apply_type(
   ..., redefine_range=True)` on every global region (one call covers the
   whole span),`set_lvar_types` on the section runners so the pseudocode
   renders struct access.
4. **Score** — the MCP scoring script vs the ground-truth table; fix
   anything fixable, re-score, re-commit.
5. **Report** — `docs/forge_api_recovery_eval_output.md` in this repo
   (round-1 lives at `H:/re/_random/c_structs/docs/forge_api_recovery_eval_output.md`)
   with: accuracy table (per struct/global/function + total %), every
   incorrect/missing item with the forge call that failed to produce it,
   and the ranked forge gaps (these feed the TODO list).

## Acceptance

- All `fixture.h` types committed in the IDB with exact layouts.
- All globals render as structs in `decompile`.
- ≥90% weighted accuracy overall — proven achievable: the instrumented
  run recovered 12/12 struct families (14 committed types), 14/14 user
  functions, and applied 3 global structs.
- Report ends with the ranked forge-gap list.