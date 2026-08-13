# Forge API recovery evaluation — recover and apply ALL types

## Mission

Reverse the fixture's **type surface, completely**: every struct, every
global, and every pointer type flowing through functions. This is not a
feature-exercise (that was rounds 1–2). Forge API is the type toolchain —
use it to **recover, apply, and rename types**; ida-domain may be used
freely for anything else, and no "break-out" accounting is required. The
score is the only thing that matters: recovered vs ground truth.

## Target

`H:/re/_random/c_structs/pure_c_struct_fixture.exe` — open it **cold via
`ida_open_database` (the .exe, not any existing .i64)** so the IDB is
fresh; if a prior .i64 is used anyway, treat every existing type as
unverified and rebuild it.

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
  (`apply_type(..., redefine_range=True)`), arrays recognized (`u32[2]`,
  `Stack2[2]`), no stray qword/blob fallbacks in `decompile`.
- **Pointer flow (20%)**: locals/args carrying the recovered types are
  retyped (`set_lvar_types`) and the decompiled pseudocode shows member
  access (`parent->magic`, `node->payload[0]`) — sampled over the
  functions in `fixture.c`'s section runners.

Report per-item exact/partial/missing with evidence (call + output), and
a final percentage.

## Rules

1. Forge first for the **type verbs** (create_structure/add_member/
   deep_scan/scan_global/scan_from_allocation/guess_allocation/
   create_type/finalize/apply_type/set_lvar_types/rename_local/rename_ea).
   If a type verb is missing or broken in forge, do it via ida-domain and
   note it — that note is a finding, not a penalty.
2. Everything else (function discovery, disassembly, string reads,
   name cleanup) is free-form: ida-domain, idc, raw ida_*.
3. One script per execute — idle workers drop after ~20 s lease; the
   store replays deterministically, so a drop is a re-run, not a loss.
4. When forge gets a type wrong (wrong member set/offsets), fix it in
   the store and re-commit (`create_type(overwrite=True)`) — the point is
   the end state, not the path.

## Phases

1. **Recon** — map functions, globals, and every printf format string
   (they carry member names). Plan which section runner feeds which
   struct.
2. **Recover** — per section: find the allocation site /
   `scan_from_allocation` or `deep_scan` with root retype; hand-build
   what the scanners miss (arrays, nested inlines); name members from
   the format-string evidence.
3. **Apply** — `finalize`/`create_type` (children first), `apply_type`
   on every global region, `set_lvar_types` on the section runners so
   the pseudocode renders struct access.
4. **Score** — the MCP scoring script vs the ground-truth table; fix
   anything fixable, re-score.
5. **Report** — `docs/forge_api_recovery_eval_output.md` with: accuracy
   table (per struct/global/function + total %), every incorrect/missing
   item with the forge call that failed to produce it, and the ranked
   forge gaps that caused misses (these feed the TODO).

## Acceptance

- All `fixture.h` types committed in the IDB with exact layouts.
- All globals render as structs in `decompile`.
- ≥90% weighted accuracy overall (it is a small, deliberately
  recoverable fixture — the previous two rounds recovered 12/12 structs
  and 14/14 function names by hand).
- Report ends with the ranked forge-gap list.