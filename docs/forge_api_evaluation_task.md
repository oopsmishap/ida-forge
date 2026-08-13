# Forge API evaluation task — full-workflow binary reversal via IDA MCP

## Mission

Reverse-engineer a real binary end-to-end using **only** the headless
`forge_api` facade through the IDA MCP tools (`ida_open_database` /
`ida_execute_python`). The point is not the reversal itself — it is a
**feature-by-feature exercise of the entire facade** — so use every
function the API offers somewhere in the session, and record what worked,
what didn't, and what was missing.

## Target

Any binary available in the session — the one the user opened in IDA MCP,
or the agent's pick (an unknown/unfamiliar `*.exe`/`*.i64` is ideal).
Open it cold via `ida_open_database`; if a `.i64` already exists, treat
its types as unverified and re-derive the interesting parts anyway.

Source code may or may not exist for the target — it is never consulted
during the session; only the binary speaks. If a source is available,
compare only after the report is drafted, to score recovery.

## Ground rules

1. Prefer `forge_api` for **everything** — type recovery, struct
   creation, member naming, vtable discovery, arg/local retyping and
   renaming, type commit, prototype fixes, name cleanup. Anything done
   with raw `ida_*` calls counts as a gap: record it, then try to express
   the same operation in forge.
2. Use `forge_api.help()` to discover the surface — the catalog is
   self-describing. Consult the source (`src/forge_api.py`) only when an
   error is genuinely unclear.
3. Keep every MCP script **self-contained in a single execute** — idle
   workers drop after ~20 s and take the in-memory IDB with them. After a
   cold reopen, replay roots/types (it's deterministic).
4. Don't be clever: when the facade offers a path, take the facade path
   even if a raw call looks shorter — the report depends on it.

## Mandatory feature coverage (try each at least once)

**Store & structs**: `create_structure`, `get_structure`, `structures`,
`set_member`, `add_member` (incl. a self/forward reference like
`Node *` before the IDB type exists), `remove_members`, `nudge_members`,
`rename_structure`, `clear_structures`, `get_member(include_disabled=True)`
on a collision-disabled offset, `to_vtable`, `link_child` +
`create_child_types`.

**Scanning**: `decompile` (incl. `max_lines`, `force`), `signature`,
`deep_scan` (with `var_name`, `root_type`, `recurse_calls`),
`shallow_scan`, `scan_global`, `guess_allocation`,
`scan_from_allocation` (take a heap-allocated object and recover its
element type).

**Types**: `create_type` — including calling it twice with
`overwrite=True` to prove refinement of an existing type — plus
`finalize` headless, `apply_type(ea, decl, redefine_range=True)` so a
global renders as a struct, `is_type`, `type_of`, `named_types`, and
`create_field`.

**Mirror**: `import_types` (on the binary's local structs), `push_type`,
`push_all`, `refresh_types` — round-trip a rename in both directions.

**Recon**: `function_info`, `callers_of`, `callees_of`, `imports`,
`vtable_entries`, `vtable_name`, `templated_keys` / `templated_decl` /
`templated_apply`, `to_usercall` (if a candidate exists), `inverse_if`,
`create_field`.

**Pseudocode mutation — the "naming" core**: `set_lvar_types` on args
and locals, `rename_local` on ~10 variables, `set_func_proto` on a wrong
signature, and **renaming functions** (however you manage it — if forge
has no path, that is a finding).

## Deliverable: the report (`forge_api_evaluation_output.md` — or next to
the task doc)

An honest usability review with these sections:

1. **Session log** — what was recovered: structs, vtable→method mapping
   (`vtable_entries` + `decompile` of slot functions showing named
   members → infer "what functions are called"), committed types, retyped
   functions. Quick wins and where the facade shined.
2. **Good** — genuinely useful, easy, well-shaped: call + outcome.
3. **Bad / broken** — everything that failed or silently misbehaved, with
   the repro call and the exact error.
4. **Not useful / N/A** — features tried and dropped, with why; a
   feature that doesn't apply to this binary is a legitimate "needs an
   applicability hint" entry.
5. **Needs tweaks** — friction in existing APIs (naming, defaults,
   return shapes, missing confirmations) with the smallest-change
   suggestion for each.
6. **Feature requests, ranked** — anything that would have made this
   session easier: function/global renaming (`ida_name.set_name` lives
   raw), automatic root retyping, member naming from constants/string
   literals, batching (`decompile_all`, `recover(...)`), array/stride
   detection, undo of type writes, decode of bit/flag fields — plus
   anything you had to do with a raw `ida_*` escape.
7. **Score** — verdict on the facade overall, and the 1–2 changes you
   would prioritize first.

## Exit criteria

- Report exists with all seven sections.
- Every checklist item is used or explicitly marked N/A with the reason.
- The report closes with a ranked top-5-change list for the next forge
  iteration.