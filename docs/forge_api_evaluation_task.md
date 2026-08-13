# Forge API evaluation task — full-workflow binary reversal via IDA MCP

## Mission

Reverse-engineer one fixture binary end-to-end using **only** the headless
`forge_api` facade through the IDA MCP tools (`ida_open_database` /
`ida_execute_python`). The point is not the reversal itself — it is a
**feature-by-feature exercise of the entire facade** — so use every
function the API offers somewhere in the session, and record what worked,
what didn't, and what was missing.

## Target

`tests/fixtures/build/Release/complex_fixture.exe` (or, if a GUI DB is
already open, `H:\re\_random\c_structs\pure_c_struct_fixture.exe.i64`).
Open it cold via `ida_open_database` (no `.i64` reuse; re-derive).
Source exists under `tests/fixtures/` — **do not read it during recovery**;
compare only after the final report is drafted, to judge what was missed.

## Ground rules

1. Prefer `forge_api` for **everything** — type recovery, struct creation,
   member naming, vtable discovery, arg/local retyping and renaming, type
   commit, prototype fixes. Anything done with raw `ida_*` calls counts as
   a gap: record it, then try to express the same operation in forge.
2. Use `*forge_api.help()*` (or the `help` call) to discover the surface;
   the catalog is self-describing. Consult `src/forge_api.py` only when an
   error is genuinely unclear.
3. Keep every MCP script **self-contained in one execute** — idle workers
   drop after ~20 s lease. Re-type roots after a cold reopen (replay is
   deterministic).
4. No source comparison during the session (allowed only at the end).
5. After the run, write `docs/forge_api_evaluation_output.md` with the
   report below — and only then compare with sources to score recovery.

## Mandatory feature coverage (try each at least once)

**Store & structs**: `create_structure`, `get_structure`, `structures`,
`set_member`, `add_member` (incl. self/forward refs — `GridNode *`),
`remove_members`, `nudge_members`, `rename_structure`, `clear_structures`,
`get_member(include_disabled=True)` on collision-disabled offsets,
`to_vtable`, `link_child` + `create_child_types`.

**Scanning**: `decompile` (incl. `max_lines`, `force`), `signature`,
`deep_scan` (with `var_name`, `root_type`, `recurse_calls`),
`shallow_scan`, `scan_global`, `guess_allocation`,
`scan_from_allocation` (find the heap cell and recover the element type).

**Type commit & apply**: `create_type` (incl. `overwrite=True` twice to
prove refinement), `finalize` headless, `apply_type(ea, decl,
redefine_range=True)` so a global renders as a struct, `is_type`,
`type_of`, `named_types`.

**Mirror**: `import_types`, `push_type`, `push_all`, `refresh_types`
(round-trip a rename both directions).

**Recon**: `function_info`, `callers_of`, `callees_of`, `imports`,
`vtable_entries`, `vtable_name`, `templated_keys` / `templated_decl` /
`templated_apply`, `to_usercall` (only if a candidate exists),
`inverse_if`, `create_field`, `guess_allocation` on at least one local.

**Pseudocode mutation** — the "naming" core: `set_lvar_types` on args
and locals, `rename_local` on ~10 variables, `set_func_proto` to fix a
wrong signature, and function renames.

## Deliverable: the report (`docs/forge_api_evaluation_output.md`)

Write it as an honest usability review:

1. **Session log** — what was recovered: structs, vtable→method mapping
   (`vtable_entries` + `decompile` of slot functions naming members →
   infer "what functions are called"), types committed, functions
   retyped/prototyped. Quick wins and where the facade shined.
2. **Good** — what was genuinely useful, easy to call, and well-shaped
   (be concrete: call + outcome).
3. **Bad / broken** — everything that failed or silently misbehaved,
   with the repro call and error text.
4. **Not useful (or not needed)** — features used once and dropped, with
   why. `templated_*` on a non-templated binary is a legitimate "N/A —
   needs an applicability hint" entry.
5. **Needs tweaks** — friction in existing APIs (naming, defaults,
   return shapes, missing confirmations), with the smallest-change
   suggestion.
6. **Feature requests** — ranked, that would have made this exact
   session easier. Candidates that are known on the list: renaming
   functions/globals (`ida_name.set_name` lives raw), automatic root
   retyping, member naming from constants/string literals, grouping many
   small calls into one (`decompile_all`, `recover(...)`), batch member
   renames, decode of bit/flag fields, array detection (stride), undo of
   type writes. Anything you hit with a raw `ida_*` escape becomes a
   request.
7. **Score** — verdict on the facade overall with the 1–2 changes you
   would prioritize.

## Exit criteria

- `docs/forge_api_evaluation_output.md` exists with all seven sections.
- Every item in the coverage checklist is either used or explicitly
  marked N/A with the reason.
- The report ends with a ranked "top 5 changes" list for the next forge
  iteration.