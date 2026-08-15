---
name: ida-forge-api
description: IDA Forge API (forge_api) — the headless facade for structure reconstruction and type recovery in IDA Pro (plugin `ida-forge`). Use when recovering C structs, scanning allocations/globals, building store structures, naming and committing types, retyping locals/functions, applying struct types to globals, or mirroring types between the store and the IDB via the idalib/ida-codemode workers. Complements the `idapython` skill: forge_api is the TYPE workflow, ida_* is everything else.
---

# IDA Forge API (forge_api)

Headless facade over the ida-forge plugin's structure-builder. One flat
module, JSON-returning functions, no Qt, works outside IDA (`help()` even
does). It is **packaged for type recovery — it is NOT a general IDA
replacement**. Disassembly, xrefs, strings, segments, auto-analysis,
output → use `ida_*`/`idc` modules directly (see the `idapython` skill).
forge_api only adds the structure/type pipeline: build → scan → name →
commit → apply → mirror.

## First Rules

- Discovery: `forge_api.help()` — dict of every function with
  signature/doc/params/returns/example. Read it before assuming a verb
  exists.
- `import forge_api` works standalone; IDA-required calls raise
  `ForgeApiError` outside a session.
- Result convention: success `{"ok": True, ...}`; failure
  `{"ok": False, "error": str}` (or `None`/`False` per doc). Read the
  docstring's Returns before parsing results.
- Worker imports persist: to pick up source changes after a worker has
  already imported forge_api, delete the module group and re-import (or
  reopen the database):
  ```python
  for m in [m for m in list(sys.modules) if m == "forge_api" or m.startswith("forge")]:
      del sys.modules[m]
  import forge_api
  ```
- **Never wipe the store.** `clear_structures` was REMOVED (2026-08-13:
  agents used it to erase the persisted catalog the GUI structure-builder
  reads). Deterministic sessions come from opening the `.exe` COLD
  (`ida_open_database` on the .exe, not an existing `.i64`).
- The store is shared: `forge.api.store.catalog`, persisted into the
  DB's netnode (`Storage("Structures")`). The GUI structure-builder reads
  the SAME store. IDB types (committed via `create_type`) live in the til
  and survive store wipes.
- Workers idle-drop after ~20 s: one script per execute, re-run on
  drops. The plugin dir symlinks to the repo `src/`.
- **Ground truth stays closed until the analysis is done.** If the task
  has source truth for the target (headers, `fixture.h`-style specs,
  reference structs), it is the SCORE SHEET, not the analysis input.
  Do not open it for member lists, offsets, names, sizes, or "what the
  scanner missed" while recovering — recover from binary evidence only
  (disassembly, decompilation, format strings, xrefs). Cross-check
  against ground truth at the very END, after the commit/apply passes.
  (R3.3)

## 2. When to use which

| action | tool |
|---|---|
| build/edit store structures, scan roots/globals/allocations, collisions, member naming, commit (`create_type`/`finalize`), `apply_type` on globals, `set_lvar_types`/`rename_local`/`rename_ea`, push/import/refresh mirror | **forge_api** |
| disassembly, xrefs, strings, function enumeration, data reads, file output, analysis control | **ida_\*** / ida-domain |

## 3. Verb catalog (groups)

- **meta**: `help(topic)`, `to_hex`.
- **store**: create_structure, get_structure, structures, set_current,
  remove_structure (STORE-ONLY purge; raises ForgeApiError once the
  structure is committed to the IDB — update committed types in place),
  duplicate_structure, rename_structure, add_member,
  set_member (`member_name=` disambiguates collision-offset pairs;
  editing fields), remove_members, get_member (offset + `member_name=`),
  nudge_members, auto_resolve; layouts pack by default — set_pack(name,
  N≥1) / create_structure(pack=N) changes the commit alignment,
  `set_pack(name, None)` restores natural alignment.
- **scan**: decompile(ea, force), signature, deep_scan / shallow_scan
  (ea + var_name/var_index/item_ea + structure + root_type + recurse_calls/
  max_depth), scan_global(ea, span), guess_allocation(ea, var_name),
  scan_from_allocation(ea, var_name=..., name=..., root_type=..., commit=),
  scan_sites(name) — recorded evidence sites per store structure
  (persisted in the IDB; the coverage check before committing).
- **build/apply**: create_type (overwrite=True UPDATES in place via
  `update_named_type` — the ordinal survives, applied items never
  dangle; non-placeholder existing types abort when overwrite=False),
  undo_type (restores the pre-commit declaration; REFUSES when the type
  was created by the commit — there is no delete path), finalize,
  finalize_all (children first; failure rows carry `error` +
  `created_names`), create_child_types, apply_type(ea, decl,
  redefine_range=True) — the WHOLE span becomes one struct item (no
  manual create_struct).
- **types**: create_typedef (function pointers commit via the
  declarator-name form), rename_member(name, offset, new_name) — renames
  a COMMITTED member (gap_* entries included); the store is untouched, so
  rename after the last re-commit. NO delete verbs: `remove_type` does
  not exist. Fix a layout with `remove_members`/`add_member`/`set_member`
  and re-commit with `create_type(..., overwrite=True)`.
- **naming**: rename_local, set_lvar_types (C types on args/locals;
  `scope=`), rename_ea (functions/globals — ida_name.set_name SN_NOCHECK),
  set_func_proto (function prototypes; works headless).
- **mirror**: import_types (IDB→store, skips store-known), push_type /
  push_all (store→IDB), refresh_types (IDB layout→store).
- **recon**: function_info, callers_of, callees_of, imports (real IAT,
  module/name filters), named_types, type_of, vtable_entries,
  vtable_name, to_vtable (unnamed tables → `vtbl_<addr>`).
- **features**: create_field (byte offsets on 9.x; persists), inverse_if,
  to_usercall, templated_keys / templated_decl(key, [type args]) /
  templated_apply.

## 4. Type-recovery workflow

1. Recon (ida_*): functions, globals, every printf format string — they
   carry member names.
2. Build: `create_structure("Name")` then `add_member(name, offset,
   "Type *", name=...)` — self/forward references parse before any IDB
   type exists (lazy placeholder).
3. Recover — SCAN FIRST, always: `deep_scan(ea, var_name=...,
   root_type="Type *")` or `scan_from_allocation` / `scan_global` before
   any manual construction; keep the call's output as evidence.
   `scan_from_allocation` now teleports into wrapper helpers
   (`v = node_new(...)` with the calloc inside): the helper's body is
   scanned via the allocator feeding its first returned lvar; only
   helpers whose allocator cannot be proven need manual disassembly —
   and only from BINARY evidence. "The layout differs from the header"
   is NOT a scanner failure and NOT a reason to hand-write members from
   the spec: re-run with more roots / disassemble deeper / use the
   format strings. Ground truth stays closed until step 10.
4. Check coverage — `scan_sites(name)` lists every recorded evidence
   site (func_ea + var, persisted in the IDB's netnodes — survives
   drops and reopens). If the struct is used elsewhere (other
   allocation sites, `callers_of`/`callees_of` of the runner, globals
   by xref) and the list misses them, scan those roots INTO the same
   store structure (`deep_scan(..., structure=name)`). Hand-built
   members carry no scan objects — a structure built only by
   `add_member` has no sites and nothing to apply.
5. `auto_resolve` collisions; trim junk with `remove_members` /
   `set_member(enabled=False)`; name members from printf evidence
   (`name_members_from_printf`).
6. Commit: `create_type(name, overwrite=True)` / `finalize` — the
   commit applies the pointer type at EVERY recorded scan site (the
   same "apply globally" step the GUI form runs; `reapply(name)`
   re-runs it, and `commit_declaration(name, cdecl)` commits an exact
   declaration text — the GUI pack dialog as an API call). CHECK the
   result: `applied_sites` must be non-empty when step 4 listed sites
   — an empty list means the evidence is not attached; re-scan into
   the structure, never hand-rebuild first. The GUI form and the API
   share ONE commit core (R3.9) — behavior cannot diverge.
   Children before parents. NEVER delete: there is no type-delete verb;
   correct a committed layout in place and re-commit.
7. Globals: `apply_type(ea, "Name", redefine_range=True)`.
8. Retype: `set_lvar_types` on section runners; rename functions with
   `rename_ea`.
9. Verify: `decompile(ea, force=True)` shows `x->member` in pseudocode.
10. ONLY NOW cross-check against ground truth (headers/specs), fix
   real divergences by re-scanning or evidence-based edits, and list
   any hand-built member with the missed-evidence reason.

## 5. IDA 9.4 / idalib notes (already absorbed — don't fight them)

- `ida_typeinf.parse_decl` cannot parse function prototypes; everything
  else goes through the facade's parse path (`set_func_proto` works).
- udt offsets are BYTES on 9.x (not bits); `lvar.type` is a method;
  `treeitems` is empty on fresh 9.4 — any ctree walk must use
  `ctree_visitor_t.apply_to(body, None)` with `visit_insn`/`visit_expr`.
- A struct named `inline` cannot be committed (IDB parser rejects it) —
  rename it. Commit errors are loud.
- Failed scans restore the root's previous type (no retype left behind).
- Re-commit after a child type changed: the parent's member size re-binds
  automatically.
- `decompile(force=True)` clears the cached pseudocode.

## 6. Reading results

- Committed IDB types: `named_types()`, `type_of(name)`.
- Store state: `get_structure(name)` / `structures()`.
- Rendered evidence: `decompile(ea, force=True)`.

Repo docs: `docs/forge_api_evaluation.md`, `docs/forge_api_recovery_eval.md`,
`CHANGELOG.md`; add docs under `docs/` in `H:/projects/_mishap_/ida-forge`.