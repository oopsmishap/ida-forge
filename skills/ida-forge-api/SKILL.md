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
  exists; `grouped()` returns the same catalog grouped by section.
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
- The store is a **persistent shared catalog**: `forge.api.store.catalog`
  is the single source of truth, written through to the DB's netnode
  (`Storage("Structures")`) and lazily reloaded on reopen. The GUI
  structure-builder reads the SAME catalog. IDB types
  (committed via `create_type`) live in the til and survive store
  rebuilds. There is **no clear/reset verb** — a store that grows stale is
  fixed in place, never wiped (R3.1).
- **Domain-first**: inside a session, capability offered by ida-domain MUST
  go through `Database.open()`/`db.*` first; raw `ida_*`/`idc` calls are
  only for documented gaps. `domain_status()` reports the runtime
  fallback records.
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
- Scan evidence and type references persist in the IDB's netnodes
  (`Storage("Structures")` scan-site rows + `Storage("TypeReferences")`
  dependency catalog), so coverage checks, view results and reference
  refreshes survive worker drops and warm reopens.

## 2. When to use which

| action | tool |
|---|---|
| build/edit store structures, scan roots/globals/allocations, collisions, member naming, commit (`create_type`/`commit_declaration`/`finalize`), `apply_type` on globals, `set_lvar_types`/`rename_local`/`rename_ea`, push/import/refresh mirror, provenance/reference tracking, subobject-rooted scans | **forge_api** |
| disassembly, xrefs, strings, function enumeration, data reads, file output, analysis control, opening the database | **ida-domain** (`Database.open()` + `db.*` namespaces) |
| netnode persistence, UI/actions, selected Hex-Rays mutation, operations listed in the repository migration checkpoint | **raw `ida_*`/`idc` fallback** |

Forge internals also follow this rule: a capability exposed by ida-domain MUST
use Domain first. Raw `ida_*`/`idc` calls are allowed only for the documented
gaps above. `forge_api.domain_status()` reports runtime fallback records.

## 3. Verb catalog (groups)

- **meta**: `help(topic)`, `to_hex`, `grouped`,
  `transaction(label)` (group catalog mutations with rollback + one
  persistence commit), `database_session(path, *, save_on_close=False,
  options=None)` — open an IDA Domain database and deterministically
  close its session, `domain_status(*, clear_fallbacks=False)` — Domain
  capability + SDK fallback diagnostics, `functions()`.
- **store**: create_structure, get_structure, structures, set_current,
  remove_structure (STORE-ONLY purge; raises ForgeApiError once the
  structure is committed to the IDB — update committed types in place),
  duplicate_structure, rename_structure (re-points every recorded
  reference and refreshes consumers), add_member,
  set_member (`member_name=` disambiguates collision-offset pairs;
  editing fields), remove_members, get_member (offset + `member_name=`),
  nudge_members, link_child, auto_resolve, export_store/import_store
  (portable JSON dump/rebuild, `merge=` supported); layouts pack by
  default — set_pack(name, N≥1) / create_structure(pack=N) changes the
  commit alignment, `set_pack(name, None)` restores natural alignment.
- **scan**: decompile(ea, force), decompile_many, signature,
  deep_scan / shallow_scan (ea + var_name/var_index/item_ea + structure +
  root_type + clear_first; deep_scan additionally takes recurse_calls,
  max_depth, and `subobject=` — shallow_scan accepts none of them),
  scan_global(ea, span), guess_allocation(ea, var_name),
  scan_from_allocation(ea, var_name=..., name=..., root_type=..., commit=),
  scan_returned(ea, max_depth) — return-value recon,
  recover(ea, var_name=...) — one-shot scan→commit→retype→reapply pipeline,
  scan_sites(name) — recorded evidence sites per store structure
  (persisted in the IDB; the coverage check before committing).
- **build/apply**: create_type (overwrite=True UPDATES in place via
  `update_named_type` — the ordinal survives, applied items never
  dangle; non-placeholder existing types abort when overwrite=False;
  result carries `applied_sites` + `references`), commit_declaration
  (the pack dialog as an API call: commit exact cdecl text,
  name-verified, applies at scan sites), undo_type (restores the
  pre-commit declaration; REFUSES when the type was created by the
  commit — there is no delete path), finalize, finalize_all (children
  first; failure rows carry `error` + `created_names`),
  create_child_types, apply_type(ea, decl, redefine_range=True) — the
  WHOLE span becomes one struct item (no manual create_struct).
  `create_type`/`commit_declaration` gate on **pack_readiness** (see §6).
- **types**: create_typedef (function pointers commit via the
  declarator-name form), rename_member(name, offset, new_name) — renames
  a COMMITTED member (gap_* entries included) in place via
  `rename_udm`; the store is untouched, so rename after the last
  re-commit. NO delete verbs: `remove_type` does not exist. Fix a layout
  with `remove_members`/`add_member`/`set_member` and re-commit with
  `create_type(..., overwrite=True)`.
- **naming**: rename_local, set_lvar_types (C types on args/locals;
  `scope=`), rename_ea (functions/globals — ida_name.set_name SN_NOCHECK),
  set_func_proto (function prototypes; works headless).
- **mirror**: import_types (IDB→store, skips store-known), push_type /
  push_all (store→IDB, delta-sync: a store in sync with the IDB is a
  no-op), refresh_types (IDB layout→store).
- **recovery**: recover_abi_structure(name, members, abi=) — create/replace
  a structure from detached C++ ABI evidence with scan-site + provenance
  preservation, synthesize_cpp (ABI structure + persisted root
  provenance), name_cpp_evidence, discover_global_slots, recover_pointer_flow.
- **recon**: function_info, callers_of, callees_of, imports (real IAT,
  module/name filters), named_types, type_of, is_type,
  vtable_entries, vtable_name, to_vtable (unnamed tables →
  `vtbl_<addr>`).
- **features**: create_field (byte offsets on 9.x; persists), inverse_if,
  to_usercall, split_flags, backfill_lumina, templated_keys /
  templated_decl(key, [type args]) / templated_apply.

## 4. Database open / session lifecycle

- Open a headless Domain session with the context manager:
  `database_session("file.i64"|"file.exe", save_on_close=False, options=None)`.
  The session owns the Domain `Database` handle and closes it
  deterministically on exit. `Database.open(path, ...)` (ida-domain) is
  the direct form; all forge verbs resolve the active Domain database
  lazily.
- **Cold-open determinism**: open the `.exe` fresh each run
  (`ida_open_database` on the .exe, not an existing `.i64`) so the run
  starts from binary evidence with no stale persisted store/types. The
  shared catalog and TypeReferences rows persist in netnodes and reload
  on reopen, so evidence you scanned earlier survives — but a deterministic
  recovery run starts cold and rebuilds.
- Prefer one script per worker execute; bundle reads into a single
  session when possible. Long multi-step work: `transaction(label)`
  groups catalog mutations so an exception rolls back and one commit
  lands on close.

## 5. Type-recovery workflow

1. Recon (ida_*): functions, globals, every printf format string — they
   carry member names.
2. Build: `create_structure("Name")` then `add_member(name, offset,
   "Type *", name=...)` — self/forward references parse before any IDB
   type exists (lazy placeholder).
3. Recover — SCAN FIRST, always: `deep_scan(ea, var_name=...,
   root_type="Type *")` or `scan_from_allocation` / `scan_global` before
   any manual construction; keep the call's output as evidence.
   `scan_from_allocation` teleports into wrapper helpers
   (`v = node_new(...)` with the calloc inside): the helper's body is
   scanned via the allocator feeding its first returned lvar; only
   helpers whose allocator cannot be proven need manual disassembly —
   and only from BINARY evidence. To scan a nested subobject into its own
   child structure, root at the subobject (see §7). "The layout differs
   from the header" is NOT a scanner failure and NOT a reason to
   hand-write members from the spec: re-run with more roots / disassemble
   deeper / use the format strings. Ground truth stays closed until step
   9/10.
4. Check coverage — `scan_sites(name)` lists every recorded evidence
   site (func_ea + var, persisted in the IDB's netnodes — survives
   drops and reopens). If the struct is used elsewhere (other allocation
   sites, `callers_of`/`callees_of` of the runner, globals by xref) and
   the list misses them, scan those roots INTO the same store structure
   (`deep_scan(..., structure=name)`). Hand-built members carry no scan
   objects — a structure built only by `add_member` has no sites and
   nothing to apply.
5. `auto_resolve` collisions; trim junk with `remove_members` /
   `set_member(enabled=False)`; name members from printf evidence
   (`name_members_from_printf`).
6. Commit: `create_type(name, overwrite=True)` / `finalize` (or
   `commit_declaration(name, cdecl)` for exact text — the GUI pack
   dialog as an API call). The commit applies the pointer type at EVERY
   recorded scan site (the same "apply globally" step the GUI form runs;
   `reapply(name)` re-runs it). CHECK the result: `applied_sites` must be
   non-empty when step 4 listed sites — an empty list means the evidence
   is not attached; re-scan into the structure, never hand-rebuild first.
   Children before parents (see §6 pack_readiness). The GUI form and the
   API share ONE commit core (R3.9) — behavior cannot diverge. NEVER
   delete: there is no type-delete verb; correct a committed layout in
   place and re-commit. The commit's `references` report tells you what
   the ordinal refresh gate re-applied (see §8).
7. Globals: `apply_type(ea, "Name", redefine_range=True)`.
8. Retype: `set_lvar_types` on section runners; rename functions with
   `rename_ea`.
9. Verify: `decompile(ea, force=True)` shows `x->member` in pseudocode.
10. ONLY NOW cross-check against ground truth (headers/specs), fix
   real divergences by re-scanning or evidence-based edits, and list
   any hand-built member with the missed-evidence reason.

## 6. pack_readiness and structured unresolved-reference errors

Before any commit, `create_type`/`commit_declaration` run
`catalog.pack_readiness(name)`: every enabled member's authored
declaration (`decl_src`) is re-resolved against the current type table.
When a member would pack as a placeholder — a referenced type is not yet
committed, or the declaration is malformed — the commit is REFUSED with a
**structured** error instead of silently degrading:

```json
{"ok": false, "error": "cannot pack in 'X': ...",
 "code": "unresolved_references",
 "unresolved_types": ["ChildType"],
 "blocked_members": [{"name", "offset", "status", "unresolved", ...}]}
```

`code == "unresolved_references"` means: commit the referenced store
structures first (children before parents), then re-commit. `blocked`
lists each member and the missing type names. This replaced silent
placeholder degradation — read it as the dependency order, not an error
to work around by hand-building members.

## 7. Subobject-rooted deep scan

A member at offset 0x1B60 that is really a nested subobject must be
scanned into the CHILD structure in child coordinates. Root the scan at
the subobject expression itself:

```python
forge_api.deep_scan(ea, subobject={"base_offset": 0x1B60, "var_name": "a1", "structure": "Child"})
```

`SubobjectRoot` matches `parent->m(0x1B60)` / `(child_t *)(parent + 0x1B60)`
and the shared deep-scan visitor computes member offsets ABOVE that node —
i.e. already relative to the subobject. **Rebasing invariant:**
`World base + 0x1B60 + 0x08` produces child offset `0x08` (via
`rebase_to_subobject`), never `0x1B68`. Optional descriptor keys:
`var_index`/`item_ea` (parent criteria, at most one of the three) and
`parent_type` (required parent type-name match). `root_type` is rejected
with `subobject` — retyping the parent lvar to the child type would break
the base-offset addressing. The returned result adds `"subobject": 0x1B60`.

## 8. Ordinal refresh after create_type / push_type / rename

When a committed type re-lands in the IDB with a fresh ordinal, every
consumer of its previous ordinal goes stale. The dependency catalog
(`Storage("TypeReferences")`) records each consumer — structure member
declarations (`STRUCTURE_MEMBER`), applied globals (`GLOBAL_EA`),
retyped locals (`LVAR`), function prototypes (`PROTOTYPE`). After:

- `create_type(...)` — fresh commit,
- `push_type`/`push_all` — fresh write (a delta-sync no-op does NOT fire),
- `rename_structure` — type re-file,

the **ordinal refresh gate** (`_refresh_type_references`) runs in
**reference order** (`resolve_commit_order`, referenced types first):
dependent store structures re-commit through `push_type` and recorded
globals/locals/prototypes re-apply their stored declarations. The cascade
is exactly **one level deep** (nested commits are reentrant-guarded and
skipped); failures are reported, never fatal. `create_type`'s result
carries the gate's `references` report (structures committed, globals/
lvars/prototypes re-applied, `deferred`, `failed`) — CHECK it to confirm
dependents came along. Rename additionally re-points every stored
reference old→new and re-commits the renamed structure.

## 9. Authored-member-preserving merges

Re-scans append scan-built rows blindly; when a scan lands on an offset an
authored member already occupies, the two merge **provenance-safely**
(`merge_member_evidence`, gap #8): the survivor keeps its authored
name/`decl_src`/type/comment, the loser contributes its scan evidence
(`scanned_variables`, child links), and the loser is dropped. Two authored
members at one offset stay a deliberate collision and are untouched.
Scan results carry a `"preserved"` list of `{offset, kept, merged}`
same-offset merges — read it to see what the scan merged rather than
replaced. The same evidence-preserving merge backs
`recover_abi_structure` (`preserved_sites` in its result), so an ABI
rebuild never silently drops previously recorded scan sites or the
structure's provenance.

## 10. IDA 9.4 / idalib notes (already absorbed — don't fight them)

- `ida_typeinf.parse_decl` cannot parse function prototypes; everything
  else goes through the facade's parse path (`set_func_proto` works, via
  `idc.parse_decl`).
- udt offsets are BYTES on 9.x (not bits) — except `get_udt_details`,
  which reports BITS (accepted when bit-clean, same rule as `type_of`).
- `lvar.type` is a method; `treeitems` is empty on fresh 9.4 — any ctree
  walk must use `ctree_visitor_t.apply_to(body, None)` with
  `visit_insn`/`visit_expr`; `to_specific_type` is a property on the live
  build.
- `rename_udm` (via `rename_member`) mutates the named type IN PLACE —
  til-persistent, packed layout survives; the 9.4 build has no
  `update_named_type`, and `create_udt` on pack-derived offsets errors.
- A struct named `inline` cannot be committed (IDB parser rejects it) —
  rename it. C-keyword member names are rejected loudly. Commit errors
  are loud.
- Failed scans restore the root's previous type (no retype left behind).
- Re-commit after a child type changed: the parent's member size re-binds
  automatically.
- `decompile(force=True)` clears the cached pseudocode.
- `ida_funcs.set_ti` was removed on 9.4 — `apply_tinfo` is the apply path.

## 11. Reading results

- Committed IDB types: `named_types()`, `type_of(name)`.
- Store state: `get_structure(name)` / `structures()`.
- Rendered evidence: `decompile(ea, force=True)`.
- Reference/freshness state: `references` report on `create_type`;
  `domain_status()` for Domain vs SDK-fallback usage.

`CHANGELOG.md`; add docs under `docs/` in the repo root.
