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

## 2. When to use which

| action | tool |
|---|---|
| build/edit store structures, scan roots/globals/allocations, collisions, member naming, commit (`create_type`/`finalize`), `apply_type` on globals, `set_lvar_types`/`rename_local`/`rename_ea`, push/import/refresh mirror | **forge_api** |
| disassembly, xrefs, strings, function enumeration, data reads, file output, analysis control | **ida_\*** / ida-domain |

## 3. Verb catalog (groups)

- **meta**: `help(topic)`, `to_hex`.
- **store**: create_structure, get_structure, structures, set_current,
  remove_structure, duplicate_structure, rename_structure, add_member,
  set_member (`member_name=` disambiguates collision-offset pairs;
  editing fields), remove_members, get_member (offset + `member_name=`),
  nudge_members, auto_resolve.
- **scan**: decompile(ea, force), signature, deep_scan / shallow_scan
  (ea + var_name/var_index/item_ea + structure + root_type + recurse_calls/
  max_depth), scan_global(ea, span), guess_allocation(ea, var_name),
  scan_from_allocation(ea, var_name=..., name=..., root_type=..., commit=).
- **build/apply**: create_type (overwrite=True refines; non-placeholder
  existing types abort when overwrite=False), finalize, finalize_all
  (children first; failure rows carry `error` + `created_names`),
  create_child_types, apply_type(ea, decl, redefine_range=True) — the
  WHOLE span becomes one struct item (no manual create_struct).
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
3. Recover: `deep_scan(ea, var_name=..., root_type="Type *")` or
   `scan_from_allocation`. KNOWN GAP: scans do NOT follow wrapper
   helpers (`v = node_new(...)` with the calloc inside) — deep_scan the
   callee instead.
4. De-noise: scanners emit hypotheses + byte-granular junk — trim with
   `remove_members` / `set_member(enabled=False)`, keep evidence-based
   names.
5. Commit: `create_type(name, overwrite=True)` / `finalize` — children
   before parents, or just re-commit (the parent re-binds member types
   automatically).
6. Globals: `apply_type(ea, "Name", redefine_range=True)`.
7. Retype: `set_lvar_types` on section runners; rename functions with
   `rename_ea`.
8. Verify: `decompile(ea, force=True)` shows `x->member` in pseudocode.

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