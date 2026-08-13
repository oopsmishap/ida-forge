# ida-forge TODO

Open work derived from the 2026-08-11 assessment + the 2026-08-12 live
type-recovery sessions (complex_fixture and pure_c_struct_fixture via
forge_api / ida MCP). All open items below are resolved as of 2026-08-13
(R10/R11, I.8–I.28, T3.3); details live in git history.

## How to use this file

- Open items are ordered: correctness bugs first, then facade core
  (small, high-leverage), recon reads, workflows, scanner quality,
  architecture. Each item is self-contained:
  **Status / Issue / Evidence / Plan / Acceptance**.
- Ground rules for fixes: run the specific test that covers the change;
  add a regression test for every bug fix (behavior assertions, no
  tautology); never touch `tests/conftest.py` stubs to make a test pass;
  anything that only works against the stubs is unverified against real
  IDA — mark with an explicit live-verify acceptance step.
- Baselines: `python -m pytest -q` → 455 passing; `ruff check src tests`
  clean.

---

## Correctness bugs (fix first, each with a regression test)

### R10 `create_type(overwrite=True)` never overwrites — `del_named_type` by name is a silent no-op on IDA 9.4

- **Status**: resolved — ordinal-delete overwrite (get_type_ordinal → del_numbered_type) with name-delete fallback and a visible delete-failure path; facade distinguishes the three error strings. Live-verified 2026-08-13. **Live-reproduced 2026-08-12 on an idalib 9.4 worker**
  (OWTest probe): first `create_type(overwrite=True)` ok; immediately after,
  `create_type("OWTest", overwrite=True)` → `{"ok": false, "error": "type
  already exists (overwrite disabled)"}` — every time, with unchanged
  member sets. Refinement of an existing type is therefore **impossible**:
  rebuilding the store struct and re-committing hits the same wall.
- **Root cause (pinned by live bisect)**: `Structure._set_cdecl_impl`'s
  overwrite branch deletes via `ida_typeinf.del_named_type(idati, name, 0)`
  — live probe: returns **False**, `idaapi.get_type_ordinal` unchanged (50),
  the type still resolvable afterwards. The subsequent recreate check finds
  the type and the commit returns None. `idaapi.del_numbered_type(idati,
  ordinal)` **does delete** (`found`=False after), and `create_type` then
  succeeds. The repo already contains the correct ordinal-delete pattern in
  `members.py` vtable overwrites (`get_type_ordinal` + `del_numbered_type`)
  — the established-pattern-second-site lesson again.
- **Compounding defect — the facade error lies**: `forge_api.create_type`
  maps *any* `set_cdecl → None` to
  `"type already exists (overwrite disabled)"` — so a recreate failure, a
  failed `_declaration_parses` gate, or an aborted Qt dialog are all masked
  as "already exists". Zero diagnostics.
- **Evidence**: live probe matrix (2026-08-12): `r2_overwrite_untouched` /
  `r3_overwrite_refined` / `r4_no_overwrite` all returned "already exists";
  `types_create_type_after_del: false`; `del_return: false`, ordinal
  survives name-delete, ordinal-delete works. `src/forge/api/types.py:
  create_type` exists-check; `structure.py:_set_cdecl_impl`.
- **Plan**: delete by ordinal (`idaapi.get_type_ordinal` →
  `del_numbered_type`) with name-delete fallback; make delete failure
  visible. Facade error strings: "type already exists (overwrite disabled)"
  only when `overwrite is False`; "declaration could not be parsed for
  overwrite"; "failed to recreate type after delete".
- **Acceptance**: regression test pins `del_numbered_type` after
  `get_type_ordinal` on overwrite; facade test asserts the three distinct
  error strings; live re-probe: overwrite-of-existing and overwrite-refined
  both return `ok: true` and commit the refined member.

### R11 `finalize`/`finalize_all` are unusable headless and report a 0-diagnostic failure

- **Status**: resolved — headless finalize routes through build_cdecl → set_cdecl like create_type; failures report a reason instead of empty `unresolved`. **Live-reproduced with the R10 probe:**
  `fe.finalize("OWTest")` → `{"ok": false, "unresolved": []}` on a trivial
  store struct; `finalize_all()` →
  `{"structure": "OWTest", "ok": false, "created": false}`. Empty
  `unresolved` says nothing — the failure is not child resolution.
- **Root cause (code-read pinned)**: the facade `finalize` routes through
  `Structure.create_type_if_ready` → `pack_structure`, a GUI flow:
  `ida_kernwin.ask_str(...)`/`ask_text(...)`. In an idalib worker these
  return None (no UI), so `pack_structure` returns None ("No type
  definition was provided") and the facade maps that to `unresolved: []`.
  The headless commit path already exists and is proven — the facade's own
  `create_type` calls `set_cdecl` and skips every dialog — `finalize` just
  never routes to it.
- **Plan**: `finalize`/`finalize_all` headless path = same as `create_type`
  (build_cdecl → `set_cdecl(cdecl, origin, overwrite=...)`), keeping the
  child-resolution guard (`refresh_linked_member_types` + unresolved
  check); report `"ok": false, "error": "<reason>"` instead of an empty
  `unresolved` when pack/commit fails for any non-child reason.
- **Acceptance**: live re-probe: `finalize("OWTest")` returns
  `{"ok": true, "type_name": "OWTest"}`; unit test asserts a distinct error
  string (not empty `unresolved`) when the commit path fails.

---

## Facade core (small, unblocks everything else)

### I.12 Add `set_lvar_types` + `rename_lvar` — pseudocode mutation (the most-repeated raw-IDA calls)

- **Status**: resolved — `set_lvar_types` (arg/all scope) + `rename_local` via `modify_user_lvar_info(MLI_TYPE)` / `rename_lvar`. **Every step that maps a recovered type onto code required**
  raw `ida_hexrays`: `decompile → list(cfunc.get_lvars()) → is_arg_var →
  lvar_saved_info_t{ll=lvar_locator_t(location, defea), type} →
  modify_user_lvar_info(entry_ea, MLI_TYPE, lvi)` — used ~14× in one
  session, plus `apply_type` (R9) needs the identical operation for locals.
  `vdui_t.set_lvar_type` is missing/broken headless and
  `cfunc.set_lvar_type` was removed in IDA 9.4, so an LLM caller must
  rediscover this each time.
- **Evidence**: session helper `retype_first_arg`; the `MLI_TYPE` flag is
  **mandatory** (without it `modify_user_lvar_info` returns False
  silently). Rename side confirmed live 2026-08-12: `ida_hexrays.rename_lvar
  (ea, old, new)` exists; `set_lvar_name` does **not** — the legacy call is
  the working path.
- **Plan**: `forge_api.set_lvar_types(ea, types: dict[str, str] |
  list[tuple], scope="arg"|"all")` — decompile, apply each `name → C type`
  (`"*"` → `void *`) via `modify_user_lvar_info(MLI_TYPE)`, return
  per-variable success + updated prototype. `"all"` also retypes locals
  (the `World` local in `sub_140001380` stayed raw after arg-only retypes).
  Same facade group: `rename_local(ea, name|index, new_name)` via
  `rename_lvar`.
- **Acceptance**: one call retypes `a1` to `World *` and the next
  `decompile` shows named members; regression test pins `MLI_TYPE` and
  `lvar_locator_t(location, defea)` shapes.

### I.8 Headless `deep_scan` needs pointer-typed roots — add a root-type hint

- **Status**: resolved — `deep_scan(..., root_type=...)` retypes the root lvar (MLI_TYPE); integral scalar roots auto-retype to `void *`. **`__int64 a1` root → **2 members**; same function**
  retyped `void *a1` → **341** (byte-semantics pointer arithmetic → clean
  `memptr` shapes). Every unknown signature arg is `__int64` on a fresh DB,
  so LLM callers hit this on the very first scan.
- **Evidence**: `forge_api.py` `deep_scan`/`_resolve_scan_root`;
  `visitor.py` `_manipulate` gating; live numbers from `sub_1400017A0`.
- **Plan**: `root_type: str | None = None` on `deep_scan` → retype the root
  lvar (persisted, `modify_user_lvar_info(MLI_TYPE)`); consider auto-retyping
  integral scalar roots to `void *` by default.
- **Acceptance**: on `__int64 a1`, `deep_scan(..., var_name="a1")` returns
  the full member set with no caller-side retyping; unit test pins the
  `MLI_TYPE` requirement.

### I.10 `deep_scan`/`shallow_scan` should auto-create the store structure

- **Status**: resolved — bare `deep_scan`/`shallow_scan`/`scan_from_allocation` auto-create `Structure`/`Structure Copy` via `catalog.unique_name`. **Without `create_structure(name)` first they raise**
  `ForgeApiError: no structure named ... in the forge_api store`; both
  already return `{"structure": name, ...}` so an auto-chosen name is
  discoverable.
- **Plan**: when `structure` is empty/None, auto-create via
  `_unique_structure_name("Structure")` (existing dedup helper, `base`,
  `base Copy`, `base Copy N`); `scan_global` already auto-creates
  (`global_<short_name>`).
- **Acceptance**: bare `deep_scan(ea, var_name="a1")` on an empty store
  returns `{"structure": "Structure", "members": [...]}`; the second bare
  call returns `"Structure Copy"`.

### I.9 `to_vtable` should tolerate collision-disabled members at the offset

- **Status**: resolved — `to_vtable` falls back to a placeholder member at a disabled-only offset and reports `skipped` names.
- **Issue**: `forge_api.to_vtable` raises
  `ForgeApiError: no member at offset 0x0` when the offset's members are
  all collision-disabled (`get_member_by_offset` only returns enabled
  members) even though the row is real.
- **Plan**: no enabled member at the offset → create a placeholder member
  there and convert it (preserving disabled names/comments), or raise a
  message naming the collision.
- **Acceptance**: unit test with two overlapping disabled members at offset
  0 → `to_vtable` still registers the row; no silent loss of names.

### I.11 `create_type` should surface/skip collision-disabled members instead of silently dropping them

- **Status**: resolved — `create_type` reports a `skipped` list naming collision-disabled members. **Members disabled by collisions are excluded from**
  `build_cdecl`, so a curated structure commits with **named members
  silently absent** — committed `Player` lacks its offset-0 vftable and
  `type_id`; store `System` committed as IDB type
  `fixture_PhysicsSystem` (vtable-derived name priority). The facade
  returns `{"ok": true}` without hinting.
- **Evidence**: `type_of("World")` 349 members present; `commit_Player`
  starts `u64 u64_0; u64 u64_1;` with no `_vftable_0x0`/`type_id`;
  `commit_System` `type_name`.
- **Plan**: `create_type` reports `disabled`/`skipped` member names in its
  result; optionally fail loudly when a curated member ends up disabled.
- **Acceptance**: committing a structure with one collision-disabled
  curated member lists it under `skipped`; removing it re-commits clean.
- **Replay caveat (2026-08-12)**: curated-offset scripts are deterministic
  per store, but a replay's committed absolute offsets can drift (+64..168
  B in the World tail, `system_0`@1152 vs loop constant 1088) — the script
  didn't reproduce the original incremental disables of leftover scan
  members (`u64_488`/`u128_4c0` survive). Re-verify final offsets against
  disassembly, not the previous store diff.

### I.18 `get_member(..., include_disabled=True)` + collision-surfacing on `add_member`

- **Status**: resolved — `get_member(..., include_disabled=True)` reads every offset; `add_member`/`set_member` report `"collision"` when disabled.
- **Issue**: `get_member_by_offset` returns only enabled members (I9's
  crash source); `add_member` landing on a colliding offset silently
  produces a disabled member that `create_type` then silently drops (I11).
- **Plan**: `get_member(structure, offset, include_disabled=True)`; make
  `add_member`/`set_member` report `"collision": true` when the net result
  is disabled.
- **Acceptance**: entity offsets (`Player + 0`, `+8`) readable with
  `include_disabled=True` where the current call returns `None`;
  `add_member` at a colliding offset flags the member.

### I.19 `apply_type(ea, declaration, redefine_range=False)` — apply a parsed type at any address, no scan evidence needed

- **Status**: resolved — `apply_type(ea, decl, redefine_range=False)` parses store-aware, applies at `ea` (TINFO_DEFINITE), and redefines ranges via `del_items` + `del_global_name` when asked.
- **Issue**: `create_type` only applies the pointer type to variables the
  scans recorded — it cannot type an arbitrary global, local, or data
  address, and it assumes a pointer. Making a global render as a struct
  (decompiler shows `g_outer_aggregate.cell_meta[0].tag`, field names in
  data references) required a hand-built sequence: `parse_one_declaration`
  → `apply_tinfo(..., DEFINITE)` → `del_items` over the range → deleting
  shadowing auto-names (`del_global_name` ×31 in one session). All of it is
  pseudocode-visible payoff the facade should own.
- **Evidence**: the "make the global render as a struct" flow; raw calls
  used: `ida_typeinf.parse_decl` (silently returns False with a None til —
  the domain `parse_one_declaration` was the working path),
  `ida_typeinf.apply_tinfo`, `ida_bytes.del_items`, `ida_name.del_global_name`.
- **Plan**: `forge_api.apply_type(ea, declaration, redefine_range=False)`
  — parse `declaration` (store-name aware), `apply_tinfo` at `ea` with
  `TINFO_DEFINITE`; when `redefine_range=True`: `del_items` the span of the
  new type first, then strip auto-generated names over it, so the struct
  (not its flattened qwords) owns the range.
- **Acceptance**: on a fixture global written through named qwords,
  `apply_type(ea, "OuterAggregate")` yields a decompile showing the struct
  field names; unit test pins the parse path (store-name fallback) and the
  redefine-range deletion order.

---

## Recon read facades

### I.13 Add `function_info(ea)` / `callers_of` / `callees_of`

- **Status**: resolved — `function_info` (aggregate + refs) / `callers_of(ea, kind=...)` / `callees_of(ea)` using `get_first_dref_to`/`CodeRefsTo` walks (cycle-guarded) and the decompiler.
- **Issue**: the session's own goal ("infer what functions are
  called") had no facade primitive: vtable slots were read by hand
  (`ida_bytes.get_qword(vtbl+8*i)`) and `j_free` callers via raw
  `idautils.CodeRefsTo`.
- **Plan**: `function_info(ea) -> {name, start_ea, size, prototype,
  callers, callees, refs}` (first decompile line + xref scans); thin
  `callers_of(ea, kind="code")` / `callees_of(ea)`; data-refs option for
  vtable/RTTI discovery.
- **Acceptance**: `callers_of(j_free)` matches the session's manual scan;
  `function_info` on a vtable slot returns its prototype + dispatchers.

### I.14 Add vtable read facades `vtable_entries(address)` / `vtable_name(address)`

- **Status**: resolved — `vtable_entries(address)` (slots via `populate_virtual_functions`) and `vtable_name(address)` (via `_parse_vtable_name`), both tolerant of non-vtable targets.
- **Plan**: `vtable_entries(addr) -> [{offset, ea, slot}]` (stop at first
  data reference, reusing `populate_virtual_functions`); `vtable_name(addr)`
  reusing `_parse_vtable_name` (demangle + sanitize).
- **Acceptance**: `vtable_entries(0x1400055f8)` returns the three validated
  slots; `vtable_name(0x140005a98)` → `fixture_PhysicsSystem_vtbl`.

### I.15 Add `imports(pattern=None)`

- **Status**: resolved — `imports(pattern=None)` via `idautils.Entries()` (3/4-tuple tolerant, 9.4-safe) with case-folded filter.
  `idautils.imports()` **does not exist on IDA 9.4** (live `AttributeError`),
  the working path is `idautils.Entries()`.
- **Plan**: `forge_api.imports(pattern=None) -> [{module, ea, name}]`,
  9.4-safe backend, substring filter (case-folded `??2`/`malloc`/`new`).
  Document that an empty result is meaningful.
- **Acceptance**: complex_fixture returns the same single `start` entry as
  the manual call.

### I.16 `decompile` slicing + `signature(ea)` + `force` refresh

- **Status**: resolved — `decompile(ea, max_lines=..., line_range=..., force=...)` (force clears the cfunc cache) + `signature(ea)` first-line. **Issue**: every decompile was sliced by hand
  (`str(decompile(ea)).splitlines()[:N]`).
- **Plan**: `decompile(ea, max_lines=None, line_range=None, force=False)`
  — `force=True` calls `ida_hexrays.clear_cached_cfuncs()` first (live
  verified present) so freshly retyped globals render (observed:
  `xmmword_1400060C0` where the applied struct's field should be);
  `signature(ea)` = first line
  (`World *__fastcall sub_1400017A0(World *a1)`).
- **Acceptance**: `signature` returns the session-verified prototype;
  `max_lines=5` returns exactly 5 lines.

### I.17 `is_type(name)`

- **Status**: resolved — `is_type(name)` existence guard (the session's raw `tinfo_t().get_named_type` bisect calls).
- **Plan**: `forge_api.is_type(name) -> bool`; optional
  `type_exists(name, kind="struct"|"typedef"|"any")`.
- **Acceptance**: `is_type("World")` True after commit, False before.

### I.22 `set_func_proto(ea, declaration)`

- **Status**: resolved — `set_func_proto(ea, declaration)` parses, applies, and re-decompiles the first line.
  convention-conversion side effect; there is no general prototype-set
  facade (`ida_funcs.set_ti`/`apply_tinfo` with a parsed function type).
- **Plan**: `set_func_proto(ea, "int __cdecl foo(World *, char *)")` —
  parse, apply, return the re-decompiled first line; paired with I.12 for
  arg retyping.
- **Acceptance**: new prototype shows in `decompile(ea)` and
  `function_info(ea)` (I13).

---

## Workflows (allocation-driven recovery)

### I.23 Add `scan_from_allocation(ea, var_name|item_ea, name=None)`

- **Status**: resolved — `scan_from_allocation(ea, var_name|item_ea, name=None)` wires guess → HEAP row → auto store struct → deep_scan (recurse_calls) → `to_vtable` → `create_type(overwrite=True)` in one call.
  there" workflow. Every piece works, nothing wires them (live probe on
  pure_c GUI DB, 2026-08-12):
  - `guess_allocation(0x140001610, var_name="cells")` → HEAP row at
    `cells = (char *)calloc(9u, 0xCu)` ✓
  - `deep_scan(... var_name="cells")` → 17 members, the 12-byte element
    lattice (0,2,12,24,…,104, incl. `ArrayCell *` at 104) ✓
  - yet the DB's store was empty; the recovered structs were hand-built.
- **Plan**: one call: guess → first HEAP row → auto-create store struct →
  retype root if needed (I8) → `deep_scan` anchored at the allocation
  result → `{allocation (with size), structure, members}`; optional
  `commit=True` → `create_type` (gated by R10). Vtable-stored allocations
  → subobject scan offer (I26).
- **Acceptance**: `scan_from_allocation(0x140001610, var_name="cells")`
  returns the stride-12 lattice with zero intermediate calls; orchestration
  unit tests with stubbed guess/deep pieces.

### I.24 `guess_allocation` size resolution: fold constants, unknown ≠ 0, size/count in rows

- **Status**: resolved — `_extract_numeric_argument` folds `mul`/`add`/`sub` constants (`None` when unknowable); allocator rows expose `size`/`size_hint` and `size: None` for unknown. **Issue**: `_extract_numeric_argument` returns 0 for any non-num
  arg, so `calloc((size_t)width*height, sizeof(*cells))` resolves a size of
  0; `malloc(len+1)`/`realloc` hit the same wall; callers can't tell
  "unknown" from a real 0-byte allocation.
- **Evidence**: `scan_object.py:619-655`; repo `build_grid` calloc shape.
- **Plan**: fold `mul`/`add`/`sizeof` numeral peels → constant when
  provable; return `None` when unknowable; add `size`/`size_hint` per row.
- **Acceptance**: `calloc(4, 8)` → 32; `calloc(w*h, 12)` non-num →
  `size: None`; `malloc(n+1)` folded; facade rows expose `size_hint`.

### I.25 Cross-function allocation discovery (allocs inside callees)

- **Status**: resolved — allocator rows gain a `callee` key; non-allocator callee RHSs get a one-level decompile walk for `ret` variables assigned from allocators.
  `guess_allocation` returns [] (RHS is a user call; the callee's calloc is
  invisible).
- **Plan**: root RHS is a user call → decompile the callee and rerun the
  upward walk on its allocated/returned locals (one level, capped); rows
  gain a `callee` key.
- **Acceptance**: `guess_allocation(0x140001610, var_name="grid_chain")`
  returns the traced allocator rows; fake two-function test.

### I.26 Vtable-backed allocations should offer a subobject scan (charNode case)

- **Status**: resolved — `scan_from_allocation` converts a vtable-stored allocation via `to_vtable` when the member target is vtable-typed (charNode case).
  (`typeof_charNode: {}`): vftable-class recovered by name
  (`?raw_length@charNode@@UEBAHXZ`) with zero members.
- **Plan**: in the I23 workflow, when the allocated object is stored into a
  vftable-typed member, retype the root / scan with `to_vtable` enabled.
  Ties into I.14's vtable reads.
- **Acceptance**: vtable-bearing allocation returns a non-empty structure
  with the vftable member converted.

### I.21 Add `link_child(structure, offset, child_name)` and store-name type resolution in `add_member`

- **Status**: resolved — `link_child(structure, offset, child_name)` creates relationship + member retype; `add_member` resolves store names via lazy placeholder typedef so self/forward refs parse before the IDB type exists.
  "GridNode *")` fails to parse until the IDB type exists; creating the
  type first then blocks refinement (R10). Hand-built structures never got
  a `child_relationships` edge, so `create_child_types`/finalize's child
  machinery was dead for them.
- **Plan**: `link_child(structure, offset, child_name)` creating the
  relationship and retyping the member; `add_member` resolves type names
  against the store's own names (lazy placeholder typedef on commit) so
  self/forward refs parse before the IDB type exists.
- **Acceptance**: `add_member(..., "GridNode *")` succeeds on an empty IDB
  and the committed cdecl contains the self-referential member;
  `create_child_types("Parent")` returns the child in `created` (with R11
  in place).

---

## Scanner quality

### I.20 Scanner: trace named-symbol direct stores and strcpy-through-root writes

- **Status**: resolved — `scan_global` takes named-symbol stores in range as member candidates (`span` param, u8/u16/u32/u64 arrays for named heads); string/memory writers (`strcpy`/`strncpy`/`strcat`/`memcpy`/`memmove`/`memset`) descend through the destination with `ptr + N` offsets and name-style members. **Issue**: (engine gaps, live 2026-08-12). (1) `scan_global` on an
  object written 30+ times via named globals (`qword_... = …;
  dword_... = …`) returned 2 members @0 — the stores ARE the members but
  only offset-0/pointer-rooted shapes are followed. (2) `strcpy(ptr + N,
  "…")` name-field writes are invisible to `deep_scan` (10+ structs needed
  manual name members).
- **Plan**: `scan_global`: treats stores to addresses in the object's range
  as member candidates keyed by target offset; deep-scan: descend into
  string/memory helpers with the destination expression as root
  (offset = `ptr + N`).
- **Acceptance**: fixture unit: `qword_… = x` store in scan range yields a
  member at that offset; `strcpy(ptr + 0x10, "…")` yields a name-style
  member at 0x10.

### Scan-log observations (2026-08-11, real deep scan) — candidates

- **Format-string/logger callee pollution**: deep scan descended into
  `sub_1400019B0` (printf-style logger) and created bogus members from
  format args (`char *:0x20[0x8]` from `"%s", "pointer_parent"`).
- **Non-function EA decompiles**: `decompile()` succeeds on some
  non-function EAs; visitors should `get_func`-guard and warn.
- **Naming inconsistency**: `i8 *:0x20` vs `char *` alias naming.
- **Double-visit log noise** (harmless) and `None(idx: 0)` tree labels when
  `get_func_name` returns None.

---

## Architecture

### I.28 One central structure database shared by forge_api and the structure builder

- **Status**: resolved — `forge.api.store.StructureCatalog` is the single shared store (dict-like, `unique_name`, `current`, events) with write-through persistence to `Storage("Structures")`; `forge_api._State` delegates to it and the form shares the same catalog object.
- **Issue**: two parallel in-memory stores both holding
  `Structure` models: `forge_api._state.structures`
  (`src/forge_api.py:133-139`) and `StructureBuilderForm.structures`
  (`form.py:64-65`, mutated directly by `child_scan.py:1034-1035`). A
  facade-recovered struct is invisible in the form tree and vice versa; the
  headless store dies with the worker; `_make_unique_structure_name` is
  duplicated verbatim in both (forge_api.py:263-271, form.py:705-714) —
  drift proof.
- **Persistence backend (decided 2026-08-12): `forge/api/storage.py`
  `Storage`** — the existing netnode layer (`PLUGIN_BASE_NETNODE_ID:
  Structures`), JSON + zlib, dict-like API (`storage[name] = …`,
  `get`/`keys`/`iteritems`, `kill()`), `NetnodeCorruptError` handled by
  `.get()` defaults. Precedent already in the repo:
  `forge/features/swap_if/storage.py` (`Storage("SwapIf")` for inversion
  state) — the mirror pattern to follow.
- **Plan**:
  1. New `forge/api/store.py`: `StructureCatalog` (dict + add/update/remove/
     move + child-relationship bookkeeping + unique-name helper +
     provenance), one per process; form/child_scan write through it;
     `forge_api._State` delegates to it.
  2. **Serialization**: `Structure` → a portable descriptor dict (member
     tuple: offset/name/type-string/size/comment/enabled/is_array +
     child relationships + provenance + main_offset) — **never live
     `tinfo_t` handles** (session-bound; the T1.1 leimurr rule). Member
     types round-trip as their declaration strings and re-parse lazily on
     load; unparsable types fall back to `u64` with a warning.
  3. **Persistence**: catalog snapshots to `Storage("Structures")` on every
     mutation (debounced) and loads on process start; `clear_structures`
     calls `storage.kill()`. Survives plugin reload AND worker death — the
     2026-08-12 "store was empty after the agent's worker died" failure
     disappears.
  4. Events `on_added/updated/removed` → the form refreshes its tree on
     facade mutations and vice versa.
- **Other storage candidates (audited 2026-08-12)**:
  - **I.27 mirror metadata** — `Storage("TypeMirror")`: per-type ordinal/
    hash + provenance so the "always up-to-date" baseline survives sessions.
  - **F.5 interchange** — the same portable descriptor makes scan-result
    export/import a `Storage` namespace / JSON file copy.
  - Audited and rejected: templated-types dict (already TOML-file-backed),
    `cache.imported_ea` (cheap per-session recompute), plugin config
    (forge.toml by design), swap_if (already on Storage), UI menu state.
- **Dependencies**: T4.4 `reset()` semantics move to the catalog; I27
  writes into the catalog — land this first or together with I27.
- **Acceptance**: `forge_api.create_structure("X")` + `add_member` is
  visible in the structure builder tree; a form deletion removes it from
  `forge_api.structures()`; unit test asserts both consumers share the same
  `Structure` objects and one unique-name path; **a second fresh worker
  (or plugin reload) sees the catalog from `Storage("Structures")`**;
  existing suite green.

### I.27 Type-library mirror: auto-import IDA's types into forge (bidirectional, custom structs only)

- **Status**: resolved — `import_types(pattern)` (local, non-base, non-`::` UDTs → imported structures), `push_type`/`push_all` (hash-delta sync + `TypeMirror` baseline in `Storage("TypeMirror")`), `refresh_types` (in-place member type updates keeping names, baseline bump).
- **Issue**: (requested 2026-08-12: "auto parse all types into
 forge's structures so we can handle IDA's types in forge", "a mirror to
 IDA's type
 library, always up-to-date: forge changes → IDA, IDA changes → forge").
- **Scope (user-specified)**: structs only; "custom" types only — no base/
  common til, no CRT/winnt system structs, no auto-generated names.
  Live calibration: user DB `named_types` has BYTE/DWORD/_CONTEXT/
  EXCEPTION_RECORD/UNWIND_INFO_HDR (skip) vs PointerParent/ArrayCell/
  GridNode/CellMeta (import). Filter: not in base til, not auto-generated
  (`_CONTEXT::$…` pattern), `tinfo.is_udt()`. Pin the exact predicate in a
  test against the live DB.
- **Plan**:
  1. **IDA → forge** (`forge_api.import_types(pattern=None)`): enumerate
     local til structs (`get_numbered_type_name` + `get_udt_details`),
     create/merge forge `Structure` (provenance "imported", names/
     comments kept); skip per filter. Repeated runs merge; overwrite mode
     depends on R10 + I.18.
  2. **forge → IDA**: `push_type(name)`/`push_all()` — delta sync (hash
     diff) via `set_cdecl`; `create_type`/`finalize` stay the direct path.
  3. **Up-to-date**: freshness check on access (member hash/ordinal) +
     explicit `refresh_types()`; undo-hook only if available; no background
     threads. The freshness baseline (type name → ordinal/hash + import
     provenance) persists in `Storage("TypeMirror")` so "always up-to-date"
     survives sessions (see the I28 storage audit).
- **Acceptance**: on the pure_c DB, `import_types()` returns the custom
  structs and not system ones; a forge-side rename + `push_type` shows in
  IDA; an IDA-side rename + `refresh_` updates the store.

---

## Test infrastructure

### T3.3 Stub-vs-real-IDA drift guard

- **Status**: resolved — `tests/unit/test_stub_signatures.py` pins the stub
  surface against the real call shapes (`get_segm_name`, `add_idc_func`,
  `enum_import_names`, `mark_cfunc_dirty`, `open_pseudocode`,
  `set_lvar_type` → `modify_user_lvar_info`/`MLI_TYPE`,
  `get_named_type`, `apply_tinfo`).
- **Issue**: conftest stubs 20+ `ida_*` modules with permissive
  `lambda *_args: ...`; signature drift is invisible (T1.2's `add_idc_func`
  docs-vs-real mismatch is the model case).
- **Plan**: `test_stub_signatures.py` asserting each stub accepts the exact
  shapes the plugin passes (docs-fetched with cached snapshot, or encoded
  manually); minimum surface: `get_segm_name`, `add_idc_func`,
  `enum_import_names`, `mark_cfunc_dirty`, `open_pseudocode`, `set_lvar_type`,
  `get_named_type`, `apply_tinfo`.
- **Acceptance**: the test fails when a call site's argument shape drifts to
  something the stub accepts but real IDA does not.

---

## Future capabilities (ideas, in value order — not committed scope)

### F.1 Implement member type application (closes the core loop)

- `ScannedStructureMemberObject.apply_type` is a `# TODO` no-op — members of
  created structs never get their types rewritten in IDA
  (`scanner.py:235-250`). Use `get_udt_details`/`udt_member_t.set_type` or
  re-`set_cdecl`; gate behind a "rewrite types" toggle.

### F.2 Batch scans with progress UI

- `decompile` loops block the UI thread; use `replace_wait_box` +
  `decompile_many` with process-function chunking.

### F.3 Finish return-value scanning (see T1.3)

- The deleted `DeepScanReturnVisitor` concept: "this function returns a
  `Foo*` — find every caller's use" — unlocks whole-interface recovery.

### F.4 IDA undo integration for type writes

- `create_type_if_ready`/`set_cdecl`/`rename_created_type` inside
  `ida_undo` snapshots (T4.1 already snapshots `set_cdecl`); de-risks all
  type writes.

### F.5 Scan-result exchange / portability

- Export/import the I28 portable `Structure` descriptor (members,
  provenance, relationships, re-parsed type strings) as a `Storage`
  namespace or JSON file — lets recovered structures move between IDBs and
  be shared with other analysts; the in-IDB persistence itself is I28.

### F.6 Generalize `swap_if` into a ctree-rewriting DSL

- `swap_if` persists inversions across re-decompilation via
  `SilentIfSwapper` maturity hooks — the skeleton for loop-hoisting
  helpers, struct-arg splitting, etc.

### F.7 Lumina metadata backfill

- `func_info_t`/lumina metadata (9.3: `calc_func_metadata`/
  `apply_metadata`) so recovered structure info survives into shared
  analysis.

### F.8 One-shot recovery pipeline (the 2026-08-12 session, packaged)

- The type-recovery recipe is deterministic (replayed twice): retype root →
  create_structure → deep_scan → rename from decompile semantics →
  to_vtable → create_type → retype args → decompile to verify. A facade
  `forge_api.recover(root_ea, var_name="a1", name="...")` orchestrates the
  whole loop; built on I.8 + I.10 + I.12.
- Acceptance: on a fresh DB, `recover(0x1400017A0, var_name="a1")` returns a
  committed named type whose re-decompile shows recovered member names —
  no intermediate raw-IDA calls.

---

## Verification commands

```bash
python -m pytest -q            # full suite (532 passing)
python -m ruff check src tests # clean
git diff --stat HEAD           # confirm no stray working-tree changes
```

## Replication notes

- Windows checkout: git warns "LF will be replaced by CRLF" for
  `src/forge/util/logging.py` — line endings are not a signal.
- The test temp config dir is auto-purged per test
  (`_purge_user_config_dir` fixture in `tests/conftest.py`) — do not write
  test fixtures that persist under `%TEMP%\ida-forge-tests`.
- Real-IDA verification (T1.2, T3.3) requires IDA ≥ 9.0 with Hex-Rays; the
  structure-builder features need the decompiler, the rest don't.
- When touching `types.py`, re-read the leimurr comment — the canonical
  warning for the tinfo-handle class of bug (T1.1).
- Headless (ida-codemode / idalib worker) session notes, 2026-08-12:
  - `importlib.reload(forge_api)` re-executes the module and **wipes the
    forge_api store** — plain `import forge_api` keeps state for the whole
    worker; reload only after editing plugin source.
  - Idle workers disconnect after ~20 s lease (keepalive=0 for
    MCP-spawned workers) — keep curation scripts in one execute or the
    in-memory IDB is lost (scripts are deterministic; fixture needs a cold
    reopen + arg retypes replay).
  - IDA 9.4 lvar API: `cfunc.set_lvar_type` is gone; use
    `modify_user_lvar_info(func_ea, MLI_TYPE, lvar_saved_info_t)`; without
    `MLI_TYPE` it silently fails. `lvar.is_arg_var` is a property,
    `get_next_func(ea)` takes one arg, `rename_lvar` exists /
    `set_lvar_name` does not.
  - The plugin dir (`%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-forge`) is a
    symlink to `src/`; source fixes reach a live worker only after DB
    close/reopen (or hot-patch the cached module attribute).
  - WER dumps: crashed idalib workers drop ~370 MB dumps in the plugin dir
    — worth deleting after a crash storm.

---

## Archived (resolved 2026-08-13)

All 23 open items closed by the forge-api plan (phases A–G); suite 532
passing, `ruff check src tests` clean. One-line summaries (sha1 prefixes
on `forge-api`):

- **R10** — `create_type(overwrite=True)` now deletes by ordinal
  (`get_type_ordinal` → `del_numbered_type`), name-delete fallback, visible
  delete failure; facade distinguishes the three error strings. `e5e52f7`.
- **R11** — headless `finalize`/`finalize_all` route through
  build_cdecl → set_cdecl; failures report a reason, never empty
  `unresolved`. `e5e52f7`.
- **I.12** — `set_lvar_types` (scope arg/all) + `rename_local` via
  `modify_user_lvar_info(MLI_TYPE)` / `rename_lvar`. `d84448d`.
- **I.8** — `deep_scan(root_type=...)` persists root retypes; integral
  scalar roots auto-retype to `void *`. `d84448d`.
- **I.10** — bare `deep_scan`/`shallow_scan`/`scan_from_allocation`
  auto-create `Structure`/`Structure Copy`. `d84448d`.
- **I.9** — `to_vtable` placeholder member + `skipped` reporting on
  disabled-only offsets. `d84448d`.
- **I.11** — `create_type` returns `skipped` collision-disabled member
  names. `d84448d`.
- **I.18** — `get_member(include_disabled=True)`; `add_member`/`set_member`
  report `"collision"`. `d84448d`.
- **I.19** — `apply_type(ea, decl, redefine_range=False)` (store-aware
  parse, TINFO_DEFINITE, range redefinition via `del_items` +
  `del_global_name`). `d84448d`.
- **I.13** — `function_info` / `callers_of(ea, kind=...)` / `callees_of(ea)`
  (dref/code walk, cycle-guarded). `c66bfe8`.
- **I.14** — `vtable_entries(address)` / `vtable_name(address)`, tolerant
  of non-vtable targets. `c66bfe8`.
- **I.15** — `imports(pattern)` via `idautils.Entries()` (9.4-safe).
  `c66bfe8`.
- **I.16** — `decompile(max_lines/line_range/force)` + `signature(ea)`.
  `c66bfe8`.
- **I.17** — `is_type(name)`. `c66bfe8`.
- **I.22** — `set_func_proto(ea, declaration)`. `c66bfe8`.
- **I.23** — `scan_from_allocation` (guess → HEAP row → auto store struct →
  deep_scan → `to_vtable` → `create_type(overwrite=True)`). `a923469`.
- **I.24** — allocator size folding (`mul`/`add`/`sub`), `size: None`
  unknown, `size_hint`/`callee` in rows. `a923469`.
- **I.25** — one-level callee decompile for allocator-returned locals.
  `a923469`.
- **I.26** — vtable-stored allocations offer the subobject scan with
  `to_vtable`. `a923469`.
- **I.21** — `link_child` + store-name placeholder resolution in
  `add_member`. `d84448d`.
- **I.20** — scanner: named-symbol direct stores (`span` + named heads) and
  strcpy/memory-writer member synthesis (allowlist, `char[N+1]` literals).
  `a538825`.
- **I.28** — `forge.api.store.StructureCatalog`: one shared, persisted
  store (`Storage("Structures")`), events, `unique_name`, `current`;
  form + forge_api share it. `71054db`.
- **I.27** — type-library mirror: `import_types` / `push_type` / `push_all`
  / `refresh_types` with the `Storage("TypeMirror")` baseline. `71054db`.
- **T3.3** — `tests/unit/test_stub_signatures.py` pins the conftest stub
  surface to the real call shapes. `7f8d1b8`.