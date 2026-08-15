# Changelog

All notable changes are tracked here. Format: date — change set (branch/commit).

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
