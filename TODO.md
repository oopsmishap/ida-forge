# ida-forge TODO

Work plan derived from the 2026-08-11 project assessment (code read, git history,
scout reports, 246-test run, official IDAPython docs cross-check).

## How to use this file

- Items are ordered by priority within each section. Every item is self-contained:
  **Issue / Evidence / Plan / Acceptance**.
- Evidence gives `file:line`; some line numbers came from a read-only survey pass
  and should be re-confirmed at edit time (files are large and drift).
- Test baseline: `python -m pytest -q` → 246 passing in ~1.3 s on Windows.
  Lint baseline: `python -m pip install ruff && python -m ruff check src tests`
  → 410 findings (273 auto-fixable), of which `src/` carries ~150.
- The suite stubs 20+ `ida_*` modules in `tests/conftest.py` with permissive
  lambdas. **Anything that only works against the stubs is unverified against
  real IDA** — mark such fixes with an explicit "verify in real IDA" acceptance
  step.
- Required-ground rules for fixes: run the specific test that covers the change;
  add a regression test for every bug fix (suite convention: behavior assertions,
  no tautology); never touch `tests/conftest.py` stubs to make a test pass.

---

## Tier 1 — Correctness bugs (fix first, each with a regression test)

### R6 Collision-row KeyError from dropped config default — RESOLVED 2026-08-11

- **Status**: the dark-theme rework (b04c129) removed
  `collision_foreground_color` from `StructureBuilderConfig.default_config`
  while `form.py:1011` kept reading it — any structure with a colliding member
  crashed `update_structure_fields` with
  `KeyError: 'collision_foreground_color'` (real crash reproduced from a scan
  log). Default restored to `#F0DB2B`; regression tests:
  `test_update_structure_fields_collision_state_paints_all_columns`
  (form) and `test_config_forward_fills_missing_nested_form_keys` (nested
  forward-fill — mutation-verified: both fail with the exact KeyError when the
  default is absent). Persisted `cfg/forge.toml` was also patched directly.
  Note: `plugins/ida-forge` under `%APPDATA%` is a symlink to `src/`, so repo
  edits are live in IDA immediately.
- Lesson: b04c129 shipped without a collision-paint test (see G6-adjacent gap).
  The lesson applies to any future config-key removal: grep all readers before
  dropping a default.

### R7 Child scan on typed pointer members silently produced nothing — RESOLVED 2026-08-11

- **Symptom**: "Unable to derive child structure scan results" when child
  scanning `u64_10`/`u64_18` (members holding pointers, declared `__int64`).
- **Root cause (live-reproduced on pure_c_struct_fixture via ida MCP)**: the
  child-scan visitor is created with skip-until-object gating anchored at the
  *evidence ea*. Real evidence anchors at the parent-scan instruction EAs
  (var/asg instructions), and no node at those EAs ever satisfies the
  `StructureReferenceObject` matcher (it only matches `memptr` nodes at the
  member offset). `_skip` therefore never cleared: `_check_call` still spooled
  callee visits (the observed `Add visit` + logger decompiles), but
  `leave_expr` early-returned → zero members, zero member logs. The engine
  itself was fine: evidence anchored at real memptr instruction EAs produced
  the correct child struct (`0x0/0x4/0x8/0x10 _DWORD + 0x1C i8*`).
- **Fix**: `NewDeepScanVisitor` gained `skip_until_object: bool = True`;
  `_scan_evidence_in_function` passes `skip_until_object=False` — member-rooted
  child scans run body-wide (the memptr matcher is precise, so whole-function
  matching is safe and the anchor becomes irrelevant). Var-rooted deep scans
  keep the skip.
- **Tests**: 3 regressions in `test_scanner.py` (`_make_member_scan_harness`
  drives the real visitor over the exact member-use ctree shape): gating
  reproduces the silent failure, skip-disabled creates members from a stale
  anchor, anchored runs still work.
- **Related finding (open→RESOLVED 2026-08-11)**: parent scans of typed functions degrade — when a
  struct is applied, member uses are `memptr` nodes and
  `_extract_member_from_ptr` does not handle a `memptr` first parent, so
  var-rooted deep scans collapse member offsets to 0 (`field_0` only). Fix:
  `_extract_member_from_ptr`/`_extract_member_from_expr` now consume a
  `memptr` first parent (offset = the memptr delta) and `_extract_member`
  peels `add`/`idx` wrappers ahead of a cast in typed functions;
  `_prefer_object_tinfo` only falls back to the scanned object's type when
  the member's ctree type is incomplete (complete scalar member types like
  `__int64`/`char *` are no longer clobbered by the root struct type).
  Regression tests: `test_typed_parent_scan_reads_member_at_memptr_offset`,
  `test_typed_parent_scan_cast_add_shape_preserves_offset_and_type`,
  `test_typed_parent_scan_assignment_uses_memptr_offset`,
  `test_untyped_parent_scan_add_shape_keeps_working`,
  `test_prefer_object_tinfo_only_falls_back_to_object_type_for_unknown_members`
  (+ FakeType `get_pointed_object`). Live-verified on pure_c_struct_fixture:
  typed var-rooted scan of `a1` (test *) now recovers all five fixture
  offsets (0x0/0x8/0x10/0x18/0x20) instead of a single `field_0`.

### Scan-log observations (2026-08-11, real deep scan) — candidates for later tiers

- **Format-string/logger callee pollution**: deep scan descended into
  `sub_1400019B0(...)` (a `printf`-style logger) and created bogus members from
  format arguments (e.g. `char *:0x20[0x8]` from `"%s", "pointer_parent"`).
  Consider excluding callees with varargs/format-string prototypes or a
  heuristics denylist (see F.2 batch-scan note).
- **Non-function EA decompiles**: `Decompiling 0x...38E8 @ <no-function>` —
  `decompile()` succeeds on some non-function EAs (data/thunk regions) and the
  scan visits them; `_recursive_process` should verify `get_func(ea)` before
  preparing a scan, and warn instead of scanning.
- **Naming inconsistency**: `i8 *:0x20` vs `char *` — `types["i8"]`/`char`
  aliases produce different member names for the same semantic type.
- **Double-visit log noise**: several EAs log "Extracting member from
  expression" + "Extracting member" twice (rescan loop re-processing the same
  expression); harmless but makes debug logs 2x longer.
- **Scan tree labels**: `None(idx: 0)` names appear when
  `ida_funcs.get_func_name` returns `None` for a visited EA.

### T1.1 Remove long-lived `tinfo_t` cache in `forge/api/types.py` — RESOLVED 2026-08-11

- **Status**: `_TypeEntry` descriptors (typedef name, ordinal, enum, save flag)
  replaced the cached `Type` instances; every `types[name]` access rebuilds fresh
  handles from the IDB via `_get_type`/`_load_base_tinfo`. Bonus fix found by
  live-IDL verification: `_save_or_load_typedef_to_idb` now logs and falls back
  to ordinal 0 instead of raising when `save_tinfo` refuses a builtin-alias name
  (e.g. "u8" → `unsigned __int8`); the enum path yields the identical type.
  Regression tests: `test_canonical_types_are_rebuilt_fresh_per_access`,
  `test_conversion_reflects_named_type_redefinition`, plus three save-fallback
  tests in `tests/unit/test_types.py`. Verified end-to-end on a live idalib 9.x
  worker (init, freshness, shapes, canonicalization, func_t).
- **Issue**: `Types.__init__` builds `_type_cache` of `Type(name, tinfo_t, ptr,
  const, const_ptr, ordinal)` once at plugin init. IDA invalidates existing
  `tinfo_t` handles when new types are created — and Forge creates types
  constantly (`create_type`, `set_cdecl`, `save_tinfo`). Cached handles can
  dangle, so `convert_to_simple_type` / `equals_to` may compare against stale or
  corrupt types and apply wrong member types to the user's DB. The module even
  contains the warning about this (leimurr comment above `TypesConfig`).
- **Evidence**: `src/forge/api/types.py:13-15` (leimurr warning), `:68`
  (`_type_cache`), `:118-147` (`_add_type_to_cache` and variations), `:224-260`
  (`convert_to_simple_type` cache reads), `:200-222`
  (`_is_canonical_scalar_type`). Test file: `tests/unit/test_types.py` (currently
  fakes the whole class via `compile+exec` + `FakeTinfo`).
- **Plan**:
  1. Rebuild `Type` variations on demand: keep only ordinal/name per scalar and
     construct `tinfo_t` copies from the named type (`get_named_type`) per call,
     or memoize with a "generation" check (bump generation on every
     `save_tinfo`/`create_type` the plugin performs).
  2. `convert_to_simple_type`: after any cache hit, re-fetch the named type and
     verify `equals_to` still holds; drop the entry if not.
  3. `_create_dummy_func` and the `func_t` entry: same treatment.
- **Acceptance**: `test_types.py` still green; new regression test that simulates
  type invalidation (re-create named type mid-session, then call
  `convert_to_simple_type` on a previously canonicalized input) and asserts the
  result is still correct; `Types` exposes no stored `tinfo_t` that outlives a
  single operation where avoidable.

### T1.2 Verify `ida_expr.add_idc_func` argument format on real IDA — RESOLVED 2026-08-11

- **Status**: Verified LIVE on an idalib 9.x worker. The plugin's tuple form
  `(ida_expr.VT_LONG,)` / `(ida_expr.VT_STR,)` is CORRECT — registration,
  IDC round-trip (arg passing + return value), and del/re-add all work. The
  docs' `args: str` typing is misleading SWIG metadata; passing a plain str
  raises `TypeError: 'str' object cannot be interpreted as an integer`.
  Hardened `register_idc_func` (`_register_idc_func`): failures now log a
  warning via the stdlib logger (importing `forge.util.logging` here would be a
  circular import — it imports this module for `PLUGIN_NAME`) instead of
  aborting plugin init. New test file `tests/unit/test_plugin.py` pins the
  exact argument shape (5 tests).
- **Issue**: `register_idc_func` calls
  `ida_expr.add_idc_func(name, plugmod.get_state, (ida_expr.VT_LONG,))`.
  Official docs (`https://python.docs.hex-rays.com/ida_expr/`) type the args
  parameter as `str` (a VT-code array, per the C++ `ext_idcfunc_t`), so a tuple
  may raise `TypeError` at plugin init on real IDA. The conftest stub accepts
  anything, so CI cannot catch it.
- **Evidence**: `src/forge/plugin.py:39-52`; docs `ida_expr.add_idc_func(name,
  fp, args, defvals=(), flags=0)` and `py_add_idc_func(..., args: str, ...)`.
- **Plan**: On IDA 9.2/9.3, run `ida_expr.add_idc_func("forge_test_f",
  some_callable, (ida_expr.VT_LONG,))` and the documented string form; adopt the
  one that works, and make `register_idc_func` log and continue on failure
  instead of letting init die.
- **Acceptance**: plugin `init()` completes on real IDA 9.0 and 9.3 with the IDC
  accessors callable from IDC; unit test asserts the exact argument shape passed
  to `add_idc_func` so stub drift is caught.

### T1.3 Delete or complete `DeepScanReturnVisitor` — RESOLVED 2026-08-11 (deleted)

- **Status**: Deleted the class and its `_iter_callers`/`_prepare_scanner`
  helpers; dropped the now-unused `get_funcs_calling_address` import from
  `scanner.py`. Return-value scanning is tracked as future capability F.3.
- **Issue**: dead class (zero references in `src/`), and internally broken:
  `_start` asserts on `_prepare_scanner()` but discards the decompiled caller
  cfunc; `_finish` calls `_recursive_process()` on the original function without
  ever `prepare_new_scan`-ing callers. `cfunc` is assigned and unused at :761.
- **Evidence**: `src/forge/api/scanner.py:744-770`; grep for
  `DeepScanReturnVisitor` matches only the definition.
- **Plan**: Either remove the class (and its `_iter_callers`/`_prepare_scanner`)
  or implement it properly: in `_start`, decompile each caller EA from
  `self._callers_ea`, `prepare_new_scan(caller_cfunc, arg_idx=-1, obj,
  skip=False)` and run `_recursive_process` per caller. Pick completion only if
  the "scan return value into callers" feature is wanted (see F.3).
- **Acceptance**: no dead-code lint findings for the file; if removed, grep
  confirms no imports; if completed, a scanner test drives a fake two-function
  call graph and asserts members discovered in the caller.

### T1.4 Fix `ObjectVisitor.get_line` dead exception — RESOLVED 2026-08-11

- **Status**: `get_line` now logs a warning and returns `""` on the no-parent
  fallback (matching `hexrays.get_line`, which also returns `""` now).
  Deliberately NOT a raise: `guess_allocation` calls it to build chooser rows,
  and a raise would abort the traversal mid-scan on unusual trees.
- **Issue**: `AssertionError("Parent instruction is not found")` is constructed
  but never raised; function falls through and returns `None`.
- **Evidence**: `src/forge/api/visitor.py:58` (ruff PLW0133). Same lookup
  duplicated in `src/forge/api/hexrays.py` `get_line` (logs a warning instead).
- **Plan**: raise the exception (matching `hexrays.get_line`'s contract would
  also be fine if callers tolerate `None` — check callers first; there appear to
  be none in `src/` for `visitor.get_line`).
- **Acceptance**: ruff clean on the file; test asserting the raise when no
  non-expr parent exists.

### T1.5 Add missing `Iterator` import in structure builder form — RESOLVED 2026-08-11

- **Status**: `Iterator` added to the `typing` import in `form.py`.
- **Issue**: `Iterator` used in a return annotation but not imported
  (`form.py` imports only `Dict, Optional` from `typing`). Latent under
  `from __future__ import annotations`; breaks `get_type_hints`/tooling.
- **Evidence**: `src/forge/features/structure_builder/form.py:1-4` and
  `:486` (ruff F821 at 483:35).
- **Plan**: add `Iterator` to the `typing` import; optionally run auto-fix.
- **Acceptance**: `python -m ruff check src` no F821 for the file; suite green.

---

## Tier 2 — Structural debt (ALL RESOLVED 2026-08-11)

- T2.1 `collect_ctree_items_near_ea` in `forge/api/hexrays.py`; form.py +
  child_scan.py chains migrated (3 sites); exhaustive vs short-circuit modes;
  conftest carries a faithful behavioral double; 6 new tests.
- T2.2 `_execute_visit` extracted; both loops in
  `RecursiveDownwardsObjectVisitor._recursive_process` now share it
  (`_VISIT_DEFERRED` sentinel distinguishes retry from drop; `progressed`
  semantics preserved exactly).
- T2.3 `_execute_child_scan_plan` split into `_collect_evidence_by_function`
  + `_scan_evidence_in_function`; `_build_child_scan_plan` guards extracted to
  `_sorted_scan_evidence` + `_member_scan_tinfo`; 4 new direct unit tests; no
  function in child_scan.py exceeds 120 lines (max is `_build_child_scan_plan`
  at 95).
- T2.4 src/ is now free of BLE001/S110: silent swallows in
  `templated_types/form.py` log warnings; eager chains log at debug; genuine
  IDA-version-tolerance sites carry `# noqa` with reasons; explored a mutation
  check via the stale `# noqa` removal (config.py re-raise case).
- T2.5 `visitor.ObjectVisitor.get_line` delegates to `hexrays.get_line`.
- T2.6 `hexrays.get_ptr(ea)` → `read_pointer(ea)`; `Types.get_ptr` →
  `get_ptr_tinfo`; all call sites + test fakes renamed.
- T2.7 16-bit (width 2) supported: `_size_t_enum` picks BTF_UINT16,
  `get_ptr_type` returns u16; init assert replaced with a runtime width check;
  new tests cover width detection and the u16 pointer path.

### T2.1 Extract the duplicated ctree-item lookup chain

- **Issue**: the treeitems → eamap → find_closest_addr fallback chain is
  copy-pasted 5×, each copy carrying its own bare `except Exception: pass`.
  These bare excepts are exactly the hiding places for the next IDA API break
  (the 9.3 `is_imported` crash is the model for what happens when they fire).
- **Evidence**: `src/forge/features/structure_builder/form.py:1703-1771`,
  `:1756-1803`; `src/forge/features/structure_builder/child_scan.py:107-142`,
  `:250-277`, `:1761-1780`.
- **Plan**: one helper in `forge/api/hexrays.py` or a new
  `forge/api/ctree_lookup.py`: `resolve_item_near_ea(cfunc, ea) ->
  ctree_item_t|None`, with per-fallback logging (`log_debug` on fallback, no
  swallowing); migrate all five call sites; keep `form.py` and `child_scan.py`
  identical behavior (verified by existing form/actions tests).
- **Acceptance**: grep shows no remaining copy of the chain; a unit test feeds a
  fake cfunc whose `eamap` raises and asserts the debug log + graceful fallback.

### T2.2 Deduplicate the two recursive-scan loop bodies in `visitor.py`

- **Issue**: `RecursiveDownwardsObjectVisitor._recursive_process` contains two
  near-identical ~60-line blocks (`while pending_visits` and
  `while deferred_visits`) for state save/restore, `acc_offset` accumulation,
  and child-visit re-queueing. One drift is already visible: `self._cfunc.argidx`
  vs `getattr(cfunc, "argidx", ())` between the copies.
- **Evidence**: `src/forge/api/visitor.py:470-650` (survey-verified range;
  re-confirm at edit). Covered by `tests/unit/test_visitor.py` (733 lines).
- **Plan**: extract a `_scan_visit(func_ea, arg_idx, acc_offset) -> bool`
  (decompile, argidx bounds check, `prepare_new_scan`, scan, re-queue children,
  restore state); both loops call it. Keep the deferred-retry semantics.
- **Acceptance**: `test_visitor.py` and `test_scanner.py` fully green with the
  same assertions; behavior diff is zero (run suite before/after).

### T2.3 Split `_execute_child_scan_plan` (201 lines)

- **Issue**: `child_scan.py:703-903` — deep nesting, multiple early-return
  guard branches, and it is the *only* module of the inference engine with no
  direct test coverage (see T3.4).
- **Plan**: extract plan validation, per-evidence-function decompile+scan, and
  structure-creation/relationship bookkeeping into named helpers; write tests
  per helper as part of T3.4.
- **Acceptance**: no function > 120 lines in `child_scan.py`; new unit tests
  cover the extracted helpers.

### T2.4 Blanket exception hygiene pass

- **Issue**: 29 blind `except Exception` + 12 `try/except: pass` in `src/`.
  Each is a candidate for logging or narrowing (`DecompilationFailure`,
  `AttributeError`, `KeyError`).
- **Evidence**: `python -m ruff check src --statistics` (BLE001, S110 rows);
  worst files: `api/scan_object.py` (149/171/220), `api/scanner.py:383`,
  `api/config.py:42`, `templated_types/form.py:92,116`,
  `structure_builder/child_scan.py` (9 instances, listed in survey).
- **Plan**: per-site triage — narrow the exception, log at debug with context,
  or restructure to avoid try/except (e.g. `hasattr`/`callable` guards where the
  failure is a missing API). Do not blanket-replace blindly: some are
  intentional IDA-version tolerance (add `# noqa: BLE001` with comment where
  deliberate).
- **Acceptance**: BLE001/S110 counts down; suite green; no behavior change in
  tests.

### T2.5 Collapse duplicated `get_line` in api layer

- **Issue**: `hexrays.get_line` (logs + returns None) and `visitor.get_line`
  (dead raise, T1.4) are the same utility with divergent error handling, and
  both use the fragile `cfunc.__ref__()` calling convention.
- **Plan**: keep one implementation in `forge/api/hexrays.py`, delegate from
  `visitor`, and check the single caller of each.
- **Acceptance**: grep shows one definition; suite green.

### T2.6 Rename the two `get_ptr` functions

- **Issue**: `forge/api/hexrays.py:get_ptr(ea)` (reads a pointer-sized value
  from the DB) and `forge/api/types.py:get_ptr()` (returns a pointer `tinfo_t`)
  share a name; future imports will collide.
- **Plan**: rename to `read_pointer(ea)` / `get_ptr_tinfo()` (or similar),
  update call sites, prefer explicit imports over `from x import *`
  (`visitor.py` currently star-imports `hexrays`).
- **Acceptance**: grep for `get_ptr` shows unambiguous remaining uses; suite
  green.

### T2.7 Make the 16-bit pointer-width path not crash plugin init

- **Issue**: `Types.__init__` does `assert self._type_width in (4, 8)` while
  `_get_ptr_width()` can return 2 for 16-bit binaries → plugin refuses to load.
- **Evidence**: `src/forge/api/types.py:67` (assert) and `:289-302`
  (`_get_ptr_width`).
- **Plan**: treat width 2 as unsupported-with-log (skip type loading, warn) or
  support it; either way no hard assert on user binaries.
- **Acceptance**: unit test constructs `Types` under a fake `inf_is_16bit` and
  asserts a warning, not an exception; or explicit support for 16-bit.

---

## Tier 3 — Test infrastructure

### T3.1 Add CI — RESOLVED 2026-08-11

- **Status**: `.github/workflows/ci.yml` — ubuntu + windows × Python 3.9/3.12
  matrix; installs `.[dev]` + ruff, runs `ruff check src tests` and
  `python -m pytest`. Failing lint or tests fails the build.
- **Issue**: no `.github/`, no lint config, no CI at all. The June 14 fixes
  (`is_imported`, `qt_item_flags`) were all found in real IDA — a CI gate would
  have caught several earlier.
- **Plan**: GitHub Actions workflow: `ubuntu + windows`, Python 3.9 and 3.12,
  `pip install .[dev] ruff`, run `python -m ruff check src tests` and
  `python -m pytest -q`. Consider a second job that asserts stub signatures
  against a pinned snapshot of `python.docs.hex-rays.com` (see T3.3).
- **Acceptance**: workflow file exists and passes on a fresh clone; failing a
  test fails the build.

### T3.2 Add ruff config and fix the baseline — RESOLVED 2026-08-11

- **Status**: `[tool.ruff]` + `[tool.ruff.lint]` in pyproject.toml
  (target-version py39, line-length 120, select E/F/I/UP/B/SIM/BLE/PL/RUF/FA/
  PIE/TRY/RET/C4/S; class-level ignores carry reasons — E501, S101, PLR2004,
  PLR091x complexity, PLC0415 lazy IDA imports, F403/F405 star imports
  (tracked by I.4)). `ruff check src tests` now exits 0 (was 410 findings).
  Notable migrations: `from __future__ import annotations` added where PEP 604
  unions are used (py39-safe), `Optional[X]` → `X | None`, mutable class
  defaults annotated `ClassVar` (incl. chooser `cols`), `parse_decl`/lazy-import
  swallow sites converted to `contextlib.suppress`, en-dash doc typos fixed
  (`x–` → `x--`), `raise Exception("Unsupported architecture")` → dedicated
  `UnsupportedArchitectureError`, `__hash__ = None` on eq-mutating member
  classes. Two tests were re-pointed at the real owners after F401 pruning
  removed dead re-exports from form.py (`ChildScanPlan`,
  `NewDeepScanVisitor`, `is_legal_type` now patched on `child_scan_module`).
- **Issue**: 410 findings; no `ruff.toml`/`pyproject` `[tool.ruff]` section, so
  defaults apply and nobody runs it.
- **Plan**: `[tool.ruff]` in `pyproject.toml` (target-version py39, select a
  stable set — E/F/I/UP/B/SIM/BLE/PL — with per-line `noqa` where deliberate),
  `ruff check --fix` for the 273 auto-fixable, then hand-fix the rest.
- **Acceptance**: `python -m ruff check src tests` exits 0; CI enforces it.

### T3.3 Stub-vs-real-IDA drift guard

- **Issue**: conftest stubs 20+ modules with permissive `lambda *_args: ...`;
  scanner/visitor tests bypass conftest via `spec_from_file_location`. Signature
  drift is invisible (T1.2 is the live example).
- **Plan**: add a `tests/unit/test_stub_signatures.py` that asserts each stub
  function accepts the exact argument shapes the plugin passes (fetch
  signatures from the docs site at test time with a cached snapshot, or encode
  them manually); at minimum cover `get_segm_name`, `add_idc_func`,
  `enum_import_names`, `mark_cfunc_dirty`, `open_pseudocode`, `set_lvar_type`,
  `get_named_type`, `apply_tinfo`.
- **Acceptance**: new test fails when someone changes a call site's argument
  shape to something the stub also accepts but real IDA does not — encode the
  documented signature, not the stub's.

### T3.4 Cover the untested modules — RESOLVED 2026-08-11 (priority list)

- **Status**: `child_scan.py` covered (T2.3 + R7 follow-up: 6 direct tests).
  New direct test files: `test_itanium_mangler.py` (golden corpus of
  namespace/pointer/const/ctor/dtor/const-member-fn manglings + substitution
  reuse + NotImplementedError boundaries for templates/function-pointers/
  r-value refs), `test_cxx_to_c_name.py` (42-entry operator table +
  identifier sanitation), `test_logging.py` (msg/warning routing, message-box
  gating, reload handler dedupe), `test_singleton.py`, `test_swap_if_helper.py`
  (condition negation + branch swap), `test_create_new_field.py`
  (parse_declaration incl. array size), `test_convert_to_usercall.py`
  (convention mapping incl. I.2 cleanup: `check()` honors the `enabled`
  config key and the conversion logs the target convention). Conftest gained
  `ctree_parentee_t` (same stub the scanner tests already needed).
- **Issue**: no direct tests for `child_scan.py` (the 1084-line inference
  engine), `util/itanium_mangler.py`, `util/cxx_to_c_name.py`,
  `util/logging.py`, `util/qt.py`, `util/singleton.py`,
  `create_new_field/create_new_field.py`,
  `convert_to_usercall/convert_to_usercall.py`, `swap_if/helper.py`.
- **Plan (priority order)**:
  1. `child_scan.py`: reuse the `test_scanner.py` fake-ctree pattern; cover
     `_resolve_scan_variable_target`, `_build_child_scan_plan`
     (show_warnings=False AND True), `_execute_child_scan_plan` happy path,
     `_propagate_child_scan_seed` with `None` parent-arg index (G11), the
     `ScanObject.create` fallback (G13), explicit `parent_expr` kwarg (G14).
  2. `itanium_mangler.py`: golden corpus of names (namespace, pointer, const,
     ctor/dtor, const-member-fn) with expected mangled output; assert
     `NotImplementedError` for template/function-pointer/rvalue-ref inputs.
  3. `cxx_to_c_name.py`: add missing operators first (see I.5), then table tests.
  4. `util/logging.py`, `util/qt.py`, `singleton.py`: small behavior tests.
  5. `create_new_field`, `convert_to_usercall`, `swap_if/helper.py`: happy path +
     the dead-config cleanup from I.2.
- **Acceptance**: every `src/forge` module has at least one direct test file;
  assertions are behavioral.

### T3.5 Close the 19 form/actions/child-scan gaps (from survey) — RESOLVED 2026-08-11

- **Status**: every gap now has a greppable regression test.
  G1 `test_duplicate_structure_copies_child_links_then_normalizes`; G2
  `test_remove_structure_cleans_other_structures_relationships`; G3
  `test_nudge_main_offset_follows_selected_member`; G4
  `test_structure_table_clear_decline_keeps_members`; G6
  `test_convert_to_vtable_decline_preserves_member`; G7
  `test_structure_table_item_changed_name_vs_comment_column`; G9
  `test_member_child_link_normalization_clears_stale_links`; G10
  `test_make_unique_structure_name_copy_collision_loop`; G11
  `test_propagate_child_scan_seed_unresolvable_parent_arg_is_noop`; G12
  (pre-existing) `test_parse_left_assignee_scales_nested_index_offsets`; G13
  `test_create_scan_object_from_expr_fallback_paths`; G14
  `test_build_child_scan_inference_seed_explicit_parent_expr_skips_anchor`; G15
  `test_build_child_scan_plan_warns_when_parent_type_missing_from_idb`
  (`show_warnings=True`) + the R7 plan tests; G16
  `test_scan_global_references_empty_xref_set_warns`; G17
  `test_prompt_scan_depth_parses_input` (decline/empty/garbage→config-default/
  valid); G18 `test_provenance_kind_for_object_mapping`; G19
  `test_ensure_structure_selected_no_selection_prompts_and_warns`. G8 (tree
  context menu) and G5 (clipboard fallback) remain UI-shell behaviors whose
  dialogs need a live Qt harness — noted under Tier 4.
- G1 duplicate-child duplicating; G2 orphan cleanup on remove; G3 main_offset
  follows nudge; G4 `structure_table_clear` decline path; G5 clipboard fallback
  branch; G6 `convert_to_vtable` user-declines-but-proceeds; G7 name vs comment
  column edit; G8 tree context menu; G9 member with child link + scanned
  variables combined; G10 `_make_unique_structure_name` "Copy N" collision loop;
  G11 seed propagation with unresolvable parent arg; G12 deeper idx-nesting;
  G13 `_create_scan_object_from_expr` fallback; G14 explicit `parent_expr`;
  G15 `show_warnings=True`; G16 `_scan_global_references` empty xref set;
  G17 `_prompt_scan_depth` non-integer input; G18 `local_variable` provenance
  kind; G19 stale-UI path of `_ensure_structure_selected`.
- **Evidence**: `tests/unit/test_structure_builder_form.py` (2512 lines),
  `test_structure_builder_actions.py`, `test_structure_stats.py`.
- **Acceptance**: one test per gap; all named in the gap list above become
  greppable test names.

---

## Tier 4 — User-facing risks (IDA type corruption)

### T4.1 Dry-run confirmation for `auto_resolve` — RESOLVED 2026-08-11

- **Status**: `Structure.auto_resolve_preview()` is a read-only walk returning
  exactly the members that would be disabled; `structure_table_resolve` shows
  an `ask_yn` confirm with the count and declines without touching members.
  `set_cdecl` writes now run inside an `ida_undo` snapshot
  (`_type_write_undo` context manager, guarded for the unit-test env), so a
  bad auto-resolve/overwrite result is one `undo` away. Tests:
  `test_auto_resolve_preview_reports_without_mutating`,
  `test_auto_resolve_preview_disables_lower_scored_earlier_member`,
  `test_structure_table_resolve_confirms_before_disabling`,
  `test_set_cdecl_wraps_type_write_in_undo_snapshot`,
  `test_set_cdecl_undo_is_absent_without_ida_undo`.
- **Issue**: `auto_resolve()` silently overwrites member `tinfo` values; a
  wrong heuristic clobbers a correct user-typed member.
- **Evidence**: `form.py:1975` (survey-verified; re-confirm), `Structure.auto_resolve`
  in `src/forge/api/structure.py:395-421`.
- **Plan**: show a preview (count of members whose tinfo would change) with
  Yes/No; add an "undo" via `ida_undo` snapshot (see F.4).
- **Acceptance**: dialog appears with accurate preview when overwrites would
  occur; form test asserts the confirm path.

### T4.2 Block nudge-into-collision — RESOLVED 2026-08-11

- **Status**: `nudge_selected_rows` snapshots offsets, and after
  `refresh_collisions` rejects (with a warning) any nudge whose collision set
  includes a member the user did not select — restoring every offset and the
  main_offset. Test: `test_nudge_into_collision_with_unselected_member_is_rejected`.
- **Issue**: bulk nudging offsets can create overlapping members that reach
  `pack_structure` → IDA `add_struc_member` with undefined behavior.
- **Evidence**: `form.py:1465` `nudge_selected_rows` (survey-verified);
  `Structure.refresh_collisions` at `structure.py:330-360`.
- **Plan**: after applying the delta, if new collisions involve a non-selected
  member, reject the nudge with a message; keep `refresh_collisions` as the
  single source of truth.
- **Acceptance**: unit test: nudge that would overlap an unselected member is
  refused and member offsets unchanged.

### T4.3 Guard live-type rename and `BADADDR` UI calls — RESOLVED 2026-08-11

- **Status**: `hexrays.decompile` now rejects `BADADDR` and any EA where
  `ida_funcs.get_func` returns None ("not a function" warning) — the same
  guard closes the scan-log observation about decompiling non-function EAs.
  The dialogs chooser already guarded `open_pseudocode` on `BADADDR` and
  `get_func_name` was already EA-guarded. Tests:
  `test_decompile_rejects_badaddr`, `test_decompile_rejects_non_function_ea`,
  `test_decompile_delegates_to_real_function`.
- **Issue**: `rename_created_type` on a type referenced by lvars leaves
  dangling references (`structure.py:215-235`, `form.py:1553`); `open_pseudocode`
  with `BADADDR` (`dialogs.py:40`) and `get_func_name(BADADDR)`
  (`form.py:1860`) misbehave on invalid EAs.
- **Plan**: skip rename with a warning when the EA is unmapped/BADADDR; pass
  real EAs only; add `func_ea != BADADDR` guards.
- **Acceptance**: tests passing `BADADDR` assert warning + no IDA calls.

### T4.4 Reset form/plugin singleton state on reload — RESOLVED 2026-08-11

- **Status**: `StructureBuilderForm.reset()` clears `structures` +
  `current_structure` and the cached UI state; `OnClose` calls `reset()` so a
  closed form never resurrects stale models, and `forge_plugmod_t._reload_inner`
  resets the pre-reload singleton before the re-import (via a guarded import).
  Tests: `test_on_close_clears_structure_models`,
  `test_reload_inner_resets_structure_form_models`.
- **Issue**: `StructureBuilderForm` singleton keeps `self.structures` and
  `self.current_structure` across `_reset_ui_state()`; stale in-memory models
  survive reload/close-reopen.
- **Evidence**: `form.py:64-70` (survey-verified); `actions.py` imports the
  module-level `structure_form`.
- **Plan**: clear structures on `OnClose`, and clear (or prompt to keep) on
  reload; make the reload path in `forge_plugmod_t._reload_inner` call a new
  `structure_form.reset()`.
- **Acceptance**: reload test asserts empty structure dict after reset; existing
  `test_plugin_reload.py` stays green.

---

## Tier 5 — Improvements

### I.1 Revert uncommitted DEBUG log level; make log level configurable — RESOLVED 2026-08-11

- **Status**: logger defaults to INFO; `set_log_level(name|constant)` +
  `LOG_LEVELS` (incl. `TRACE` = 5) configure it, and plugin init reads the
  root `ForgeConfig["log_level"]` key (`_apply_log_level` in forge_plugmod_t)
  before anything logs. `log_trace` added and used for scan-preparation noise.
  Tests: `test_set_log_level_accepts_names_and_constants`,
  `test_logger_defaults_to_info_not_debug`.

- **Issue**: working tree sets `_logger.setLevel(logging.DEBUG)` (uncommitted);
  committed default per `fe69a5e` was INFO. Levels are hardcoded all-or-nothing.
- **Evidence**: `git diff` on `src/forge/util/logging.py:12`;
  `src/forge/util/logging.py:17-18`.
- **Plan**: commit the INFO default (or wire a config option `log_level` read at
  plugin init), keep the handler dedupe marker.
- **Acceptance**: `git status` clean (or intentional); a config test asserts the
  level follows the option.

### I.2 Remove dead `ConvertToUsercallConfig` wiring — RESOLVED 2026-08-11

- **Status**: `check()` now honors `config["enabled"]` (popup item hidden when
  disabled); `activate()` logs the converted convention (`__usercall` /
  `__usercall_` / `__usercalle_`) after `apply_tinfo`. Covered by
  `test_convert_to_usercall.py` (enabled-gating, convention mapping ×6,
  unknown-cc and missing-func-type early returns).
- **Issue**: `self.config = ConvertToUsercallConfig()` instantiated, never read;
  no `enabled` guard honored.
- **Evidence**: `src/forge/features/convert_to_usercall/convert_to_usercall.py:9-24`.
- **Plan**: honor `config["enabled"]` in `activate()` (or delete the config
  class); log the new calling convention after conversion.
- **Acceptance**: test toggling `enabled` flips action behavior.

### I.3 Entity naming cleanup — RESOLVED 2026-08-11

- **Status**: no `getattr(obj, "tinfo"`/`id` reads remain in src — the two
  tinfo reads in scanner.py use `obj.tinfo` directly; `ScannedObject.create`
  legacy migration shim deleted (unreachable: every object has an `id`), with
  an `AssertionError` guard for unknown ids. Tests updated:
  `test_scanned_object_create_rejects_unknown_object_type` replaces the legacy
  shim test.

- **Issue**: scan pipeline uses magic attribute access (`getattr(obj, "tinfo",
  None)`, `getattr(obj, "id", None)`) instead of defined properties; legacy
  migration shims (`ScannedObject.create`) persist.
- **Plan**: define explicit `id`/`tinfo`/`ea` properties on `ScanObject`
  subclasses; keep the legacy path only if still reachable (grep callers), else
  delete. Do not rush: scanner tests depend on current shapes.
- **Acceptance**: grep shows no `getattr(obj, "tinfo"` reads; suite green.

### I.4 Logging conventions — RESOLVED 2026-08-11

- **Status**: `log_trace` added; `visitor.py`'s `from forge.api.hexrays import
  *` replaced with an explicit import list (conftest stub gained the now-
  imported `get_argument`/`get_argument_index`/`get_line`/etc — T3.3-style
  stub-drift gap). `FunctionTouchVisitor.process` reset bug fixed:
  `self._functions = set()` between `apply_to` collection and
  `touch_all_iterative` discarded the nested-call set, so process() touched
  nothing below the top level; now the collected set feeds the iteration.

- **Issue**: no `log_trace`; `FunctionTouchVisitor.process` resets
  `self._functions` mid-run (works by accident — re-audit); `visitor.py`
  star-imports `hexrays_api` *and* `from forge.api.hexrays import *`.
- **Plan**: add `log_trace`; replace star imports with explicit names
  (T2.6 partner); fix the `FunctionTouchVisitor.reset` order after auditing.
- **Acceptance**: ruff clean for the touched files; behavior tests for
  `FunctionTouchVisitor` (currently untested).

### I.5 Extend `cxx_to_c_name.py` operators — RESOLVED 2026-08-11

- **Status**: added `operator<=>` (spaceship), `operator co_await`, and
  `operator->*` to the replacement table (longest-first, ahead of `<`/`->`);
  conversion operators (`operator TYPE`) already survive as `operator_<type>`
  via sanitize — covered by tests.

- **Issue**: missing `operator<=>` (spaceship), `co_await`, conversion
  operators; unary/binary `& * + -` collapse to one textual form.
- **Evidence**: `src/forge/util/cxx_to_c_name.py:7-57`.
- **Plan**: add the missing operators; make unary vs binary distinct where the
  mangled name allows (`operator&` vs `operator&&` already exist); keep the
  existing `sanitize_c_identifier` behavior.
- **Acceptance**: table-driven tests for every operator (I.4/T3.4 step 3).

### I.6 Drop the `toml` dependency where possible — RESOLVED 2026-08-11 (read path)

- **Status**: config reads use stdlib `tomllib` (binary mode) on Python 3.11+
  (IDA 9.x ships 3.12), falling back to the `toml` package on 3.9/3.10. The
  `toml` dependency remains declared because writes still need it (tomllib is
  read-only). The crash where tomllib objects to text-mode files is covered by
  the binary-mode read.

- **Issue**: runtime dep `toml>=0.10` in `pyproject.toml`; Python ≥3.9 IDA ships
  `tomllib` (3.11+) — IDA 9.x bundles 3.12. Keep `toml` as a fallback for
  older IDA builds per `idaVersions: 9.0+`.
- **Plan**: `try: import tomllib except ImportError: import toml as tomllib`
  in `forge/api/config.py`; keep the dep declared for 3.9/3.10.
- **Acceptance**: config tests pass with `tomllib`; an import test asserts the
  fallback branch.

### I.7 Stale docs — RESOLVED 2026-08-11

- **Status**: root `README.md` rewritten (features, install, config table,
  development/test instructions); `src/README.md` describes the package
  layout; pyproject gained a description.

- **Issue**: root `README.md` says "not functional yet"; `src/README.md` is 156B.
- **Plan**: rewrite with feature list, install/plugin-manager instructions,
  hotkeys, development/test instructions; update `pyproject` version/description
  if still 0.0.1.
- **Acceptance**: README describes real features and how to run tests.

---

## Future capabilities (ideas, in value order — not committed scope)

### F.1 Implement member type application (closes the core loop)

- **Issue**: `ScannedStructureMemberObject.apply_type` is a `# TODO` no-op
  (warning + return). Members of created structs never get their types rewritten
  in IDA, so scan evidence is only half-applied.
- **Evidence**: `src/forge/api/scanner.py:235-250`.
- **Plan**: use `tinfo_t.get_udt_details`/`udt_member_t.set_type` path or
  re-`set_cdecl` the affected member; gate behind a "rewrite types" toggle.
- **Acceptance**: a created struct's member shows the recovered type in the
  IDA Types view after a scan.

### F.2 Batch scans with progress UI

- Deep scans currently block the UI thread per function (`decompile` loops in
  `visitor.py`/`child_scan.py`). Use `ida_kernwin.replace_wait_box` +
  `ida_hexrays.decompile_many` and process-function chunking.

### F.3 Finish return-value scanning (see T1.3)

- The dead `DeepScanReturnVisitor` is the intended inverse of argument
  propagation ("this function returns a `Foo*` — find every caller's use").
  Completing it (rather than deleting) unlocks whole-interface recovery.

### F.4 IDA undo integration for type writes

- Wrap `create_type_if_ready` / `set_cdecl` / `rename_created_type` in
  `ida_undo` snapshots so type corruption is reversible — this de-risks the
  entire Tier 4.

### F.5 Persistent scan-result export/import

- Beyond debug CSV: JSON export/import of `Structure` models (members,
  provenance, relationships) via the existing `Storage` netnode layer or IDB
  sidecar, so recovered structures survive re-analysis and can be shared.

### F.6 Generalize `swap_if` into a ctree-rewriting DSL

- `swap_if` already persists inversions across re-decompilation via
  `SilentIfSwapper` maturity hooks; that hook infrastructure is the skeleton for
  other decompiler-ergonomics features (e.g. loop hoisting helpers, struct-arg
  splitting).

### F.7 Lumina metadata backfill

- Push scan evidence into `func_info_t`/`lumina` metadata (9.3 supports
  `calc_func_metadata`/`apply_metadata`) so recovered structure info survives
  into Lumina-shared analysis.

---

## Verification commands

```bash
python -m pytest -q                 # full suite (baseline: 246 passed)
python -m pip install ruff          # linter (not currently in dev deps)
python -m ruff check src tests      # baseline: 410 findings / 273 fixable
python -m ruff check src --statistics
git diff --stat HEAD                # confirm no stray working-tree changes
```

## Replication notes

- Windows checkout: git warns "LF will be replaced by CRLF" for
  `src/forge/util/logging.py` — line endings are not a signal.
- The test temp config dir is auto-purged per test
  (`_purge_user_config_dir` fixture in `tests/conftest.py`) — do not write test
  fixtures that persist under `%TEMP%\ida-forge-tests`.
- Real-IDA verification (T1.2, T3.3) requires IDA ≥ 9.0 with Hex-Rays; the
  structure-builder features need the decompiler, other features don't.
- When touching `types.py`, re-read the leimurr comment — it is the canonical
  warning for the exact class of bug in T1.1.