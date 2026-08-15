# ida-forge TODO

Current state (2026-08-15): all planned work is done — the assessment
wave, the forge-api plan (R10/R11, I.8–I.28, T3.3), the O1–O5 pass, the
E-series bug fixes, the round-2 review fixes, both recovery evals
(round 1 baseline; round 2 = **99/100** on the cold fixture, 20/20
types, 5/5 globals, 10/10 flows), and the **full E/R/F closure wave**
(commits `726dd8b`..`cb55b3f`): R2.1–R2.6 + E.13–E.29 + F.1–F.8 all
implemented and live-verified (see CHANGELOG 2026-08-15).
**`CHANGELOG.md` owns the completed history**; this file tracks only
open work.

Baselines: `python -m pytest -q` → 632 passing; `python -m ruff check
src tests` → clean; branch `forge-api` clean working tree.

## Closed in the 2026-08-15 closure wave (commits 726dd8b..cb55b3f)

Everything below was OPEN at the previous snapshot and is now
implemented, unit-tested and live-verified against the fixture worker;
the detail lives in CHANGELOG.md 2026-08-15:

- **R2.1** placeholder-size poison at pack — `Member.effective_size()`
  resolves the FRESH pack tinfo (unit + live: `PackParent` cdecl packs
  the 40-byte child with no chain shift).
- **R2.2/R2.3** `apply_type(redefine_range=True)` — DELIT_DELNAMES
  whole-span apply + `auto_wait` + verify/retry + base-name restore;
  live: `g_main_outer` 320 B / `g_static_grid` 16 B items, name kept,
  member access renders, persists across save/reopen, guard sibling
  stable.
- **R2.4** `del_items` end-vs-size — recorder test pins
  `(ea, DELIT_DELNAMES, ea + size)`; span-end sibling intact live.
- **R2.5** `intN`/`uintN` aliases; **R2.6** keyword member names loud
  (`_validate_member_name`).
- **E.21** `deep_scan`/`shallow_scan(clear_first=)`. **E.22/R2.7**
  helper-mediated allocation rows + ≤2-hop alias chain + pointer-return
  fallback; live `guess_allocation` on the fixture's `make_chain`
  returns a HEAP row (size folded to 40) and `scan_from_allocation`
  commits the type. **E.23** IAT-slot callee resolution.
  **E.24** `(offset, name, type)` member triple match.
  **E.25** `scan_global` exclusive-tail extension for data-referenced
  boundary heads. **E.26** mirror honesty (`skipped` reason dict,
  `refresh_types(include_names=)`). ~~**E.27** `remove_type`~~ — removed
  by R3.1 (update-not-delete: `create_type(overwrite=True)` now updates
  the til in place; `undo_type` refuses to delete; `remove_structure`
  refuses committed structures).
  **E.28** inline-union member parse + pack (live: `VariantT` 16 B, 4
  tags). **E.29** `create_typedef`. **E.14** `name_members_from_printf`
  (live: PointerParent members named from `log_msg` formats: parent/
  magic/count — local-wrapper + cast-peel + lvar-idx forms all live).
  **E.16** stride collapse. **E.17** `undo_type` + commit snapshots.
  **E.18** `split_flags` (byte-aligned only). **E.19** `reapply`.
  **E.20** tweak batch (commit-error surfacing, `nudge_members` moved
  map, `include_disabled=False` default, `max_lines` doc note,
  "not a code-pointer array", empty-import note).
- **F.1** `ScannedStructureMemberObject.apply_type` via
  `get_udt_details`/`set_type`/`set_udt_details`. **F.2**
  `decompile_many`. **F.3** `scan_returned` (`iter_returned_exprs`
  moved to `forge.api.hexrays`). **F.4** superseded by E.17 snapshots.
  **F.5** `export_store`/`import_store` (JSON, headless). **F.6**
  `forge.api.ctree_transform` DSL (`CtreeStatementVisitor`,
  `StatementTransform`, `IfInverter`; `SilentIfSwapper` moved). **F.7**
  `backfill_lumina` (feature-detected). **F.8 + E.13** `recover()` with
  reapply tail — live: committed `DeepChainNodeR`, root var retyped,
  `v1->field_0.tag` renders. **E.20d** doc note done.
- Live 9.4 walker hardening discovered during the probes: treeitems
  statement bodies (`x`/`a`) resolve via the ctree walk +
  `to_specific_type` property-or-method + `creturn.expr` values —
  applies to `iter_returned_exprs`, the guess iterators and the facade
  call walker.

Open items: none committed to scope. The "future capabilities" notes
below remain observations, not tasks.

## Verification commands

```bash
python -m pytest -q            # 577 passing
python -m ruff check src tests # clean
git log --oneline main..HEAD   # pending commit list
```

## Replication notes

- Windows checkout: git warns "LF will be replaced by CRLF" for
  `src/forge/util/logging.py` — line endings are not a signal.
- The test temp config dir is auto-purged per test
  (`_purge_user_config_dir` in `tests/conftest.py`) — do not write test
  fixtures that persist under `%TEMP%\ida-forge-tests`.
- Real-IDA verification (T1.2, T3.3) requires IDA ≥ 9.0 with Hex-Rays;
  the structure-builder features need the decompiler.
- When touching `types.py`, re-read the leimurr comment — the canonical
  warning for the tinfo-handle class of bug.
- **Headless (ida-codemode / idalib) session notes, 2026-08-12/13/15**:
  - `importlib.reload(forge_api)` re-executes the module — the store
    catalog survives (it lives in `forge.api.store`), but module-level
    state like the guess visitor must be reloaded separately
    (`importlib.reload(forge.features.guess_allocation.guess_allocation)`);
    or delete the whole module group (`del sys.modules[...]` for
    `forge_api` + `forge*`) then re-import.
  - Idle workers disconnect after ~20 s lease — the installed
    `ida-codemode` defaults are patched to `keepalive=600`; takes effect
    after the MCP server restarts. Keep curation scripts in one execute
    either way.
  - IDA 9.4 lvar API: `cfunc.set_lvar_type` gone; use
    `modify_user_lvar_info(func_ea, MLI_TYPE, lvar_saved_info_t)` and
    pass the flag (without `MLI_TYPE` it silently fails). `lvar.type`
    is a callable. `rename_lvar` exists, `set_lvar_name` does not;
    `lvar.is_arg_var` is a property.
  - IDA 9.4 ctree: `cfunc.treeitems` empty; statement traversal uses
    `ctree_visitor_t.apply_to(body, None)` with the `visit_insn` hook;
    `cit_return` is 80 (not the older SDK's 78).
  - The plugin dir (`%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-forge`) is a
    symlink to `src/`; source fixes reach a live worker only after DB
    close/reopen or a module reload.
  - WER dumps: crashed idalib workers drop ~370 MB dumps in the plugin
    dir — delete after a crash storm.