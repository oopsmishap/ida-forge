# forge

IDA Forge — decompiler-driven structure recovery for IDA Pro ≥ 9.0.

Package layout:

- `forge.plugin` — IDA plugin entry (`ida_forge_plugin.py`), IDC helpers,
  action registry.
- `forge.api` — engine: `structure.py` (Structure model + commit),
  `store.py` (shared, netnode-persisted `StructureCatalog`), `storage.py`
  (JSON+zlib netnodes), `scanner.py`/`visitor.py` (member extraction),
  `scan_object.py`, `hexrays.py` (ctree helpers), `types.py`/`members.py`
  (type mapping), `config.py`.
- `forge.features` — feature modules (structure builder form/actions,
  child scanning, guess allocation, templated types, swap_if,
  create_new_field, convert_to_usercall).
- `forge.util` — logging, Qt shims, naming helpers.
- `forge_api.py` — flat headless facade over the above
  (`forge_api.help()` lists every call; the catalog it writes is the same
  one the structure-builder form reads).

Development: `python -m compileall -q src tests scripts` (the CI compile
gate runs before Ruff/pytest; note `scripts/*` is gitignored except
`r3_gap_probe.py`), `python -m pytest -q` (suite stubs the `ida_*` modules)
and `python -m ruff check src tests` must stay green.
