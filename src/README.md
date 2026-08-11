# ida-forge source package

The plugin's Python package, importable as `forge`.

- `api/` — IDA API wrappers, scan objects, structure model, decompiler
  visitors/scanners.
- `features/` — user-facing features (structure_builder, create_new_field,
  convert_to_usercall, guess_allocation, swap_if, templated_types, menu).
- `util/` — logging, reload, itanium mangling, C++ name sanitization, Qt
  binding detection, config plumbing.

Entry point: `src/ida_forge_plugin.py` (registers `ida_forge_plugin_t`,
exposes IDC accessors `forge_get_state` / `forge_set_state`).

See the repo root `README.md` for feature list, install, and development
instructions.
