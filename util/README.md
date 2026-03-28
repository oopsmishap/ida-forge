# UI build workflow

IDA 9.3 ships Qt bindings, but not the usual Python runtime `.ui` loaders such as `PyQt5.uic` or `PySide6.QtUiTools`.

Because of that, Forge keeps Qt Designer files as the editable source of truth and commits generated Python wrappers for runtime use.

## Source files

Editable Qt Designer files:
- `src/forge/features/structure_builder/form.ui`
- `src/forge/features/templated_types/form.ui`
- `src/forge/menu/about.ui`

Generated Python wrappers:
- `src/forge/features/structure_builder/ui_form.py`
- `src/forge/features/templated_types/ui_form.py`
- `src/forge/menu/ui_about.py`

## Regenerating UI wrappers

From the repo root:

```bash
python3 util/build_ui.py
```

The script will use the first available UI compiler it finds:
- `pyside6-uic`
- `pyside2-uic`
- `pyuic5`
- `python -m PySide6.scripts.uic`
- `python -m PyQt5.uic.pyuic`

## Typical workflow

1. Edit a `.ui` file in Qt Designer
2. Regenerate wrappers:
   ```bash
   python3 util/build_ui.py
   ```
3. Review the generated changes
4. Commit both the `.ui` file and generated Python wrapper

## Notes

- Runtime code should import generated `Ui_*` classes, not load `.ui` files directly.
- Generated files are rewritten to import Qt through `forge.util.qt` so they work across IDA Qt5/PyQt5-shim and Qt6/PySide6 environments.
