from __future__ import annotations

import csv
import io
from importlib import import_module
from types import SimpleNamespace

import pytest

from forge.api.structure import Structure

hexrays_api = import_module("forge.api.hexrays")
scanner_api = import_module("forge.api.scanner")
hexrays_api.get_funcs_referencing_address = lambda *_args, **_kwargs: []
hexrays_api.is_legal_type = lambda *_args, **_kwargs: True
scanner_api.NewShallowScanVisitor = type("NewShallowScanVisitor", (), {})

form_module = import_module("forge.features.structure_builder.form")
child_scan_module = import_module("forge.features.structure_builder.child_scan")
structure_module = import_module("forge.api.structure")


@pytest.fixture(autouse=True)
def _fresh_catalog():
    """The form now shares the process-wide catalog (I.28); each test starts
    from an empty, event-free catalog."""
    from forge.api.store import catalog

    catalog.events.clear()
    catalog.clear()
    yield
    catalog.events.clear()
    catalog.clear()


class _FakeLineEdit:
    def __init__(self, value: str = ""):
        self._value = value

    def text(self) -> str:
        return self._value


class _FakeFilter:
    def __init__(self):
        self.cleared = False

    def clear(self) -> None:
        self.cleared = True

class _Recorder:
    def __init__(self):
        self.enabled = None
        self.text = None

    def setEnabled(self, value):
        self.enabled = value

    def setText(self, value):
        self.text = value

    def selectedIndexes(self):
        return []

    def currentRow(self):
        return -1

    def currentColumn(self):
        return -1


class _FakeMember:
    def __init__(
        self,
        offset: int,
        size: int,
        *,
        type_name: str = "u8",
        name: str = "field_0",
        comment: str = "",
        score: int = 0,
        origin: int = 0,
    ):
        self.offset = offset
        self.size = size
        self.type_name = type_name
        self.name = name
        self.comment = comment
        self.score = score
        self.origin = origin
        self.enabled = True
        self.is_array = False
        self.scanned_variables = set()

    def invalidate_score(self):
        pass

    def __lt__(self, other):
        return (self.offset, self.type_name) < (other.offset, other.type_name)

    __hash__ = None  # mutable fake; __eq__ compares and merges
    def __eq__(self, other):
        return (self.offset, self.type_name) == (other.offset, other.type_name)


class _FakeScanObject:
    def __init__(
        self,
        *,
        func_ea: int,
        ea: int,
        name: str,
        function_name: str,
        root_func_ea: int | None = None,
        root_ea: int | None = None,
        root_function_name: str | None = None,
    ):
        self.func_ea = func_ea
        self.ea = ea
        self.name = name
        self.function_name = function_name
        self.scan_root_function_ea = func_ea if root_func_ea is None else root_func_ea
        self.scan_root_ea = ea if root_ea is None else root_ea
        self.scan_root_function_name = (
            function_name if root_function_name is None else root_function_name
        )

    def __hash__(self):
        return hash((self.func_ea, self.ea, self.name))

    def __eq__(self, other):
        return (
            isinstance(other, _FakeScanObject)
            and self.func_ea == other.func_ea
            and self.ea == other.ea
            and self.name == other.name
        )




def _make_descendant_member_evidence(
    target_offset: int,
    leaf_offset: int,
    *,
    entry_ea: int = 0x401000,
    evidence_ea: int = 0x401030,
    anchor_ea: int = 0x401020,
    parent_ea: int = 0x401010,
 ) -> SimpleNamespace:
    for op_name in ("var", "num", "add", "cast", "ptr"):
        if not hasattr(child_scan_module.ctype, op_name):
            setattr(child_scan_module.ctype, op_name, op_name)
    ctype = child_scan_module.ctype
    parent_expr = SimpleNamespace(op=ctype.var, ea=parent_ea)
    anchor_add = SimpleNamespace(
        op=ctype.add,
        x=parent_expr,
        y=SimpleNamespace(op=ctype.num, numval=lambda: target_offset),
        ea=anchor_ea - 0xC,
    )
    anchor_cast = SimpleNamespace(op=ctype.cast, x=anchor_add, ea=anchor_ea - 4)
    anchor_expr = SimpleNamespace(
        op=ctype.ptr,
        x=anchor_cast,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
        ea=anchor_ea,
    )
    descendant_add = SimpleNamespace(
        op=ctype.add,
        x=anchor_expr,
        y=SimpleNamespace(op=ctype.num, numval=lambda: leaf_offset),
        ea=evidence_ea - 4,
    )
    descendant_expr = SimpleNamespace(
        op=ctype.ptr,
        x=descendant_add,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 1),
        ea=evidence_ea,
    )
    parent_map = {
        id(anchor_add): anchor_cast,
        id(anchor_cast): anchor_expr,
        id(anchor_expr): descendant_add,
        id(descendant_add): descendant_expr,
    }
    cfunc = SimpleNamespace(
        entry_ea=entry_ea,
        treeitems=[descendant_expr],
        eamap={evidence_ea: [descendant_expr]},
        body=SimpleNamespace(
            find_parent_of=lambda expr: parent_map.get(id(expr)),
            find_closest_addr=lambda _ea: descendant_expr,
        ),
    )
    return SimpleNamespace(
        cfunc=cfunc,
        parent_expr=parent_expr,
        anchor_expr=anchor_expr,
        descendant_expr=descendant_expr,
    )


def _make_form(monkeypatch) -> form_module.StructureBuilderForm:
    structure_form = form_module.StructureBuilderForm()
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)
    monkeypatch.setattr(structure_form, "update_structure_fields", lambda: None)
    monkeypatch.setattr(structure_form, "reload_structure_list", lambda: None)
    monkeypatch.setattr(structure_form, "_select_structure_in_tree", lambda _name: False)
    monkeypatch.setattr(
        structure_form,
        "set_structure",
        lambda name: setattr(structure_form, "current_structure", structure_form.structures[name]),
    )
    return structure_form

def test_on_close_resets_cached_ui_state(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.parent = object()
    structure_form.ui = SimpleNamespace(tbl_structure=object(), tree_structures=object())
    structure_form.layout = object()
    structure_form._shortcut_actions = [object(), object()]

    structure_form.OnClose(None)

    assert structure_form.parent is None
    assert structure_form.ui is None
    assert structure_form.layout is None
    assert structure_form._shortcut_actions == []



def test_show_resubscribes_to_catalog_after_reset(monkeypatch):
    """The form is a module-level singleton: after OnClose->reset drops the
    catalog subscription, a re-show must re-subscribe or the form stops
    seeing headless catalog mutations (I.28)."""
    from forge.api.store import catalog

    structure_form = _make_form(monkeypatch)
    structure_form.reset()
    assert structure_form.reload_structure_list not in catalog.events

    structure_form.show()

    assert structure_form.reload_structure_list in catalog.events


def test_register_structure_models_fires_one_catalog_notification(monkeypatch):
    """A hierarchy commit registers all models inside one catalog
    transaction: a single snapshot + change notification, not one per
    structure (which was O(N) serializations and N tree rebuilds)."""
    from forge.api.store import catalog as store_catalog

    structure_form = _make_form(monkeypatch)
    notifications = []
    monkeypatch.setattr(
        store_catalog, "notify_changed", lambda: notifications.append(1)
    )
    models = [Structure(f"child_{i}") for i in range(4)]

    registered = structure_form._register_structure_models(models)

    assert tuple(registered) == tuple(models)
    for model in models:
        assert store_catalog[model.name] is model
    assert notifications == [1]


def test_get_selected_rows_handles_stale_table_after_reload(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.parent = object()
    structure_form.layout = object()

    class _StaleTable:
        def selectedIndexes(self):
            raise RuntimeError("wrapped C/C++ object of type QTableWidget has been deleted")

    structure_form.ui = SimpleNamespace(tbl_structure=_StaleTable())

    assert structure_form.get_selected_rows() == []
    assert structure_form.ui is None
    assert structure_form.parent is None
    assert structure_form.layout is None


def test_update_structure_fields_returns_when_table_selection_is_stale(monkeypatch):
    structure_form = _make_form(monkeypatch)
    monkeypatch.setattr(
        structure_form,
        "update_structure_fields",
        form_module.StructureBuilderForm.update_structure_fields.__get__(structure_form),
    )
    structure_form.parent = object()
    structure_form.layout = object()

    class _StaleTable:
        def selectedIndexes(self):
            raise RuntimeError("wrapped C/C++ object of type QTableWidget has been deleted")

    structure_form.ui = SimpleNamespace(tbl_structure=_StaleTable())
    structure_form.current_structure = Structure("Selected")

    structure_form.update_structure_fields()

    assert structure_form.ui is None
    assert structure_form.parent is None
    assert structure_form.layout is None




def test_make_table_item_uses_shared_qt_flag_helper(monkeypatch):
    calls = []

    class _FakeItem:
        def __init__(self, text):
            self.text = text
            self.flags = None
            self.background = None
            self.foreground = None

        def setFlags(self, flags):
            self.flags = flags

        def setBackground(self, color):
            self.background = color

        def setForeground(self, color):
            self.foreground = color

    monkeypatch.setattr(form_module, "QTableWidgetItem", _FakeItem)
    monkeypatch.setattr(
        form_module,
        "qt_item_flags",
        lambda *flags: calls.append(flags) or 0xD,
    )

    item = form_module.StructureBuilderForm._make_table_item("field", editable=True)

    assert item.text == "field"
    assert item.flags == 0xD
    # _make_table_item now sets a default background and foreground
    # so no cell is ever transparent (the QTableWidget viewport is
    # white in IDA's theme and would otherwise bleed through).
    assert item.background is not None
    assert item.foreground is not None
    assert calls == [
        (form_module.Qt.ItemIsSelectable, form_module.Qt.ItemIsEnabled),
        (0xD, form_module.Qt.ItemIsEditable),
    ]


def test_update_structure_fields_disabled_state_paints_all_columns(monkeypatch):
    """Disabled rows must paint the disabled color on *every* column.

    A previous version of the form relied on the per-item
    ``setBackground`` to override the QTableWidget viewport's white
    background. Some cells were left transparent on dark themes and
    rendered white-on-white for the disabled foreground. The fix
    guarantees a default per-cell background in ``_make_table_item``
    so the disabled/collision colors reliably win for all columns.
    """
    structure_form = _make_form(monkeypatch)
    captured = []

    class _FakeItem:
        def __init__(self, text):
            self.text = text
            self.flags = None
            self.background = None
            self.foreground = None

        def setFlags(self, flags):
            self.flags = flags

        def setBackground(self, color):
            self.background = color

        def setForeground(self, color):
            self.foreground = color

    class _FakeTable:
        def __init__(self):
            self._items = {}
            self.column_count = 5

        def columnCount(self):
            return self.column_count

        def rowCount(self):
            return 1

        def setRowCount(self, _n):
            self._items.clear()

        def setItem(self, row, col, item):
            captured.append((row, col, item))
            self._items[(row, col)] = item

        def item(self, row, col):
            return self._items.get((row, col))

        def setEnabled(self, _v):
            pass

        def setDisabled(self, _v):
            pass

        def clearSelection(self):
            pass

        def selectRow(self, _row):
            pass

        def setRangeSelected(self, *_args, **_kwargs):
            pass

        def setCurrentCell(self, *_args, **_kwargs):
            pass

        def verticalScrollBar(self):
            return SimpleNamespace(value=lambda: 0, setValue=lambda _v: None)

    table = _FakeTable()
    structure_form.ui = SimpleNamespace(
        tbl_structure=table,
        input_name=SimpleNamespace(setText=lambda _t: None),
    )

    member = SimpleNamespace(
        offset=0x10,
        size=8,
        name="field_disabled",
        type_name="u64",
        score=0,
        comment="",
        enabled=False,
        is_array=False,
    )
    structure = Structure("disabled_check")
    structure.add_member(member)
    # Use a different main_offset so the origin highlight does not
    # repaint the offset cell on top of the disabled state.
    structure.main_offset = 0x20
    structure_form.current_structure = structure

    monkeypatch.setattr(form_module, "QTableWidgetItem", _FakeItem)
    monkeypatch.setattr(form_module, "QColor", lambda hexstr: hexstr)
    monkeypatch.setattr(structure_form, "get_selected_rows", list)
    monkeypatch.setattr(structure_form, "_restore_selected_rows", lambda _r: None)
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)

    form_module.StructureBuilderForm.update_structure_fields.__get__(structure_form)()

    # Sanity: verify the fake recorded the expected setItem calls
    assert len(captured) == 5, (
        f"expected 5 setItem calls (one per column), got {len(captured)}: {captured}"
    )
    for row, col, _ in captured:
        assert row == 0
        assert 0 <= col < 5

    disabled_bg = form_module.config["form"]["disabled_color"]
    disabled_fg = form_module.config["form"]["disabled_foreground_color"]

    for col in range(5):
        item = table.item(0, col)
        assert item is not None, f"column {col} has no item"
        assert item.background is not None, (
            f"column {col} has no background — viewport white would"
            " show through and disabled text becomes invisible"
        )
        assert item.background == disabled_bg, (
            f"column {col} did not receive the disabled background"
        )
        assert item.foreground == disabled_fg, (
            f"column {col} did not receive the disabled foreground"
        )


def test_update_structure_fields_collision_state_paints_all_columns(monkeypatch):
    """Colliding members must paint every column with the collision palette.

    Regression: the dark-theme rework (b04c129) removed
    ``collision_foreground_color`` from the config defaults while
    ``update_structure_fields`` kept reading it, so the first collision row
    crashed with ``KeyError: 'collision_foreground_color'`` at
    ``QColor(config["form"]["collision_foreground_color"])``.
    """
    structure_form = _make_form(monkeypatch)
    captured = []

    class _FakeItem:
        def __init__(self, text):
            self.text = text
            self.background = None
            self.foreground = None

        def setFlags(self, _flags):
            pass

        def setBackground(self, color):
            self.background = color

        def setForeground(self, color):
            self.foreground = color

    class _FakeTable:
        def __init__(self):
            self._items = {}
            self.column_count = 5

        def columnCount(self):
            return self.column_count

        def rowCount(self):
            return 2

        def setRowCount(self, _n):
            self._items.clear()

        def setItem(self, row, col, item):
            captured.append((row, col, item))
            self._items[(row, col)] = item

        def item(self, row, col):
            return self._items.get((row, col))

        def setEnabled(self, _v):
            pass

        def setDisabled(self, _v):
            pass

        def clearSelection(self):
            pass

        def selectRow(self, _row):
            pass

        def setRangeSelected(self, *_args, **_kwargs):
            pass

        def setCurrentCell(self, *_args, **_kwargs):
            pass

        def verticalScrollBar(self):
            return SimpleNamespace(value=lambda: 0, setValue=lambda _v: None)

    table = _FakeTable()
    structure_form.ui = SimpleNamespace(
        tbl_structure=table,
        input_name=SimpleNamespace(setText=lambda _t: None),
    )

    # Two enabled members overlapping at offset 0x0 -> collision.
    class _FakeMember(SimpleNamespace):
        def __lt__(self, other):
            return (self.offset, self.name) < (other.offset, other.name)

    structure = Structure("collision_check")
    structure.add_member(
        _FakeMember(
            offset=0x0,
            size=8,
            name="field_a",
            type_name="u64",
            score=0,
            comment="",
            enabled=True,
            is_array=False,
        )
    )
    structure.add_member(
        _FakeMember(
            offset=0x0,
            size=4,
            name="field_b",
            type_name="u32",
            score=0,
            comment="",
            enabled=True,
            is_array=False,
        )
    )
    # Use a different main_offset so the origin highlight does not repaint.
    structure.main_offset = 0x20
    structure_form.current_structure = structure

    monkeypatch.setattr(form_module, "QTableWidgetItem", _FakeItem)
    monkeypatch.setattr(form_module, "QColor", lambda hexstr: hexstr)
    monkeypatch.setattr(structure_form, "get_selected_rows", list)
    monkeypatch.setattr(structure_form, "_restore_selected_rows", lambda _r: None)
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)

    form_module.StructureBuilderForm.update_structure_fields.__get__(structure_form)()

    assert len(captured) == 10, (
        f"expected 10 setItem calls (2 rows x 5 columns), got {len(captured)}"
    )
    for col in range(5):
        for row in range(2):
            item = table.item(row, col)
            assert item is not None, f"row {row} column {col} has no item"
            assert item.background == form_module.config["form"]["collision_background_color"], (
                f"row {row} column {col} did not receive the collision background"
            )
            assert item.foreground == form_module.config["form"]["collision_foreground_color"], (
                f"row {row} column {col} did not receive the collision foreground"
            )


def test_update_structure_fields_origin_cell_uses_disabled_palette_when_row_disabled(
    monkeypatch,
):
    """A row that is the structure's main offset but is disabled must
    paint the offset cell with the disabled palette, not the origin
    blue. The visual cue is the row state, not the offset cell.
    """
    structure_form = _make_form(monkeypatch)
    captured = []

    class _FakeItem:
        def __init__(self, text):
            self.text = text
            self.background = None
            self.foreground = None

        def setFlags(self, _flags):
            pass

        def setBackground(self, color):
            self.background = color

        def setForeground(self, color):
            self.foreground = color

    class _FakeTable:
        def __init__(self):
            self._items = {}
            self.column_count = 5

        def columnCount(self):
            return self.column_count

        def rowCount(self):
            return 1

        def setRowCount(self, _n):
            self._items.clear()

        def setItem(self, row, col, item):
            captured.append((row, col, item))
            self._items[(row, col)] = item

        def item(self, row, col):
            return self._items.get((row, col))

        def setEnabled(self, _v):
            pass

        def setDisabled(self, _v):
            pass

        def clearSelection(self):
            pass

        def selectRow(self, _row):
            pass

        def setRangeSelected(self, *_args, **_kwargs):
            pass

        def setCurrentCell(self, *_args, **_kwargs):
            pass

        def verticalScrollBar(self):
            return SimpleNamespace(value=lambda: 0, setValue=lambda _v: None)

    table = _FakeTable()
    structure_form.ui = SimpleNamespace(
        tbl_structure=table,
        input_name=SimpleNamespace(setText=lambda _t: None),
    )

    member = SimpleNamespace(
        offset=0x10,
        size=8,
        name="origin_field",
        type_name="u64",
        score=0,
        comment="",
        enabled=False,
        is_array=False,
    )
    structure = Structure("disabled_origin")
    structure.add_member(member)
    # The member's offset IS the structure's main offset, so it is
    # the origin row. With the row disabled, the origin cell must
    # adopt the disabled palette.
    structure.main_offset = 0x10
    structure_form.current_structure = structure

    monkeypatch.setattr(form_module, "QTableWidgetItem", _FakeItem)
    monkeypatch.setattr(form_module, "QColor", lambda hexstr: hexstr)
    monkeypatch.setattr(structure_form, "get_selected_rows", list)
    monkeypatch.setattr(structure_form, "_restore_selected_rows", lambda _r: None)
    monkeypatch.setattr(structure_form, "update_action_states", lambda: None)

    form_module.StructureBuilderForm.update_structure_fields.__get__(structure_form)()

    offset_item = table.item(0, 0)
    assert offset_item is not None
    # Origin cell should now be the disabled palette, not the origin blue.
    assert offset_item.background == form_module.config["form"]["disabled_color"]
    assert offset_item.foreground == form_module.config["form"]["disabled_foreground_color"]
    assert offset_item.background != form_module.config["form"]["origin_color"]


def test_create_structure_treats_none_as_cancel(monkeypatch):
    structure_form = _make_form(monkeypatch)

    created = structure_form.create_structure(None)

    assert created is None
    assert list(structure_form.structures) == []
    assert structure_form.current_structure is None


def test_create_structure_rejects_duplicate_explicit_names(monkeypatch):
    structure_form = _make_form(monkeypatch)

    first = structure_form.create_structure("manual")
    duplicate = structure_form.create_structure("manual")

    assert first is not None
    assert first.is_auto_named is False
    assert duplicate is None
    assert list(structure_form.structures) == ["manual"]


def test_prompt_create_structure_treats_none_as_cancel(monkeypatch):
    structure_form = _make_form(monkeypatch)
    monkeypatch.setattr(form_module.ida_kernwin, "HIST_IDENT", 0, raising=False)
    monkeypatch.setattr(form_module.ida_kernwin, "ask_str", lambda *_args, **_kwargs: None)

    created = structure_form.prompt_create_structure()

    assert created is None
    assert list(structure_form.structures) == []
    assert structure_form.current_structure is None


def test_prompt_create_structure_auto_names_blank_and_whitespace(monkeypatch):
    structure_form = _make_form(monkeypatch)
    prompts = iter(["   ", "\t"])
    monkeypatch.setattr(form_module.ida_kernwin, "HIST_IDENT", 0, raising=False)
    monkeypatch.setattr(form_module.ida_kernwin, "ask_str", lambda *_args, **_kwargs: next(prompts))

    first = structure_form.prompt_create_structure()
    second = structure_form.prompt_create_structure()

    assert first is not None
    assert first.is_auto_named is True
    assert second is not None
    assert second.is_auto_named is True
    # Auto-names are unique short-guid names: never the generic "Structure".
    assert first.name.startswith("structure_")
    assert first.name != "Structure"
    assert second.name.startswith("structure_")
    assert second.name != first.name
    assert list(structure_form.structures) == [first.name, second.name]
    assert structure_form.current_structure is second


def test_create_structure_auto_name_skips_taken_guid(monkeypatch):
    """An auto-created structure never collides with an existing manual name,
    even when a user already chose a ``structure_``-prefixed name."""
    structure_form = _make_form(monkeypatch)
    structure_form.create_structure("manual")

    created = structure_form.create_structure("  ")

    assert created is not None
    assert created.name.startswith("structure_")
    assert created.name not in structure_form.structures or structure_form.structures[created.name] is created
    assert created.is_auto_named is True
    assert structure_form.structures["manual"].is_auto_named is False


def test_create_structure_auto_name_is_unique_across_many(monkeypatch):
    """Many auto-named structures get distinct names."""
    structure_form = _make_form(monkeypatch)
    names = {
        created.name
        for _ in range(20)
        if (created := structure_form.create_structure("  ")) is not None
    }
    assert len(names) == 20
    assert all(name.startswith("structure_") for name in names)


def test_structure_renamed_clears_auto_named_flag(monkeypatch):
    structure_form = _make_form(monkeypatch)
    auto_named = structure_form.create_structure(" ")
    assert auto_named is not None

    fake_filter = _FakeFilter()
    structure_form.ui = SimpleNamespace(
        input_name=_FakeLineEdit("Inventory"),
        input_filter=fake_filter,
    )
    structure_form.current_structure = auto_named

    structure_form.structure_renamed()

    assert auto_named.name == "Inventory"
    assert auto_named.is_auto_named is False
    assert "Structure" not in structure_form.structures
    assert structure_form.structures["Inventory"] is auto_named
    assert fake_filter.cleared is True


def test_structure_renamed_autonamed_no_stale_lookup_with_reload(monkeypatch):
    """Regression: renaming an auto-named structure must not emit
    'Structure <name> does not exist!'. Each catalog mutation (self.structures
    IS the catalog) fires reload_structure_list re-entrantly; the object's
    name must be updated before the dict is mutated so the reloads never read
    a stale name that is already gone from the store."""
    from forge.api.store import catalog

    structure_form = _make_form(monkeypatch)
    warnings = []
    monkeypatch.setattr(form_module, "log_warning", lambda m, *a, **k: warnings.append(m), raising=False)

    # Simulate the GUI's catalog-change hook: a tree reload observes
    # current_structure by name, exactly as _current_tree_structure ->
    # set_structure would. It must never read the pre-rename name.
    stale = []

    def reload_listener():
        cs = structure_form.current_structure
        if cs is not None and cs.name not in structure_form.structures:
            stale.append(cs.name)

    catalog.events.append(reload_listener)

    auto_named = structure_form.create_structure(" ")
    assert auto_named is not None
    old_name = auto_named.name
    structure_form.current_structure = auto_named

    fake_filter = _FakeFilter()
    structure_form.ui = SimpleNamespace(
        input_name=_FakeLineEdit("Inventory"),
        input_filter=fake_filter,
    )

    structure_form.structure_renamed()

    # No reload ever read the removed old name (previously leaked as
    # "Structure Structure does not exist!").
    assert stale == []
    assert not any(old_name in w for w in warnings)
    assert auto_named.name == "Inventory"
    assert auto_named.is_auto_named is False
    assert old_name not in structure_form.structures
    assert structure_form.structures["Inventory"] is auto_named

def test_structure_renamed_syncs_created_type_name_when_canonical(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("manual")
    assert structure is not None

    structure.created_type_name = "manual"
    rename_calls = []

    def fake_rename_created_type(old_name, new_name):
        rename_calls.append((old_name, new_name))
        structure.created_type_name = new_name
        return True

    monkeypatch.setattr(structure, "rename_created_type", fake_rename_created_type)

    fake_filter = _FakeFilter()
    structure_form.ui = SimpleNamespace(
        input_name=_FakeLineEdit("Inventory"),
        input_filter=fake_filter,
    )
    structure_form.current_structure = structure

    structure_form.structure_renamed()

    assert rename_calls == [("manual", "Inventory")]
    assert structure.name == "Inventory"
    assert structure.created_type_name == "Inventory"
    assert structure_form.structures["Inventory"] is structure
    assert fake_filter.cleared is True




def test_duplicate_structure_copies_provenance_and_outbound_relationships(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.set_provenance(
        kind="confirmed_root",
        root_object_name="player",
        source_member_offset=0x30,
    )
    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="Child *", name="inventory_ptr")
    parent.add_member(member)
    member.linked_child_structure_name = "Child"
    member.child_relation_kind = "pointer"

    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="inventory_ptr",
    )
    child.add_parent_relationship(relationship)
    structure_form.current_structure = parent

    structure_form.duplicate_structure()

    duplicate = structure_form.structures["Parent Copy"]
    assert duplicate.provenance == parent.provenance
    assert duplicate.provenance is not parent.provenance
    assert duplicate.is_auto_named is True
    assert duplicate.created_type_name is None
    assert duplicate.parent_relationships == []
    assert len(duplicate.child_relationships) == 1
    assert duplicate.child_relationships[0].parent_structure_name == "Parent Copy"
    assert duplicate.child_relationships[0].child_structure_name == "Child"
    assert duplicate.members[0].linked_child_structure_name == "Child"
    assert duplicate.members[0].child_relation_kind == "pointer"
    assert sorted(
        rel.parent_structure_name for rel in child.parent_relationships
    ) == ["Parent", "Parent Copy"]


def test_duplicate_structure_clears_orphaned_member_links_and_inbound_parents(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x20,
        parent_member_name="child_ptr",
    )
    child.add_parent_relationship(relationship)

    orphan_member = _FakeMember(0x30, 8, type_name="Ghost *", name="ghost_ptr")
    child.add_member(orphan_member)
    orphan_member.linked_child_structure_name = "Ghost"
    orphan_member.child_relation_kind = "pointer"
    structure_form.current_structure = child

    structure_form.duplicate_structure()

    duplicate = structure_form.structures["Child Copy"]
    assert duplicate.parent_relationships == []
    assert duplicate.members[0].linked_child_structure_name is None
    assert duplicate.members[0].child_relation_kind is None


def test_format_type_status_reports_created_structures_with_unresolved_children(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="inventory_ptr",
    )
    parent.created_type_name = "Parent_t"

    assert (
        structure_form._format_type_status(parent)
        == "created as Parent_t | unresolved children: Child"
    )

    child.created_type_name = "Child_t"

    assert structure_form._format_type_status(parent) == "created as Parent_t | child links ready"


def test_structure_table_finalize_blocks_unresolved_children(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="child_ptr",
    )
    structure_form.current_structure = parent

    warnings: list[str] = []
    monkeypatch.setattr(
        structure_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    pack_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        parent,
        "pack_structure",
        lambda *args, **kwargs: pack_calls.append((args, kwargs)) or object(),
    )

    structure_form.structure_table_finalize()

    assert pack_calls == []
    assert warnings == [
        "Cannot create type for Parent: unresolved child structures: Child"
    ]


def test_structure_table_finalize_uses_headless_commit(monkeypatch):
    """The form's default Create Type path commits via the headless core
    (no C-preview/overwrite-confirm dialogs)."""
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("Parent")
    assert structure is not None
    structure.add_member(_FakeMember(0x0, 8, type_name="u32", name="count"))
    structure_form.current_structure = structure

    captured: list = []
    monkeypatch.setattr(
        structure,
        "create_type_if_ready",
        lambda structures_by_name, **kwargs: captured.append(
            (structures_by_name, kwargs)
        )
        or object(),
    )

    structure_form.structure_table_finalize()

    assert len(captured) == 1
    _, kwargs = captured[0]
    assert kwargs["headless"] is True


def test_structure_table_finalize_with_preview_uses_pack_structure(monkeypatch):
    """The opt-in 'Create Type (Edit Declaration)' path keeps the editable
    dialog, routing through pack_structure with the unresolved-children
    guard preserved."""
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("Parent")
    assert structure is not None
    structure.add_member(_FakeMember(0x0, 8, type_name="u32", name="count"))
    structure_form.current_structure = structure

    pack_calls: list = []
    monkeypatch.setattr(
        structure,
        "pack_structure",
        lambda *args, **kwargs: pack_calls.append((args, kwargs)) or object(),
    )
    create_calls: list = []
    monkeypatch.setattr(
        structure,
        "create_type_if_ready",
        lambda *args, **kwargs: create_calls.append(True) or object(),
    )

    structure_form.structure_table_finalize_with_preview()

    assert pack_calls == [((), {})]
    # The preview path must not invoke the (now-headless) create_type_if_ready.
    assert create_calls == []


def test_structure_table_resolve_clears_stale_selection_after_refresh(monkeypatch):
    structure_form = _make_form(monkeypatch)

    class _TableSelectionRecorder:
        def __init__(self):
            self.clear_selection_calls = 0
            self.current_cells = []

        def clearSelection(self):
            self.clear_selection_calls += 1

        def setCurrentCell(self, row, column):
            self.current_cells.append((row, column))

    calls: list[str] = []
    table = _TableSelectionRecorder()
    structure_form.ui = SimpleNamespace(tbl_structure=table)
    structure_form.current_structure = SimpleNamespace(
        auto_resolve_preview=list,
        auto_resolve=lambda: calls.append("resolve"),
    )
    monkeypatch.setattr(
        structure_form, "update_structure_fields", lambda: calls.append("fields")
    )
    monkeypatch.setattr(
        structure_form, "update_action_states", lambda: calls.append("actions")
    )

    structure_form.structure_table_resolve()

    assert calls == ["resolve", "fields", "actions"]
    assert table.clear_selection_calls == 1
    assert table.current_cells == [(-1, -1)]


def test_create_child_types_creates_direct_children_in_offset_order(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child_a = structure_form.create_structure("ChildA")
    child_b = structure_form.create_structure("ChildB")

    assert parent is not None
    assert child_a is not None
    assert child_b is not None

    parent.add_child_relationship(
        child_structure_name="Missing",
        parent_member_offset=0x08,
        parent_member_name="missing_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="ChildB",
        parent_member_offset=0x20,
        parent_member_name="child_b_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="ChildA",
        parent_member_offset=0x10,
        parent_member_name="child_a_ptr",
    )
    structure_form.current_structure = parent

    warnings: list[str] = []
    monkeypatch.setattr(
        form_module,
        "log_warning",
        lambda message, *args, **kwargs: warnings.append(message),
    )

    created: list[str] = []
    created_kwargs: list[dict] = []
    monkeypatch.setattr(
        child_a,
        "create_type_if_ready",
        lambda structures_by_name, **kwargs: created.append("ChildA") or created_kwargs.append(kwargs) or object(),
    )
    monkeypatch.setattr(
        child_b,
        "create_type_if_ready",
        lambda structures_by_name, **kwargs: created.append("ChildB") or created_kwargs.append(kwargs) or object(),
    )

    structure_form.create_child_types()

    assert created == ["ChildA", "ChildB"]
    # Dialog-free headless commit path.
    assert all(kwargs.get("headless") is True for kwargs in created_kwargs)
    assert warnings == [
        "Linked child structure Missing does not exist."
    ]


def test_create_type_subtree_creates_children_before_parent(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child_b = structure_form.create_structure("ChildB")
    child_c = structure_form.create_structure("ChildC")
    grandchild = structure_form.create_structure("Grandchild")

    assert parent is not None
    assert child_b is not None
    assert child_c is not None
    assert grandchild is not None

    parent.add_child_relationship(
        child_structure_name="ChildB",
        parent_member_offset=0x10,
        parent_member_name="child_b_ptr",
    )
    parent.add_child_relationship(
        child_structure_name="ChildC",
        parent_member_offset=0x20,
        parent_member_name="child_c_ptr",
    )
    child_b.add_child_relationship(
        child_structure_name="Grandchild",
        parent_member_offset=0x08,
        parent_member_name="grandchild_ptr",
    )
    structure_form.current_structure = parent

    created: list[str] = []
    created_kwargs: list[dict] = []
    monkeypatch.setattr(
        structure_module.Structure,
        "create_type_if_ready",
        lambda self, structures_by_name, **kwargs: created.append(self.name) or created_kwargs.append(kwargs) or object(),
    )

    structure_form.create_type_subtree()

    assert created == ["Grandchild", "ChildB", "ChildC", "Parent"]
    # Dialog-free headless commit across the whole subtree.
    assert created_kwargs and all(
        kwargs.get("headless") is True for kwargs in created_kwargs
    )


def test_update_action_states_enables_child_type_actions_for_child_relationships(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")

    assert parent is not None
    assert child is not None

    parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="child_ptr",
    )
    structure_form.current_structure = parent

    structure_form.ui = SimpleNamespace(
        btn_remove=_Recorder(),
        btn_duplicate_structure=_Recorder(),
        btn_apply_name=_Recorder(),
        input_name=_Recorder(),
        input_filter=_Recorder(),
        tbl_structure=_Recorder(),
        btn_auto_resolve=_Recorder(),
        btn_create_type=_Recorder(),
        btn_enable_rows=_Recorder(),
        btn_disable_rows=_Recorder(),
        btn_toggle_array=_Recorder(),
        btn_set_origin=_Recorder(),
        btn_remove_rows=_Recorder(),
        btn_clear_rows=_Recorder(),
        btn_view_scanned_uses=_Recorder(),
        btn_recognize_vtable=_Recorder(),
        btn_add_row=_Recorder(),
        btn_duplicate_row=_Recorder(),
        btn_edit_row=_Recorder(),
        btn_scan_child=_Recorder(),
        btn_open_child=_Recorder(),
        btn_create_child_types=_Recorder(),
        btn_create_subtree_types=_Recorder(),
        action_enable=_Recorder(),
        action_disable=_Recorder(),
        action_resolve=_Recorder(),
        action_finalize=_Recorder(),
        action_edit=_Recorder(),
        action_add_row=_Recorder(),
        action_duplicate_row=_Recorder(),
        action_scan_child=_Recorder(),
        action_create_child_types=_Recorder(),
        action_create_subtree_types=_Recorder(),
    )
    monkeypatch.setattr(structure_form, "get_selected_rows", list)
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: None)
    monkeypatch.setattr(structure_form, "_build_child_scan_plan", lambda _member: None)
    monkeypatch.setattr(structure_form, "_update_summary_label", lambda: None)
    monkeypatch.setattr(
        structure_form,
        "_update_inspector_panel",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert structure_form.ui.btn_create_child_types.enabled is True
    assert structure_form.ui.btn_create_subtree_types.enabled is True
    assert structure_form.ui.action_create_child_types.enabled is True
    assert structure_form.ui.action_create_subtree_types.enabled is True
    assert structure_form.ui.btn_scan_child.enabled is False
    assert structure_form.ui.action_scan_child.enabled is False



def test_scan_child_structure_auto_creates_child_and_records_metadata(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root"),
    ]
    parent.created_type_name = "Parent_t"
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = child_scan_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="embedded",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan,
    )

    def fake_execute(child_structure, built_plan):
        assert built_plan is plan
        # child structures are stored child-local (main_offset 0); the
        # The scanned member's absolute origin travels via plan.source_base.
        assert child_structure.main_offset == 0
        child_structure.add_member(_FakeMember(0, 4, type_name="u32", name="value"))
        return True

    monkeypatch.setattr(structure_form, "_execute_child_scan_plan", fake_execute)

    structure_form.scan_child_structure()

    child = next(
        s for s in structure_form.structures.values() if s.is_auto_named
    )
    assert child.name.startswith("structure_")
    assert structure_form.current_structure is child
    assert child.is_auto_named is True
    assert child.main_offset == 0
    assert child.provenance.kind == "child_scan"
    assert child.provenance.root_object_name == "Parent.child_ptr"
    assert child.provenance.source_member_offset == 0x30
    assert member.linked_child_structure_name == child.name
    assert member.child_relation_kind == "embedded"
    assert parent.child_relationships[0].child_structure_name == child.name
    assert child.parent_relationships[0].parent_structure_name == "Parent"



def test_scan_child_structure_reuses_existing_linked_child(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    assert parent is not None
    assert child is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.linked_child_structure_name = "Child"
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = child_scan_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="pointer",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan,
    )
    monkeypatch.setattr(
        structure_form,
        "_execute_child_scan_plan",
        lambda child_structure, _plan: child_structure.add_member(
            _FakeMember(0, 4, type_name="u32", name="value")
        )
        or True,
    )

    structure_form.scan_child_structure()

    assert list(structure_form.structures) == ["Parent", "Child"]
    assert structure_form.current_structure is child
    assert member.linked_child_structure_name == "Child"
    assert parent.child_relationships[0].child_structure_name == "Child"
    assert child.parent_relationships[0].parent_structure_name == "Parent"

def test_show_scanned_variables_dedupes_duplicate_selected_member_evidence(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    class _DuplicateScanObject:
        def __init__(self, *, func_ea: int, ea: int, name: str, origin: int = 0x20):
            self.func_ea = func_ea
            self.ea = ea
            self.name = name
            self.origin = origin

        def to_list(self):
            return [f"0x{self.origin:04X}", "child_func", self.name, hex(self.ea)]

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    scan_a = _DuplicateScanObject(func_ea=0x401000, ea=0x401234, name="child_ptr_scan")
    scan_b = _DuplicateScanObject(func_ea=0x401000, ea=0x401234, name="child_ptr_scan")
    member.scanned_variables = {scan_a, scan_b}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [member])

    captured = {}

    class _ChooserRecorder:
        def __init__(self, scanned_variables):
            captured["scanned_variables"] = list(scanned_variables)

        def Show(self):
            captured["shown"] = True

    monkeypatch.setattr(child_scan_module, "ScannedVariableChooser", _ChooserRecorder)

    structure_form.show_scanned_variables()

    assert captured["shown"] is True
    assert len(captured["scanned_variables"]) == 1
    assert captured["scanned_variables"][0].name == "child_ptr_scan"


def test_build_structure_table_debug_csv_includes_scan_metadata(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(
        0x30,
        8,
        type_name="Child *",
        name="child_ptr",
        comment="linked",
        score=13,
        origin=0x20,
    )
    scan_object = _FakeScanObject(
        func_ea=0x401000,
        ea=0x401234,
        name="child_ptr_scan",
        function_name="child_func",
        root_func_ea=0x400800,
        root_ea=0x400ABC,
        root_function_name="root_func",
    )

    member.scanned_variables = {scan_object}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])

    fake_cfunc = SimpleNamespace(
        treeitems=[SimpleNamespace(ea=0x401234), SimpleNamespace(ea=0x400ABC)],
        find_item_coords=lambda _item: (2, 0) if getattr(_item, "ea", None) == 0x401234 else (1, 0),
        get_pseudocode=lambda: [
            "if (ok) {",
            "    parent->child = value;",
        ],
    )
    monkeypatch.setattr(form_module, "decompile", lambda func_ea: fake_cfunc if func_ea in (0x401000, 0x400800) else None)
    csv_text = structure_form._build_structure_table_debug_csv()
    rows = list(csv.reader(io.StringIO(csv_text)))



    assert rows[0] == [
        "structure_name",
        "row",
        "offset",
        "type",
        "name",
        "score",
        "comment",
        "enabled",
        "array",
        "origin",
        "scan_location_count",
        "scan_locations",
        "scan_lines",
        "scan_root_location_count",
        "scan_root_locations",
        "scan_root_lines",
    ]
    assert rows[1] == [
        "Parent",
        "0",
        "0x0030 [0x8]",
        "Child *",
        "child_ptr",
        "13",
        "linked",
        "yes",
        "no",
        "0x20",
        "1",
        f"child_func@{hex(0x401234)}",
        "parent->child = value;",
        "1",
        f"root_func@{hex(0x400ABC)}",
        "if (ok) {",
    ]





def test_build_structure_table_debug_csv_falls_back_for_root_labels_and_lines(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(
        0x30,
        8,
        type_name="Child *",
        name="child_ptr",
        comment="linked",
        score=13,
        origin=0x20,
    )
    scan_object = _FakeScanObject(
        func_ea=0x401000,
        ea=0x401234,
        name="child_ptr_scan",
        function_name="child_func",
        root_func_ea=0x400800,
        root_ea=0x400ABC,
        root_function_name=None,
    )
    scan_object.scan_root_function_name = None
    member.scanned_variables = {scan_object}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])
    monkeypatch.setattr(
        form_module.ida_funcs,
        "get_func_name",
        lambda ea: {0x401000: "child_func", 0x400800: "root_func"}.get(ea, f"sub_{ea:x}"),
        raising=False,
    )

    root_item = SimpleNamespace(ea=0x400ABC)
    fake_cfunc = SimpleNamespace(
        treeitems=[SimpleNamespace(ea=0x401234)],
        eamap={0x400ABC: [root_item]},
        find_item_coords=lambda item: (2, 0) if getattr(item, "ea", None) == 0x401234 else (1, 0),
        get_pseudocode=lambda: [
            "if (ok) {",
            "    parent->child = value;",
        ],
    )
    monkeypatch.setattr(form_module, "decompile", lambda func_ea: fake_cfunc if func_ea in (0x401000, 0x400800) else None)
    csv_text = structure_form._build_structure_table_debug_csv()
    rows = list(csv.reader(io.StringIO(csv_text)))

    row = dict(zip(rows[0], rows[1]))

    assert row["scan_location_count"] == "1"
    assert row["scan_locations"] == "child_func@0x401234"
    assert row["scan_lines"] == "parent->child = value;"
    assert row["scan_root_location_count"] == "1"
    assert row["scan_root_locations"] == "root_func@0x400abc"
    assert row["scan_root_lines"] == "if (ok) {"

def test_build_structure_table_debug_csv_reads_simpleline_line_text(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(
        0x30,
        8,
        type_name="Child *",
        name="child_ptr",
        comment="linked",
        score=13,
        origin=0x20,
    )
    scan_object = _FakeScanObject(
        func_ea=0x401000,
        ea=0x401234,
        name="child_ptr_scan",
        function_name="child_func",
        root_func_ea=0x400800,
        root_ea=0x400ABC,
        root_function_name="root_func",
    )
    member.scanned_variables = {scan_object}
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])

    class _FakeSimpleLine:
        def __init__(self, line: str):
            self.line = line

        def __str__(self) -> str:
            return "<ida_kernwin.simpleline_t proxy>"

    fake_cfunc = SimpleNamespace(
        treeitems=[SimpleNamespace(ea=0x401234), SimpleNamespace(ea=0x400ABC)],
        find_item_coords=lambda _item: (2, 0) if getattr(_item, "ea", None) == 0x401234 else (1, 0),
        get_pseudocode=lambda: [
            _FakeSimpleLine("if (ok) {"),
            _FakeSimpleLine("    parent->child = value;"),
        ],
    )
    monkeypatch.setattr(form_module, "decompile", lambda func_ea: fake_cfunc if func_ea in (0x401000, 0x400800) else None)

    csv_text = structure_form._build_structure_table_debug_csv()
    rows = list(csv.reader(io.StringIO(csv_text)))
    row = dict(zip(rows[0], rows[1]))

    assert row["scan_lines"] == "parent->child = value;"
    assert row["scan_root_lines"] == "if (ok) {"


def test_copy_structure_table_debug_csv_writes_clipboard(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.scanned_variables = {
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x401234,
            name="child_ptr_scan",
            function_name="child_func",
            root_func_ea=0x400800,
            root_ea=0x400ABC,
            root_function_name="root_func",
        )
    }
    parent.add_member(member)
    structure_form.current_structure = parent
    monkeypatch.setattr(structure_form, "get_selected_members", lambda rows=None: [])
    monkeypatch.setattr(form_module, "decompile", lambda *_args, **_kwargs: None)




    fake_clipboard = SimpleNamespace(text=None, setText=lambda value: setattr(fake_clipboard, "text", value))
    monkeypatch.setattr(form_module.ida_kernwin, "copy_to_clipboard", lambda value: fake_clipboard.setText(value), raising=False)

    structure_form.copy_structure_table_debug_csv()

    assert fake_clipboard.text is not None
    assert fake_clipboard.text.startswith("structure_name,row,offset,type,name,score,comment,enabled,array,origin")




def test_scan_child_structure_rolls_back_new_child_when_scan_finds_nothing(
    monkeypatch,
):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = child_scan_module.ChildScanPlan(
        scan_object=SimpleNamespace(name="child_ptr"),
        function_eas=(0x401000,),
        relation_kind="pointer",
        root_object_name="Parent.child_ptr",
        root_object_ea=0x402000,
        root_function_ea=0x401000,
        has_multiple_roots=False,
    )
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan,
    )
    monkeypatch.setattr(
        structure_form,
        "_execute_child_scan_plan",
        lambda _child_structure, _plan: True,
    )

    structure_form.scan_child_structure()

    assert "Structure" not in structure_form.structures
    assert structure_form.current_structure is parent
    assert parent.child_relationships == []
    assert member.linked_child_structure_name is None


def test_build_child_scan_plan_uses_created_parent_type(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root"),
    ]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.relation_kind == "embedded"
    assert plan.function_eas == (0x401000,)
    assert plan.root_object_name == "Parent.child_ptr"
    assert plan.scan_object.struct_name == "Parent_t"
    assert plan.scan_object.offset == 0x30




def test_build_child_scan_plan_preserves_distinct_scan_locations(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = {
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x402000,
            name="root",
            function_name="root_func",
        ),
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x402010,
            name="root",
            function_name="root_func",
        ),
    }
    parent.add_member(member)
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.function_eas == (0x401000,)
    assert plan.has_multiple_roots is True
    assert plan.root_object_ea in {0x402000, 0x402010}
    assert len(plan.scan_variables) == 2
    assert {scan_variable.ea for scan_variable in plan.scan_variables} == {0x402000, 0x402010}


def test_build_child_scan_plan_accepts_inferred_primitive_member(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("auto_struct_001")
    assert parent is not None

    member = _FakeMember(0xCD8, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root", _name="auto_struct_001"),
    ]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.relation_kind == "embedded"
    assert plan.scan_object.struct_name == "auto_struct_001"
    assert plan.scan_object.offset == 0xCD8



def test_build_child_scan_plan_uses_structure_name_when_untyped(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("auto_struct_001")
    assert parent is not None

    member = _FakeMember(0xCD8, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root"),
    ]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.scan_object.struct_name == "auto_struct_001"
    assert plan.scan_object.offset == 0xCD8


def test_build_child_scan_plan_allows_ambiguous_member_evidence_when_parent_named(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: True, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root_a", _name="TypeA"),
        SimpleNamespace(func_ea=0x401100, ea=0x402100, name="root_b", _name="TypeB"),
    ]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.scan_object.struct_name == "Parent"
    assert plan.has_multiple_roots is True

def test_build_child_scan_plan_prefers_scan_root_evidence(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    parent.created_type_name = "Parent_t"
    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [
        _FakeScanObject(
            func_ea=0x401000,
            ea=0x402000,
            name="root",
            function_name="use_func",
            root_func_ea=0x400800,
            root_ea=0x400ABC,
            root_function_name="seed_func",
        ),
    ]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    plan = structure_form._build_child_scan_plan(member)

    assert plan is not None
    assert plan.function_eas == (0x400800,)
    assert plan.root_object_ea == 0x400ABC
    assert plan.root_function_ea == 0x400800
    assert len(plan.scan_variables) == 1
    assert plan.scan_variables[0].ea == 0x400ABC
    assert plan.scan_variables[0].func_ea == 0x400800



def test_handle_structure_table_selection_change_coalesces_duplicate_signals(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.current_structure = Structure("Parent")

    class _FakeIndex:
        def __init__(self, row):
            self._row = row

        def row(self):
            return self._row

    class _FakeTable:
        def __init__(self):
            self._row = 1
            self._column = 0

        def selectedIndexes(self):
            return [_FakeIndex(self._row)]

        def currentRow(self):
            return self._row

        def currentColumn(self):
            return self._column

    calls = []
    structure_form.ui = SimpleNamespace(tbl_structure=_FakeTable())
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        lambda: calls.append(structure_form._structure_table_selection_signature()),
    )

    structure_form._handle_structure_table_selection_change()
    structure_form._handle_structure_table_selection_change()
    structure_form._handle_structure_table_selection_change()

    assert len(calls) == 1
    assert calls[0] == ("Parent", (1,), 1, 0)

    structure_form.ui.tbl_structure._row = 2
    structure_form._handle_structure_table_selection_change()

    assert len(calls) == 2
    assert calls[1] == ("Parent", (2,), 2, 0)


def test_update_action_states_builds_child_scan_plan_once_per_refresh(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root")]
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = SimpleNamespace(function_eas=(0x401000,), relation_kind="embedded")
    plan_calls = []

    structure_form.ui = SimpleNamespace(
        btn_remove=_Recorder(),
        btn_duplicate_structure=_Recorder(),
        btn_apply_name=_Recorder(),
        input_name=_Recorder(),
        input_filter=_Recorder(),
        tbl_structure=_Recorder(),
        btn_auto_resolve=_Recorder(),
        btn_create_type=_Recorder(),
        btn_enable_rows=_Recorder(),
        btn_disable_rows=_Recorder(),
        btn_toggle_array=_Recorder(),
        btn_set_origin=_Recorder(),
        btn_remove_rows=_Recorder(),
        btn_clear_rows=_Recorder(),
        btn_view_scanned_uses=_Recorder(),
        btn_recognize_vtable=_Recorder(),
        btn_add_row=_Recorder(),
        btn_duplicate_row=_Recorder(),
        btn_edit_row=_Recorder(),
        btn_scan_child=_Recorder(),
        btn_open_child=_Recorder(),
        btn_create_child_types=_Recorder(),
        btn_create_subtree_types=_Recorder(),
        action_enable=_Recorder(),
        action_disable=_Recorder(),
        action_resolve=_Recorder(),
        action_finalize=_Recorder(),
        action_edit=_Recorder(),
        action_add_row=_Recorder(),
        action_duplicate_row=_Recorder(),
        action_scan_child=_Recorder(),
        action_create_child_types=_Recorder(),
        action_create_subtree_types=_Recorder(),
        lbl_summary=_Recorder(),
        lbl_provenance=_Recorder(),
        lbl_root_info=_Recorder(),
        lbl_parent_links=_Recorder(),
        lbl_child_links=_Recorder(),
        lbl_selected_member_info=_Recorder(),
        lbl_type_status=_Recorder(),
    )
    monkeypatch.setattr(structure_form, "get_selected_rows", lambda: [0])
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_plan",
        lambda _member, show_warnings=False: plan_calls.append((_member, show_warnings)) or plan,
    )
    monkeypatch.setattr(structure_form, "_update_summary_label", lambda: None)
    monkeypatch.setattr(structure_form, "_format_structure_provenance", lambda _structure: "manual")
    monkeypatch.setattr(structure_form, "_format_root_info", lambda _structure: "root")
    monkeypatch.setattr(
        structure_form,
        "_format_relationships",
        lambda _relationships, direction: direction,
    )
    monkeypatch.setattr(
        structure_form,
        "_format_selected_member_info",
        lambda _member, *, child_scan_ready=False: "child scan ready" if child_scan_ready else "selected",
    )
    monkeypatch.setattr(structure_form, "_format_type_status", lambda _structure: "status")
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert plan_calls == [(member, False)]
    assert structure_form.ui.btn_scan_child.enabled is True
    assert structure_form.ui.lbl_selected_member_info.text == "Selected Row: child scan ready"


def test_update_action_states_enables_child_scan_actions_for_scannable_member(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root")]
    parent.created_type_name = "Parent_t"
    parent.add_member(member)
    structure_form.current_structure = parent

    plan = SimpleNamespace(function_eas=(0x401000,), relation_kind="embedded")

    structure_form.ui = SimpleNamespace(
        btn_remove=_Recorder(),
        btn_duplicate_structure=_Recorder(),
        btn_apply_name=_Recorder(),
        input_name=_Recorder(),
        input_filter=_Recorder(),
        tbl_structure=_Recorder(),
        btn_auto_resolve=_Recorder(),
        btn_create_type=_Recorder(),
        btn_enable_rows=_Recorder(),
        btn_disable_rows=_Recorder(),
        btn_toggle_array=_Recorder(),
        btn_set_origin=_Recorder(),
        btn_remove_rows=_Recorder(),
        btn_clear_rows=_Recorder(),
        btn_view_scanned_uses=_Recorder(),
        btn_recognize_vtable=_Recorder(),
        btn_add_row=_Recorder(),
        btn_duplicate_row=_Recorder(),
        btn_edit_row=_Recorder(),
        btn_scan_child=_Recorder(),
        btn_open_child=_Recorder(),
        btn_create_child_types=_Recorder(),
        btn_create_subtree_types=_Recorder(),
        action_enable=_Recorder(),
        action_disable=_Recorder(),
        action_resolve=_Recorder(),
        action_finalize=_Recorder(),
        action_edit=_Recorder(),
        action_add_row=_Recorder(),
        action_duplicate_row=_Recorder(),
        action_scan_child=_Recorder(),
        action_create_child_types=_Recorder(),
        action_create_subtree_types=_Recorder(),
    )
    monkeypatch.setattr(structure_form, "get_selected_rows", lambda: [member])
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(structure_form, "_build_child_scan_plan", lambda _member, show_warnings=False: plan)
    monkeypatch.setattr(structure_form, "_update_summary_label", lambda: None)
    monkeypatch.setattr(
        structure_form,
        "_update_inspector_panel",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        structure_form,
        "update_action_states",
        form_module.StructureBuilderForm.update_action_states.__get__(structure_form),
    )

    structure_form.update_action_states()

    assert structure_form.ui.btn_scan_child.enabled is True
    assert structure_form.ui.action_scan_child.enabled is True
    assert (
        "child scan ready"
        in structure_form._format_selected_member_info(member, child_scan_ready=True)
    )



def test_execute_child_scan_plan_builds_hierarchy_requests_with_source_base(monkeypatch):
    """The plan executor groups seeded evidence into HierarchyScanRequests
    carrying the plan's source_base, and delegates to the hierarchy runner."""
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None

    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(SimpleNamespace(func_ea=0x401000, ea=0x402000),),
        source_base=0x30,
    )
    captured = {}

    def fake_hierarchy_scan(structure, requests, *, max_depth):
        captured["structure"] = structure
        captured["requests"] = list(requests)
        captured["max_depth"] = max_depth
        return object()

    monkeypatch.setattr(structure_form, "_run_deep_hierarchy_scan", fake_hierarchy_scan)
    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda _ea: SimpleNamespace(entry_ea=0x401000),
    )

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured["structure"] is child
    assert captured["max_depth"] is None
    requests = captured["requests"]
    assert len(requests) == 1
    assert requests[0].cfunc.entry_ea == 0x401000
    assert requests[0].obj.name == "child_ptr"
    assert requests[0].obj.ea == 0x402000
    assert requests[0].source_base == 0x30


def test_execute_child_scan_plan_runs_for_each_scan_location(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None
    child.main_offset = 0x30

    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(
            SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root_a"),
            SimpleNamespace(func_ea=0x401000, ea=0x402010, name="root_b"),
        ),
        source_base=0x30,
    )

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda _ea: SimpleNamespace(
            entry_ea=0x401000,
            treeitems=[
                SimpleNamespace(ea=0x402000),
                SimpleNamespace(ea=0x402010),
            ],
            eamap={},
            body=None,
        ),
    )

    captured = []

    def fake_hierarchy_scan(structure, requests, *, max_depth):
        for request in requests:
            captured.append(
                (
                    request.cfunc.entry_ea,
                    request.source_base,
                    request.obj.ea,
                    request.obj.func_ea,
                    request.obj.name,
                )
            )
        return object()

    monkeypatch.setattr(structure_form, "_run_deep_hierarchy_scan", fake_hierarchy_scan)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    assert captured == [
        (0x401000, 0x30, 0x402000, 0x401000, "child_ptr"),
        (0x401000, 0x30, 0x402010, 0x401000, "child_ptr"),
    ]


def test_build_child_scan_plan_warns_when_parent_type_missing_from_idb(monkeypatch):
    """A form-only parent structure (missing IDB type) used to fail with a
    silent 'Unable to derive child structure scan results'. The plan builder
    now fails fast with an actionable warning."""
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    member = _FakeMember(0x30, 8, type_name="Child *", name="child_ptr")
    member.tinfo = SimpleNamespace(is_ptr=lambda: True, is_udt=lambda: False)
    member.scanned_variables = [
        SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root_a", _name="TypeA"),
    ]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level (line 13) before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)

    warnings = []
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin, "_parent_type_exists_in_idb",
        staticmethod(lambda name: False),
    )
    monkeypatch.setattr(child_scan_module, "log_warning",
                        lambda message, *_a, **_k: warnings.append(message), raising=False)

    plan = structure_form._build_child_scan_plan(member, show_warnings=True)

    assert plan is None
    assert any("not defined in the IDB" in w for w in warnings), warnings


def test_parent_type_exists_in_idb_queries_the_type_table(monkeypatch):
    structure_form = _make_form(monkeypatch)

    monkeypatch.setattr(
        child_scan_module.ida_typeinf.tinfo_t,
        "get_named_type",
        lambda self, _idati, _name, _flags=0: True,
        raising=False,
    )
    assert (
        structure_form._parent_type_exists_in_idb("Parent") is True
    )

    monkeypatch.setattr(
        child_scan_module.ida_typeinf.tinfo_t,
        "get_named_type",
        lambda self, _idati, _name, _flags=0: False,
        raising=False,
    )
    assert (
        structure_form._parent_type_exists_in_idb("Parent") is False
    )


def test_execute_child_scan_plan_normalizes_legacy_scan_variables(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None

    legacy_lvar = SimpleNamespace(location="stack", defea=0x1234)
    legacy_scan_variable = SimpleNamespace(
        name="root_a",
        ea=0x402000,
        func_ea=0x401000,
        _ScannedVariableObject__lvar=legacy_lvar,
    )
    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(
            name="child_ptr",
            id=import_module("forge.api.scan_object").ObjectType.structure_reference,
        ),
        scan_variables=(legacy_scan_variable,),
        source_base=0x30,
    )

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda _ea: SimpleNamespace(entry_ea=0x401000, treeitems=[], eamap={}, body=None),
    )

    captured = {}

    def fake_hierarchy_scan(_structure, requests, *, max_depth):
        captured["requests"] = list(requests)
        captured["max_depth"] = max_depth
        return object()

    monkeypatch.setattr(structure_form, "_run_deep_hierarchy_scan", fake_hierarchy_scan)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    requests = captured["requests"]
    assert len(requests) == 1
    request = requests[0]
    assert request.cfunc.entry_ea == 0x401000
    assert request.source_base == 0x30
    assert getattr(request.obj, "name", None) == "child_ptr"
    assert getattr(request.obj, "ea", None) == 0x402000
    assert getattr(request.obj, "id", None) == import_module(
        "forge.api.scan_object"
    ).ObjectType.structure_reference
    assert getattr(request.obj, "lvar", None) is None

def test_execute_child_scan_plan_prefers_inferred_child_roots(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None

    inferred_root = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x402000)
    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(SimpleNamespace(func_ea=0x401000, ea=0x402000),),
        source_base=0x30,
    )

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: SimpleNamespace(entry_ea=ea),
    )
    monkeypatch.setattr(
        structure_form,
        "_infer_child_scan_roots",
        lambda cfunc, scan_object: (inferred_root,),
    )

    captured = {}

    def fake_hierarchy_scan(_structure, requests, *, max_depth):
        captured["requests"] = list(requests)
        return object()

    monkeypatch.setattr(structure_form, "_run_deep_hierarchy_scan", fake_hierarchy_scan)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    requests = captured["requests"]
    assert len(requests) == 1
    assert requests[0].cfunc.entry_ea == 0x402000
    assert requests[0].obj is inferred_root
    assert requests[0].source_base == 0x30









def test_collect_evidence_by_function_groups_and_skips_badaddr(monkeypatch):
    structure_form = _make_form(monkeypatch)
    def ev(func_ea, ea):
        return SimpleNamespace(id=object(), func_ea=func_ea, ea=ea)
    plan = SimpleNamespace(
        scan_variables=(
            ev(0x401000, 0x10),
            ev(0x401000, 0x20),
            ev(0x402000, 0x30),
            ev(-1, 0x40),  # BadAddr: dropped
        ),
    )

    grouped = structure_form._collect_evidence_by_function(plan)

    assert sorted(grouped.keys()) == [0x401000, 0x402000]
    assert [v.ea for v in grouped[0x401000]] == [0x10, 0x20]
    assert [v.ea for v in grouped[0x402000]] == [0x30]


def test_sorted_scan_evidence_dedupes_and_orders(monkeypatch):
    structure_form = _make_form(monkeypatch)
    member = SimpleNamespace(
        scanned_variables=[
            SimpleNamespace(func_ea=0x402000, ea=0x30, name="b"),
            SimpleNamespace(func_ea=0x401000, ea=0x10, name="a"),
            SimpleNamespace(func_ea=0x401000, ea=0x10, name="a"),  # duplicate
        ]
    )

    ordered = structure_form._sorted_scan_evidence(member)

    assert len(ordered) == 2
    assert [(v.func_ea, v.ea, v.name) for v in ordered] == [
        (0x401000, 0x10, "a"),
        (0x402000, 0x30, "b"),
    ]


def test_member_scan_tinfo_validates_and_warns(monkeypatch):
    structure_form = _make_form(monkeypatch)
    warnings = []

    legal = SimpleNamespace(is_ptr=lambda: True)
    assert (
        structure_form._member_scan_tinfo(SimpleNamespace(tinfo=legal), warnings.append)
        is legal
    )
    assert warnings == []

    assert (
        structure_form._member_scan_tinfo(SimpleNamespace(tinfo=None), warnings.append)
        is None
    )
    assert len(warnings) == 1

    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda tinfo: False)
    assert (
        structure_form._member_scan_tinfo(
            SimpleNamespace(tinfo=SimpleNamespace(is_ptr=lambda: False)),
            warnings.append,
        )
        is None
    )
    assert len(warnings) == 2


def test_build_child_scan_inference_seed_recovers_descendant_parent_member_anchors(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    offset_10 = _make_descendant_member_evidence(
        0x10, 4, evidence_ea=0x401030, anchor_ea=0x401020, parent_ea=0x401010
    )
    offset_18 = _make_descendant_member_evidence(
        0x18, 0x10, evidence_ea=0x401130, anchor_ea=0x401120, parent_ea=0x401110
    )
    parent_10 = SimpleNamespace(name="v1_parent")
    parent_18 = SimpleNamespace(name="v0_parent")

    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        classmethod(
            lambda cls, _cfunc, expr: (
                parent_10
                if expr is offset_10.parent_expr
                else parent_18 if expr is offset_18.parent_expr else None
            )
        ),
    )

    seed_10 = structure_form._build_child_scan_inference_seed(
        offset_10.cfunc,
        SimpleNamespace(offset=0x10, ea=offset_10.descendant_expr.ea, name="field_10"),
    )
    seed_18 = structure_form._build_child_scan_inference_seed(
        offset_18.cfunc,
        SimpleNamespace(offset=0x18, ea=offset_18.descendant_expr.ea, name="field_18"),
    )

    assert seed_10 is not None
    assert seed_18 is not None
    assert seed_10.parent_object is parent_10
    assert seed_18.parent_object is parent_18
    assert seed_10.evidence_ea == offset_10.anchor_expr.ea
    assert seed_18.evidence_ea == offset_18.anchor_expr.ea
    assert seed_10.scan_object.ea == offset_10.anchor_expr.ea
    assert seed_18.scan_object.ea == offset_18.anchor_expr.ea


def test_infer_child_scan_roots_recovers_descendant_seed_before_walking_callers(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    evidence = _make_descendant_member_evidence(0x10, 4)
    scan_object = SimpleNamespace(
        offset=0x10,
        ea=evidence.descendant_expr.ea,
        name="child_ptr",
    )
    parent_object = SimpleNamespace(
        id=import_module("forge.api.scan_object").ObjectType.local_variable,
        index=0,
        lvar=SimpleNamespace(is_arg_var=True),
        name="a1",
    )
    caller_seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x400800,
        evidence_ea=0x400880,
        scan_object=scan_object,
        parent_object=SimpleNamespace(name="caller_parent"),
        caller_path=(0x401000,),
    )
    inferred_root = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x400800)
    caller_candidate = child_scan_module.ChildScanRootCandidate(
        function_ea=0x400800,
        evidence_ea=0x4008A0,
        root=inferred_root,
        caller_path=(0x401000,),
    )
    caller_cfunc = SimpleNamespace(entry_ea=0x400800)
    seen = []

    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        classmethod(
            lambda cls, _cfunc, expr: parent_object if expr is evidence.parent_expr else None
        ),
    )

    def fake_infer_direct(cfunc, seed):
        seen.append((cfunc.entry_ea, seed.parent_object, seed.evidence_ea))
        if cfunc.entry_ea == evidence.cfunc.entry_ea:
            assert seed.parent_object is parent_object
            assert seed.evidence_ea == evidence.anchor_expr.ea
            return ()
        assert seed is caller_seed
        return (caller_candidate,)

    monkeypatch.setattr(structure_form, "_infer_direct_child_roots", fake_infer_direct)
    monkeypatch.setattr(
        structure_form,
        "_propagate_child_scan_seed",
        lambda cfunc, seed: (caller_seed,) if seed.parent_object is parent_object else (),
    )
    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: caller_cfunc if ea == 0x400800 else None,
    )

    roots = structure_form._infer_child_scan_roots(evidence.cfunc, scan_object)

    assert roots == (inferred_root,)
    assert seen == [
        (0x401000, parent_object, evidence.anchor_expr.ea),
        (0x400800, caller_seed.parent_object, 0x400880),
    ]


def test_infer_child_scan_roots_walks_callers_for_assignment_sources(monkeypatch):
    structure_form = _make_form(monkeypatch)
    scan_object = SimpleNamespace(offset=0x18, name="child_ptr")
    initial_seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x401000,
        evidence_ea=0x402000,
        scan_object=scan_object,
        parent_object=SimpleNamespace(name="arg_parent"),
    )
    caller_seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x400800,
        evidence_ea=0x400880,
        scan_object=scan_object,
        parent_object=SimpleNamespace(name="caller_parent"),
        caller_path=(0x401000,),
    )
    inferred_root = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x400800)
    caller_candidate = child_scan_module.ChildScanRootCandidate(
        function_ea=0x400800,
        evidence_ea=0x4008A0,
        root=inferred_root,
        caller_path=(0x401000,),
    )
    callee_cfunc = SimpleNamespace(entry_ea=0x401000)
    caller_cfunc = SimpleNamespace(entry_ea=0x400800)
    seen = []

    monkeypatch.setattr(
        structure_form,
        "_build_child_scan_inference_seed",
        lambda cfunc, _scan_object, **_kwargs: initial_seed,
    )

    def fake_infer_direct(cfunc, seed):
        seen.append((cfunc.entry_ea, seed.function_ea))
        if cfunc.entry_ea == 0x401000:
            return ()
        return (caller_candidate,)

    monkeypatch.setattr(structure_form, "_infer_direct_child_roots", fake_infer_direct)
    monkeypatch.setattr(
        structure_form,
        "_propagate_child_scan_seed",
        lambda cfunc, seed: (caller_seed,) if seed is initial_seed else (),
    )
    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: caller_cfunc if ea == 0x400800 else None,
    )

    roots = structure_form._infer_child_scan_roots(callee_cfunc, scan_object)

    assert roots == (inferred_root,)
    assert seen == [(0x401000, 0x401000), (0x400800, 0x400800)]


def test_infer_direct_child_roots_matches_pointer_arithmetic_assignment(monkeypatch):
    structure_form = _make_form(monkeypatch)
    ctype = child_scan_module.ctype
    monkeypatch.setattr(child_scan_module.ctype, "ptr", "ptr", raising=False)
    monkeypatch.setattr(child_scan_module.ctype, "asg", "asg", raising=False)
    parent_expr = SimpleNamespace(op=ctype.var, ea=0x401050)
    rhs_expr = SimpleNamespace(op=ctype.var, ea=0x401060)
    index_expr = SimpleNamespace(op=ctype.num, numval=lambda: 3)
    idx_expr = SimpleNamespace(
        op=ctype.idx,
        x=SimpleNamespace(op=ctype.cast, x=parent_expr),
        y=index_expr,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )
    lhs_expr = SimpleNamespace(
        op=ctype.ptr,
        x=idx_expr,
        type=SimpleNamespace(get_ptrarr_objsize=lambda: 8),
    )
    assignment = SimpleNamespace(op=ctype.asg, x=lhs_expr, y=rhs_expr, ea=0x401070)
    cfunc = SimpleNamespace(entry_ea=0x401000, treeitems=[assignment])
    parent_object = SimpleNamespace(name="parent")
    root_object = SimpleNamespace(name="child_var", ea=0x500123, func_ea=0x401000)
    seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x401000,
        evidence_ea=0x402000,
        scan_object=SimpleNamespace(offset=24),
        parent_object=parent_object,
    )

    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_scan_object_matches_expr",
        staticmethod(lambda obj, expr: obj is parent_object and expr is parent_expr),
    )
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        classmethod(lambda cls, _cfunc, expr: root_object if expr is rhs_expr else None),
    )

    candidates = structure_form._infer_direct_child_roots(cfunc, seed)

    assert len(candidates) == 1
    assert candidates[0].root is root_object
    assert candidates[0].function_ea == 0x401000


def test_create_scan_object_from_expr_unwraps_casted_offset_expression(monkeypatch):
    ctype = child_scan_module.ctype
    cfunc = SimpleNamespace(entry_ea=0x401000)
    base_expr = SimpleNamespace(op=ctype.var, ea=0x401020)
    offset_expr = SimpleNamespace(op=ctype.num, numval=lambda: 0x20)
    wrapped_expr = SimpleNamespace(
        op=ctype.cast,
        x=SimpleNamespace(op=ctype.add, x=base_expr, y=offset_expr),
    )
    base_object = SimpleNamespace(name="child_base")
    derived_object = SimpleNamespace(name="child_offset")

    monkeypatch.setattr(
        child_scan_module.ScanObject,
        "create",
        staticmethod(lambda _cfunc, expr: base_object if expr is base_expr else None),
    )
    monkeypatch.setattr(
        child_scan_module,
        "_make_offset_scan_object",
        lambda obj, offset: derived_object if obj is base_object and offset == 0x20 else None,
    )

    result = child_scan_module.ChildScanMixin._create_scan_object_from_expr(cfunc, wrapped_expr)

    assert result is derived_object
    assert result.func_ea == 0x401000


def test_execute_child_scan_plan_falls_back_to_seeded_member_when_inference_fails(monkeypatch):
    structure_form = _make_form(monkeypatch)
    child = structure_form.create_structure("Child")
    assert child is not None

    plan = SimpleNamespace(
        function_eas=(0x401000,),
        scan_object=SimpleNamespace(name="child_ptr", id="member"),
        scan_variables=(SimpleNamespace(func_ea=0x401000, ea=0x402000),),
        source_base=0x30,
    )
    warnings = []

    monkeypatch.setattr(
        structure_form,
        "_prepare_scan_cfunc",
        lambda ea: SimpleNamespace(entry_ea=ea),
    )
    monkeypatch.setattr(
        structure_form,
        "_infer_child_scan_roots",
        lambda cfunc, scan_object: (),
    )
    monkeypatch.setattr(
        child_scan_module,
        "log_warning",
        lambda message=None, display_messagebox=False: warnings.append((message, display_messagebox)),
    )

    captured = {}

    def fake_hierarchy_scan(_structure, requests, *, max_depth):
        captured["requests"] = list(requests)
        return object()

    monkeypatch.setattr(structure_form, "_run_deep_hierarchy_scan", fake_hierarchy_scan)

    assert structure_form._execute_child_scan_plan(child, plan) is True
    requests = captured["requests"]
    assert len(requests) == 1
    assert requests[0].cfunc.entry_ea == 0x401000
    assert requests[0].obj.name == "child_ptr"
    assert requests[0].obj.ea == 0x402000
    assert requests[0].source_base == 0x30
    assert any(
        "fell back to seeded member evidence" in message
        for message, _display in warnings
        if message is not None
    )



def test_scan_child_structure_uses_absolute_member_origin(monkeypatch):
    """Embedded children scan the parent buffer: the plan carries the
    member's absolute origin as source_base (the hierarchy session re-bases
    observations by subtracting it), and the child structure itself is
    stored child-local (main_offset 0)."""
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    assert parent is not None

    member = _FakeMember(0xCD8, 8, type_name="u64", name="child_ptr", origin=0x30)
    member.tinfo = SimpleNamespace(is_ptr=lambda: False, is_udt=lambda: False)
    member.scanned_variables = [SimpleNamespace(func_ea=0x401000, ea=0x402000, name="root")]
    structure_form.current_structure = parent
    # is_legal_type is bound module-level before import_module;
    # patching form_module would target a name form no longer holds.
    monkeypatch.setattr(child_scan_module, "is_legal_type", lambda _tinfo: True, raising=False)
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_parent_type_exists_in_idb",
        staticmethod(lambda name: True),
    )

    plan = structure_form._build_child_scan_plan(member, show_warnings=True)

    assert plan is not None
    assert plan.relation_kind == "embedded"
    assert plan.source_base == 0xD08


def test_link_child_structure_materializes_pointer_and_inline_member_types(monkeypatch):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    assert parent is not None
    assert child is not None
    child.created_type_name = "ChildType"

    member_pointer = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    member_inline = _FakeMember(0x40, 8, type_name="u64", name="child_inline")

    parent.add_member(member_pointer)
    parent.add_member(member_inline)

    sentinel = SimpleNamespace(
        dstr=lambda: "ChildType",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    seen: list[tuple[str, str, str]] = []

    def fake_materialize(member, child_type_name, relation_kind):
        seen.append((member.name, child_type_name, relation_kind))
        member.tinfo = sentinel
        return True

    monkeypatch.setattr(
        child_scan_module,
        "materialize_linked_child_member_type",
        fake_materialize,
    )

    form_module.StructureBuilderForm._link_child_structure(parent, child, member_pointer, "pointer")
    form_module.StructureBuilderForm._link_child_structure(parent, child, member_inline, "embedded")

    assert ("child_ptr", "ChildType", "pointer") in seen
    assert ("child_inline", "ChildType", "embedded") in seen
    assert member_pointer.tinfo is sentinel
    assert member_inline.tinfo is sentinel
    assert member_pointer.child_relation_kind == "pointer"
    assert member_inline.child_relation_kind == "embedded"


def test_link_child_structure_defers_materialization_for_untyped_auto_child(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure(" ")
    assert parent is not None
    assert child is not None

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    original_tinfo = SimpleNamespace(
        dstr=lambda: "u64",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    member.tinfo = original_tinfo
    parent.add_member(member)
    seen = []

    monkeypatch.setattr(
        child_scan_module,
        "materialize_linked_child_member_type",
        lambda *_args: seen.append(_args) or True,
    )

    form_module.StructureBuilderForm._link_child_structure(parent, child, member, "pointer")

    assert seen == []
    assert member.tinfo is original_tinfo
    assert member.linked_child_structure_name == child.name
    assert member.child_relation_kind == "pointer"


def test_refresh_all_linked_member_types_materializes_deferred_child_links(
    monkeypatch,
 ):
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    assert parent is not None
    assert child is not None
    child.created_type_name = "ChildType"

    member = _FakeMember(0x30, 8, type_name="u64", name="child_ptr")
    original_tinfo = SimpleNamespace(
        dstr=lambda: "u64",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    sentinel = SimpleNamespace(
        dstr=lambda: "ChildType",
        get_size=lambda: 8,
        is_funcptr=lambda: False,
    )
    member.tinfo = original_tinfo
    parent.add_member(member)
    relationship = parent.add_child_relationship(
        child_structure_name="Child",
        parent_member_offset=0x30,
        parent_member_name="child_ptr",
        relation_kind="pointer",
    )
    child.add_parent_relationship(relationship)
    member.linked_child_structure_name = "Child"
    member.child_relation_kind = "pointer"
    seen = []

    def fake_materialize(member, child_type_name, relation_kind):
        seen.append((member.name, child_type_name, relation_kind))
        member.tinfo = sentinel
        return True

    monkeypatch.setattr(
        structure_module,
        "materialize_linked_child_member_type",
        fake_materialize,
    )

    structure_form._refresh_all_linked_member_types()

    assert seen == [("child_ptr", "ChildType", "pointer")]
    assert member.tinfo is sentinel


def test_convert_to_vtable_replaces_member_with_virtual_table(monkeypatch):
    structure_form = _make_form(monkeypatch)
    structure_form.create_structure("TestStruct")

    member = _FakeMember(0, 8, type_name="_QWORD", comment="from deep scan")
    member.scanned_variables = {"sv1", "sv2"}
    structure_form.current_structure.members.append(member)

    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)

    monkeypatch.setattr(form_module.ida_kernwin, "HIST_IDENT", 0, raising=False)
    monkeypatch.setattr(
        form_module.ida_kernwin,
        "ask_str",
        lambda *_args, **_kwargs: "0x140018338",
    )

    captured = {}

    class _FakeVirtualTable:
        def __init__(self, offset, address, scanned_variable=None, origin=None):
            captured["offset"] = offset
            captured["address"] = address
            captured["origin"] = origin
            self.offset = offset
            self.address = address
            self.scanned_variables = set()
            self.comment = ""
            self.type_name = "VTable"
            self.name = "vftable"
            self.enabled = True
            self.is_array = False
            self.size = 8
            self.origin = origin

        @staticmethod
        def is_virtual_table(address):
            return 5

        def __lt__(self, other):
            return (self.offset, self.type_name) < (
                getattr(other, "offset", 0),
                getattr(other, "type_name", ""),
            )

        __hash__ = None  # mutable fake; __eq__ compares

        def __eq__(self, other):
            return (self.offset, self.type_name) == (
                getattr(other, "offset", 0),
                getattr(other, "type_name", ""),
            )

    monkeypatch.setattr(form_module, "VirtualTable", _FakeVirtualTable)

    structure_form.convert_to_vtable()

    assert len(structure_form.current_structure.members) == 1
    vtable = structure_form.current_structure.members[0]
    assert isinstance(vtable, _FakeVirtualTable)
    assert captured["offset"] == 0
    assert captured["address"] == 0x140018338
    assert captured["origin"] == 0
    assert vtable.scanned_variables == {"sv1", "sv2"}
    assert vtable.comment == "from deep scan"

# ---------------------------------------------------------------------------
# T3.5 G-gap regression tests
# ---------------------------------------------------------------------------


def test_duplicate_structure_copies_child_links_then_normalizes(monkeypatch):
    """G1: duplicating a structure re-targets self-child links (name,
    offset, kind) and re-normalizes member links."""
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    linked = _FakeMember(0x10, 8, name="child_ptr")
    linked.linked_child_structure_name = "Child"
    linked.child_relation_kind = "pointer"
    parent.add_member(linked)
    parent.add_child_relationship(child_structure_name="Child", parent_member_offset=0x10, parent_member_name="child_ptr", relation_kind="pointer")
    child.add_member(_FakeMember(0x0, 4))
    structure_form.current_structure = parent
    assert child.parent_relationships == []

    structure_form.duplicate_structure()

    duplicate = structure_form.structures["Parent Copy"]
    assert duplicate.child_relationships[0].parent_member_offset == 0x10
    assert duplicate.child_relationships[0].child_structure_name == "Child"
    assert duplicate.child_relationships[0].relation_kind == "pointer"
    member = duplicate.get_member_by_offset(0x10)
    assert member.linked_child_structure_name == "Child"
    assert member.child_relation_kind == "pointer"
    assert len(child.parent_relationships) == 1
    parent_rel = child.parent_relationships[0]
    assert parent_rel.parent_structure_name == "Parent Copy"
    assert parent_rel.parent_member_offset == 0x10


def test_remove_structure_cleans_other_structures_relationships(monkeypatch):
    """G2: removing a structure drops every relationship pointing at it."""
    structure_form = _make_form(monkeypatch)
    parent = structure_form.create_structure("Parent")
    child = structure_form.create_structure("Child")
    parent.add_child_relationship(child_structure_name="Child", parent_member_offset=0x8, parent_member_name="u64_8", relation_kind="pointer")
    structure_form.ui = SimpleNamespace(tree_structures=object())
    structure_form.set_structure("Parent")
    monkeypatch.setattr(structure_form, "_current_tree_structure", lambda: parent)

    structure_form.remove_structure()

    assert "Parent" not in structure_form.structures
    assert child.parent_relationships == []


def test_nudge_main_offset_follows_selected_member(monkeypatch):
    """G3: nudging the member that owns main_offset moves main_offset with it."""
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    structure.set_main_offset(0x10)
    member_at_main = _FakeMember(0x10, 8, name="root")
    other = _FakeMember(0x0, 8, name="field_0")
    structure.add_member(member_at_main)
    structure.add_member(other)
    structure_form.current_structure = structure
    monkeypatch.setattr(structure_form, "get_selected_members", lambda: [member_at_main])

    structure_form.nudge_selected_rows(8)

    assert member_at_main.offset == 0x18
    assert structure.main_offset == 0x18
    assert other.offset == 0x0


def test_structure_table_clear_decline_keeps_members(monkeypatch):
    """G4: declining the clear dialog leaves all members intact."""
    import ida_kernwin

    monkeypatch.setattr(ida_kernwin, "ASKBTN_NO", 0, raising=False)
    monkeypatch.setattr(ida_kernwin, "ASKBTN_YES", 1, raising=False)
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    structure.add_member(_FakeMember(0x0, 8))
    structure_form.current_structure = structure
    monkeypatch.setattr(ida_kernwin, "ask_yn", lambda dflt, text: ida_kernwin.ASKBTN_NO, raising=False)

    structure_form.structure_table_clear()

    assert len(structure.members) == 1

    monkeypatch.setattr(ida_kernwin, "ask_yn", lambda dflt, text: ida_kernwin.ASKBTN_YES, raising=False)
    structure_form.structure_table_clear()
    assert structure.members == []


def test_convert_to_vtable_decline_preserves_member(monkeypatch):
    """G6: declining the 'convert anyway' prompt keeps the member as-is."""
    import ida_kernwin

    monkeypatch.setattr(ida_kernwin, "ASKBTN_NO", 0, raising=False)
    monkeypatch.setattr(ida_kernwin, "ASKBTN_YES", 1, raising=False)
    monkeypatch.setattr(ida_kernwin, "HIST_IDENT", 1, raising=False)
    monkeypatch.setattr(ida_kernwin, "warning", lambda *a, **k: None, raising=False)
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    member = _FakeMember(0x10, 8, name="vtbl", origin=0x10)
    structure.add_member(member)
    structure_form.current_structure = structure
    monkeypatch.setattr(structure_form, "get_selected_member", lambda: member)
    monkeypatch.setattr(ida_kernwin, "ask_str", lambda dflt, hist, title: "140001000", raising=False)
    monkeypatch.setattr(ida_kernwin, "ask_yn", lambda dflt, text: ida_kernwin.ASKBTN_NO, raising=False)

    class _FakeVirtualTable:
        def __init__(self, offset, address, scanned_variable=None, origin=None):
            self.offset = offset
            self.origin = origin
            self.name = "vtbl"
            self.enabled = True
            self.is_array = False
            self.comment = ""
            self.scanned_variables = set()

        def invalidate_score(self):
            pass

        @staticmethod
        def is_virtual_table(address):
            return 0

    monkeypatch.setattr(form_module, "VirtualTable", _FakeVirtualTable)

    structure_form.convert_to_vtable()

    assert structure.members == [member]

    monkeypatch.setattr(ida_kernwin, "ask_yn", lambda dflt, text: ida_kernwin.ASKBTN_YES, raising=False)
    structure_form.convert_to_vtable()

    assert len(structure.members) == 1
    assert structure.members[0].offset == 0x10
    assert structure.members[0].origin == 0x10


def test_structure_table_item_changed_name_vs_comment_column(monkeypatch):
    """G7: name-column edits strip and fall back to the old name; comment
    edits apply verbatim; other columns are ignored."""
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    member = _FakeMember(0x0, 8, name="field_0", comment="old")
    structure.add_member(member)
    structure_form.current_structure = structure
    form_module.StructureBuilderForm = form_module.StructureBuilderForm  # type: ignore[attr-defined]

    class _Item:
        def __init__(self, row, column, text):
            self.row_ = row
            self.column_ = column
            self.text_ = text

        def row(self):
            return self.row_

        def column(self):
            return self.column_

        def text(self):
            return self.text_

    structure_form.structure_table_item_changed(_Item(0, form_module.Column.name, "  renamed  "))
    assert member.name == "renamed"
    structure_form.structure_table_item_changed(_Item(0, form_module.Column.name, "   "))
    assert member.name == "renamed"  # empty edit keeps the old name
    structure_form.structure_table_item_changed(_Item(0, form_module.Column.comment, "new note"))
    assert member.comment == "new note"
    structure_form.structure_table_item_changed(_Item(0, form_module.Column.score, "99"))
    assert member.name == "renamed"
    assert member.comment == "new note"


def test_member_child_link_normalization_clears_stale_links(monkeypatch):
    """G9: a member whose child link points at a relationship that no longer
    exists gets its link cleared; existing links keep their kind."""
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    member = _FakeMember(0x10, 8, name="ptr")
    member.linked_child_structure_name = "Ghost"
    member.child_relation_kind = "pointer"
    structure.add_member(member)
    live = _FakeMember(0x18, 8, name="live")
    live.linked_child_structure_name = "Child"
    live.child_relation_kind = "array"
    structure.add_member(live)
    structure.add_child_relationship(child_structure_name="Child", parent_member_offset=0x18, parent_member_name="live", relation_kind="array")

    structure_form._normalize_member_child_links(structure)

    assert member.linked_child_structure_name is None
    assert member.child_relation_kind is None
    assert live.linked_child_structure_name == "Child"
    assert live.child_relation_kind == "array"


def test_make_unique_structure_name_copy_collision_loop(monkeypatch):
    """G10/I.28: catalog.unique_name 'Copy N' naming increments past every
    existing collision."""
    from forge.api.store import catalog as _catalog

    structure_form = _make_form(monkeypatch)
    for name in ("Foo", "Foo Copy", "Foo Copy 2", "Foo Copy 3"):
        structure_form.create_structure(name)

    assert _catalog.unique_name("Foo") == "Foo Copy 4"
    assert _catalog.unique_name("Bar") == "Bar"

    structure_form.create_structure("Foo Copy 5")
    assert _catalog.unique_name("Foo") == "Foo Copy 4"


def test_propagate_child_scan_seed_unresolvable_parent_arg_is_noop(monkeypatch):
    """G11: a seed whose parent object cannot resolve to an argument index
    propagates nothing and never decompiles callers."""
    form = _make_form(monkeypatch)
    from types import SimpleNamespace as NS

    seed = child_scan_module.ChildScanInferenceSeed(
        function_ea=0x1400014F0,
        evidence_ea=0x140001579,
        scan_object=NS(id=1),
        parent_object=NS(id=999),  # not a local variable -> arg index is None
    )
    touched = []
    monkeypatch.setattr(
        child_scan_module,
        "_get_funcs_calling_address",
        lambda ea: touched.append(ea) or [0x140001000],
    )

    propagated = form._propagate_child_scan_seed(None, seed)

    assert propagated == ()
    assert touched == []


def test_create_scan_object_from_expr_fallback_paths(monkeypatch):
    """G13: expression-derived objects fall back to the offset-expression
    walker when ScanObject.create cannot parse the raw expression."""
    form = _make_form(monkeypatch)
    from types import SimpleNamespace as NS

    cfunc = NS(entry_ea=0x1400014F0)
    base = NS(name="base")

    assert form._create_scan_object_from_expr(cfunc, None) is None

    monkeypatch.setattr(
        child_scan_module.ScanObject, "create",
        staticmethod(lambda cfunc, expr: base if expr is base else None), raising=False,
    )
    monkeypatch.setattr(
        child_scan_module, "_extract_offset_expression",
        lambda expr: (None, 0), raising=False,
    )
    assert form._create_scan_object_from_expr(cfunc, NS(ea=1)) is None

    monkeypatch.setattr(
        child_scan_module, "_extract_offset_expression",
        lambda expr: (base, 4), raising=False,
    )
    monkeypatch.setattr(
        child_scan_module, "_make_offset_scan_object",
        lambda scan_object, offset: offset, raising=False,
    )

    offset_object = NS(name="offset")
    monkeypatch.setattr(
        child_scan_module, "_make_offset_scan_object",
        lambda scan_object, offset: offset_object, raising=False,
    )

    result = form._create_scan_object_from_expr(cfunc, NS(ea=1))
    assert result is offset_object  # the offset scan object from the walker
    assert result.func_ea == 0x1400014F0


def test_build_child_scan_inference_seed_explicit_parent_expr_skips_anchor(monkeypatch):
    """G14: an explicitly provided parent expression bypasses member-anchor
    resolution entirely (used by the caller-side propagation path)."""
    form = _make_form(monkeypatch)
    from types import SimpleNamespace as NS

    resolved = []
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_resolve_member_anchor",
        staticmethod(lambda *a, **k: resolved.append(a) or object()),
    )
    parent_expr = NS(ea=5)
    parent_obj = NS(id=1)
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_create_scan_object_from_expr",
        staticmethod(lambda cfunc, expr: parent_obj if expr is parent_expr else None),
    )
    monkeypatch.setattr(
        child_scan_module.ChildScanMixin,
        "_expression_ea",
        staticmethod(lambda cfunc, expr: getattr(expr, "ea", 0)),
    )

    seed = form._build_child_scan_inference_seed(
        NS(entry_ea=0x1400014F0),
        NS(id=1),
        parent_expr=parent_expr,
    )

    assert resolved == []
    assert seed.parent_object is parent_obj
    assert seed.evidence_ea == 5
    assert seed.function_ea == 0x1400014F0


def test_structure_table_resolve_confirms_before_disabling(monkeypatch):
    """T4.1: auto-resolve previews what it would disable and the user must
    confirm before the disabling commits."""
    import ida_kernwin

    monkeypatch.setattr(ida_kernwin, "ASKBTN_NO", 0, raising=False)
    monkeypatch.setattr(ida_kernwin, "ASKBTN_YES", 1, raising=False)
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    structure.add_member(_FakeMember(0, 8, name="base"))
    structure.add_member(_FakeMember(4, 8, name="overlap"))
    structure_form.current_structure = structure
    resolved = []
    monkeypatch.setattr(
        structure, "auto_resolve_preview",
        lambda: [structure.members[1]], raising=False,
    )
    monkeypatch.setattr(
        structure, "auto_resolve", lambda: resolved.append(True), raising=False,
    )

    monkeypatch.setattr(
        ida_kernwin, "ask_yn",
        lambda dflt, text: ida_kernwin.ASKBTN_NO, raising=False,
    )
    structure_form.structure_table_resolve()
    assert resolved == []  # declined -> nothing disabled

    monkeypatch.setattr(
        ida_kernwin, "ask_yn",
        lambda dflt, text: ida_kernwin.ASKBTN_YES, raising=False,
    )
    structure_form.structure_table_resolve()
    assert resolved == [True]  # confirmed -> resolve runs


def test_nudge_into_collision_with_unselected_member_is_rejected(monkeypatch):
    """T4.2: nudging a selected member so it overlaps a non-selected one is
    refused and every offset is restored."""
    structure_form = _make_form(monkeypatch)
    structure = structure_form.create_structure("S")
    unselected = _FakeMember(0x8, 8, name="a")   # occupies 0x8..0x10
    selected = _FakeMember(0x0, 8, name="b")     # occupies 0x0..0x8
    structure.add_member(unselected)
    structure.add_member(selected)
    structure_form.current_structure = structure
    monkeypatch.setattr(structure_form, "get_selected_members", lambda: [selected])
    warnings = []
    monkeypatch.setattr(
        form_module, "log_warning",
        lambda msg, *a, **k: warnings.append(msg), raising=False,
    )

    structure_form.nudge_selected_rows(4)  # 0x4..0xC would overlap 0x8..0x10

    assert selected.offset == 0x0
    assert unselected.offset == 0x8
    assert any("non-selected member" in msg for msg in warnings)


def test_on_close_clears_structure_models(monkeypatch):
    """T4.4/I.28: closing the form drops the cached UI/scan state but keeps
    the shared catalog — headless structures outlive the form."""
    structure_form = _make_form(monkeypatch)
    structure_form.create_structure("Foo")
    structure_form.current_structure = structure_form.structures["Foo"]
    structure_form.parent = object()
    structure_form.ui = SimpleNamespace(tbl_structure=object(), tree_structures=object())

    structure_form.OnClose(None)

    assert list(structure_form.structures) == ["Foo"]
    assert structure_form.current_structure is None
    assert structure_form.ui is None
    assert structure_form.parent is None


def test_configure_table_edit_triggers_combine_int_values(monkeypatch):
    """PySide6 regression: bitwise-ORing EditTrigger enums trips the
    PyQt5-shim RuntimeWarning; _configure_table must combine int values."""
    structure_form = _make_form(monkeypatch)
    from types import SimpleNamespace as NS

    class _Table:
        def __init__(self):
            self.edit_triggers = None

        def setSelectionBehavior(self, value):
            pass

        def setSelectionMode(self, value):
            pass

        def setEditTriggers(self, value):
            self.edit_triggers = value

        def setAlternatingRowColors(self, value):
            pass

        def setSortingEnabled(self, value):
            pass

    table = _Table()
    structure_form.ui = NS(tbl_structure=table)
    monkeypatch.setattr(
        form_module.QtWidgets,
        "QAbstractItemView",
        NS(
            SelectRows=NS(value=1),
            ExtendedSelection=NS(value=3),
            DoubleClicked=NS(value=4),
            EditKeyPressed=NS(value=8),
        ),
        raising=False,
    )

    structure_form._configure_table()

    assert table.edit_triggers == 12  # 4 | 8, computed on plain ints
