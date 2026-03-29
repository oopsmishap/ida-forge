from __future__ import annotations

import copy
import csv
import io
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional

import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi

from forge.util.qt import QtCore, QtGui, QtWidgets, qt_exec
from .ui_form import Ui_view_form

QSignalBlocker = QtCore.QSignalBlocker
Qt = QtCore.Qt
QColor = QtGui.QColor
QTreeWidgetItem = QtWidgets.QTreeWidgetItem
QMenu = QtWidgets.QMenu
QTableWidgetItem = QtWidgets.QTableWidgetItem
QWidget = QtWidgets.QWidget

from forge.api.hexrays import decompile, is_legal_type
from forge.api.members import AbstractMember, Member, VirtualTable, parse_user_tinfo
from forge.api.scan_object import ScanObject, StructurePointerObject, StructureReferenceObject
from forge.api.scanner import NewDeepScanVisitor
from forge.api.structure import Structure, StructureRelationship
from forge.api.ui import Choose, set_row_background_color, set_row_foreground_color
from forge.util.logging import log_debug, log_warning
from .config import config


class Column(IntEnum):
    offset = 0
    type = 1
    name = 2
    score = 3
    comment = 4


@dataclass
class MemberEditorValues:
    offset: int
    type_name: str
    name: str
    comment: str
    enabled: bool
    is_array: bool

@dataclass(frozen=True)
class ChildScanPlan:
    scan_object: ScanObject
    function_eas: tuple[int, ...]
    relation_kind: str
    root_object_name: str
    root_object_ea: int | None
    root_function_ea: int | None
    has_multiple_roots: bool


class UI(QWidget, Ui_view_form):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)


class ScannedVariableChooser(Choose):
    title = "Scanned Variables"
    cols = [
        ["Origin", 10],
        ["Function", 24],
        ["Name", 24],
        ["Address", 14],
    ]

    def __init__(self, scanned_variables):
        self._scanned_variables = list(scanned_variables)
        super().__init__([obj.to_list() for obj in self._scanned_variables])

    def OnSelectLine(self, n):
        scanned_variable = self._scanned_variables[n]
        if scanned_variable.func_ea != idaapi.BADADDR:
            ida_hexrays.open_pseudocode(scanned_variable.func_ea, ida_hexrays.OPF_REUSE)
        ida_kernwin.jumpto(scanned_variable.ea)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)


class MemberEditorDialog(QtWidgets.QDialog):
    def __init__(
        self,
        parent=None,
        *,
        title: str,
        values: MemberEditorValues,
    ):
        super().__init__(parent)
        self.setWindowTitle(title)

        self.offset_edit = QtWidgets.QLineEdit(f"0x{values.offset:X}")
        self.type_edit = QtWidgets.QLineEdit(values.type_name)
        self.name_edit = QtWidgets.QLineEdit(values.name)
        self.comment_edit = QtWidgets.QLineEdit(values.comment)
        self.enabled_checkbox = QtWidgets.QCheckBox("Enabled")
        self.enabled_checkbox.setChecked(values.enabled)
        self.array_checkbox = QtWidgets.QCheckBox("Treat as array")
        self.array_checkbox.setChecked(values.is_array)

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow("Offset", self.offset_edit)
        form_layout.addRow("Type", self.type_edit)
        form_layout.addRow("Name", self.name_edit)
        form_layout.addRow("Comment", self.comment_edit)

        option_layout = QtWidgets.QHBoxLayout()
        option_layout.addWidget(self.enabled_checkbox)
        option_layout.addWidget(self.array_checkbox)
        option_layout.addStretch(1)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form_layout)
        layout.addLayout(option_layout)
        layout.addWidget(buttons)

    @staticmethod
    def _parse_offset(text: str) -> int | None:
        try:
            return int(text, 0)
        except ValueError:
            return None

    def get_values(self) -> MemberEditorValues | None:
        offset = self._parse_offset(self.offset_edit.text().strip())
        if offset is None:
            log_warning(f"Invalid offset: {self.offset_edit.text().strip()}", True)
            return None

        return MemberEditorValues(
            offset=offset,
            type_name=self.type_edit.text().strip(),
            name=self.name_edit.text().strip(),
            comment=self.comment_edit.text().strip(),
            enabled=self.enabled_checkbox.isChecked(),
            is_array=self.array_checkbox.isChecked(),
        )


class BulkMemberEditorDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, *, selection_count: int):
        super().__init__(parent)
        self.setWindowTitle(f"Edit {selection_count} Structure Rows")

        self.offset_delta_edit = QtWidgets.QLineEdit("0")
        self.type_edit = QtWidgets.QLineEdit()
        self.type_edit.setPlaceholderText("Leave empty to keep existing types")
        self.comment_edit = QtWidgets.QLineEdit()
        self.comment_edit.setPlaceholderText("Leave empty to keep existing comments")
        self.name_prefix_edit = QtWidgets.QLineEdit()
        self.name_prefix_edit.setPlaceholderText("Optional prefix added to each name")

        self.enabled_combo = QtWidgets.QComboBox()
        self.enabled_combo.addItems(["No change", "Enable", "Disable"])

        self.array_combo = QtWidgets.QComboBox()
        self.array_combo.addItems(
            ["No change", "Enable array", "Disable array", "Toggle array"]
        )

        info_label = QtWidgets.QLabel(
            "Blank fields keep existing values. Offset delta is applied to every selected row."
        )
        info_label.setWordWrap(True)

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow("Offset delta", self.offset_delta_edit)
        form_layout.addRow("Type", self.type_edit)
        form_layout.addRow("Comment", self.comment_edit)
        form_layout.addRow("Name prefix", self.name_prefix_edit)
        form_layout.addRow("Enabled", self.enabled_combo)
        form_layout.addRow("Array", self.array_combo)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(info_label)
        layout.addLayout(form_layout)
        layout.addWidget(buttons)

    def get_values(self) -> dict | None:
        try:
            offset_delta = int(self.offset_delta_edit.text().strip() or "0", 0)
        except ValueError:
            log_warning(
                f"Invalid offset delta: {self.offset_delta_edit.text().strip()}",
                True,
            )
            return None

        return {
            "offset_delta": offset_delta,
            "type_name": self.type_edit.text().strip(),
            "comment": self.comment_edit.text(),
            "name_prefix": self.name_prefix_edit.text(),
            "enabled_mode": self.enabled_combo.currentText(),
            "array_mode": self.array_combo.currentText(),
        }


class StructureBuilderForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None
        self.ui = None
        self.structures: Dict[str, Structure] = {}
        self.current_structure: Structure | None = None
        self.layout = None
        self._shortcut_actions: list[QtGui.QAction] = []

    def show(self):
        return ida_kernwin.PluginForm.Show(self, "Structure Builder")

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QVBoxLayout(self.parent)
        self.ui = UI(self.parent)
        self.layout.addWidget(self.ui)

        self._connect_signals()
        self._configure_table()
        self.reload_structure_list()
        self._install_shortcuts()
        self.update_action_states()
        self.update_structure_fields()

    def _connect_signals(self) -> None:
        self.ui.btn_add.clicked.connect(self.add_structure)
        self.ui.btn_remove.clicked.connect(self.remove_structure)
        self.ui.btn_duplicate_structure.clicked.connect(self.duplicate_structure)
        self.ui.btn_apply_name.clicked.connect(self.structure_renamed)
        self.ui.input_name.returnPressed.connect(self.structure_renamed)
        self.ui.input_filter.textChanged.connect(self.reload_structure_list)
        self.ui.btn_auto_resolve.clicked.connect(self.structure_table_resolve)
        self.ui.btn_create_type.clicked.connect(self.structure_table_finalize)
        self.ui.btn_enable_rows.clicked.connect(
            lambda: self.structure_table_enable_row(None)
        )
        self.ui.btn_disable_rows.clicked.connect(
            lambda: self.structure_table_disable_row(None)
        )
        self.ui.btn_toggle_array.clicked.connect(self.structure_table_toggle_array)
        self.ui.btn_set_origin.clicked.connect(self.structure_table_set_origin)
        self.ui.btn_remove_rows.clicked.connect(self.structure_table_remove_rows)
        self.ui.btn_clear_rows.clicked.connect(self.structure_table_clear)
        self.ui.btn_view_scanned_uses.clicked.connect(self.show_scanned_variables)
        self.ui.btn_recognize_vtable.clicked.connect(self.structure_table_recognize)
        self.ui.btn_add_row.clicked.connect(self.add_manual_row)
        self.ui.btn_duplicate_row.clicked.connect(self.duplicate_selected_rows)
        self.ui.btn_edit_row.clicked.connect(self.edit_selected_row)
        self.ui.btn_scan_child.clicked.connect(self.scan_child_structure)
        self.ui.btn_open_child.clicked.connect(self.open_linked_child_structure)
        self.ui.btn_create_child_types.clicked.connect(self.create_child_types)
        self.ui.btn_create_subtree_types.clicked.connect(self.create_type_subtree)

        self.ui.tree_structures.itemSelectionChanged.connect(self.list_selection_changed)
        self.ui.tree_structures.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tree_structures.customContextMenuRequested.connect(
            self.list_context_menu
        )

        self.ui.tbl_structure.cellDoubleClicked.connect(
            self.structure_table_interaction
        )
        self.ui.tbl_structure.itemChanged.connect(self.structure_table_item_changed)
        self.ui.tbl_structure.itemSelectionChanged.connect(self.update_action_states)
        self.ui.tbl_structure.currentCellChanged.connect(
            lambda *_args: self.update_action_states()
        )
        self.ui.tbl_structure.cellClicked.connect(
            lambda *_args: self.update_action_states()
        )
        self.ui.tbl_structure.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tbl_structure.customContextMenuRequested.connect(
            self.structure_table_context_menu
        )

        self.ui.action_enable.triggered.connect(
            lambda: self.structure_table_enable_row(None)
        )
        self.ui.action_duplicate_structure.triggered.connect(self.duplicate_structure)
        self.ui.action_disable.triggered.connect(
            lambda: self.structure_table_disable_row(None)
        )
        self.ui.action_resolve.triggered.connect(self.structure_table_resolve)
        self.ui.action_finalize.triggered.connect(self.structure_table_finalize)
        self.ui.action_edit.triggered.connect(self.edit_selected_row)
        self.ui.action_add_row.triggered.connect(self.add_manual_row)
        self.ui.action_duplicate_row.triggered.connect(self.duplicate_selected_rows)
        self.ui.action_scan_child.triggered.connect(self.scan_child_structure)
        self.ui.action_create_child_types.triggered.connect(self.create_child_types)
        self.ui.action_create_subtree_types.triggered.connect(self.create_type_subtree)

        for action in (
            self.ui.action_enable,
            self.ui.action_disable,
            self.ui.action_resolve,
            self.ui.action_finalize,
            self.ui.action_edit,
            self.ui.action_add_row,
            self.ui.action_duplicate_row,
            self.ui.action_scan_child,
            self.ui.action_create_child_types,
            self.ui.action_create_subtree_types,
        ):
            self.ui.tbl_structure.addAction(action)

    def _configure_table(self) -> None:
        self.ui.tbl_structure.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows
        )
        self.ui.tbl_structure.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection
        )
        self.ui.tbl_structure.setEditTriggers(
            QtWidgets.QAbstractItemView.DoubleClicked
            | QtWidgets.QAbstractItemView.EditKeyPressed
        )
        self.ui.tbl_structure.setAlternatingRowColors(True)
        self.ui.tbl_structure.setSortingEnabled(False)

    def _register_shortcut(
        self,
        parent,
        *,
        text: str,
        shortcut: str,
        slot,
    ) -> QtGui.QAction:
        action = QtGui.QAction(text, parent)
        action.setShortcut(shortcut)
        action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        action.triggered.connect(slot)
        parent.addAction(action)
        self._shortcut_actions.append(action)
        return action

    def _install_shortcuts(self) -> None:
        self._shortcut_actions.clear()

        self._register_shortcut(
            self.ui.tree_structures,
            text="Add Structure",
            shortcut="Insert",
            slot=self.add_structure,
        )
        self._register_shortcut(
            self.ui.tree_structures,
            text="Remove Structure",
            shortcut="Delete",
            slot=self.remove_structure,
        )
        self._register_shortcut(
            self.ui.tree_structures,
            text="Duplicate Structure",
            shortcut="Ctrl+Shift+D",
            slot=self.duplicate_structure,
        )
        self._register_shortcut(
            self.ui.tree_structures,
            text="Rename Structure",
            shortcut="F2",
            slot=self.focus_structure_name,
        )
        self._register_shortcut(
            self.ui,
            text="Focus Structure Filter",
            shortcut="Ctrl+F",
            slot=self.focus_structure_filter,
        )
        self._register_shortcut(
            self.ui.input_filter,
            text="Clear Structure Filter",
            shortcut="Escape",
            slot=self.clear_structure_filter,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Remove Rows",
            shortcut="Delete",
            slot=self.structure_table_remove_rows,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Insert Row Before",
            shortcut="Ctrl+Alt+Up",
            slot=self.add_manual_row_before,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Insert Row After",
            shortcut="Ctrl+Alt+Down",
            slot=self.add_manual_row_after,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Nudge Rows Earlier",
            shortcut="Alt+Up",
            slot=lambda: self.nudge_selected_rows(-1),
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Nudge Rows Later",
            shortcut="Alt+Down",
            slot=lambda: self.nudge_selected_rows(1),
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Bulk Edit Rows",
            shortcut="Ctrl+Shift+E",
            slot=self.edit_selected_row,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Toggle Array Rows",
            shortcut="A",
            slot=self.structure_table_toggle_array,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Set Structure Origin",
            shortcut="O",
            slot=self.structure_table_set_origin,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="View Scanned Uses",
            shortcut="U",
            slot=self.show_scanned_variables,
        )
        self._register_shortcut(
            self.ui.tbl_structure,
            text="Scan Child Structure",
            shortcut="Ctrl+Shift+C",
            slot=self.scan_child_structure,
        )

    def focus_structure_filter(self) -> None:
        self.ui.input_filter.setFocus()
        self.ui.input_filter.selectAll()

    def clear_structure_filter(self) -> None:
        if not self.ui.input_filter.text():
            self.ui.tree_structures.setFocus()
            return
        self.ui.input_filter.clear()
        self.ui.tree_structures.setFocus()

    def focus_structure_name(self) -> None:
        if self.current_structure is None:
            return
        self.ui.input_name.setFocus()
        self.ui.input_name.selectAll()

    @staticmethod
    def _make_table_item(text: str, editable: bool = False) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        flags = Qt.ItemIsSelectable | Qt.ItemIsEnabled
        if editable:
            flags |= Qt.ItemIsEditable
        item.setFlags(flags)
        return item

    def get_selected_rows(self) -> list[int]:
        if self.ui is None:
            return []

        rows = sorted({index.row() for index in self.ui.tbl_structure.selectedIndexes()})
        if rows:
            return rows

        current_row = self.ui.tbl_structure.currentRow()
        return [current_row] if current_row >= 0 else []

    def normalize_rows(self, rows) -> list[int]:
        if rows is None:
            return self.get_selected_rows()
        if isinstance(rows, int):
            return [rows] if rows >= 0 else []
        return sorted({row for row in rows if row >= 0})

    def get_selected_members(self, rows=None) -> list[AbstractMember]:
        if self.current_structure is None:
            return []

        return [
            self.current_structure.members[row]
            for row in self.normalize_rows(rows)
            if 0 <= row < len(self.current_structure.members)
        ]

    def get_selected_member(self) -> AbstractMember | None:
        members = self.get_selected_members()
        return members[0] if members else None

    def _restore_selected_rows(self, selected_rows: set[int]) -> None:
        if self.ui is None:
            return

        table = self.ui.tbl_structure
        table.clearSelection()
        for row in sorted(selected_rows):
            if 0 <= row < table.rowCount():
                table.selectRow(row)
        if selected_rows:
            first_row = next((row for row in sorted(selected_rows) if row < table.rowCount()), -1)
            if first_row >= 0:
                table.setCurrentCell(first_row, Column.offset)

    @staticmethod
    def _format_type_name(member: AbstractMember) -> str:
        return f"{member.type_name} []" if member.is_array else member.type_name

    def _structure_filter_text(self) -> str:
        if self.ui is None:
            return ""
        return self.ui.input_filter.text().strip().lower()

    def _iter_visible_structures(self):
        filter_text = self._structure_filter_text()
        for structure in self.structures.values():
            if not filter_text or filter_text in structure.name.lower():
                yield structure

    def _iter_tree_items(self) -> Iterator[QTreeWidgetItem]:
        if self.ui is None:
            return

        stack = [
            self.ui.tree_structures.topLevelItem(index)
            for index in range(self.ui.tree_structures.topLevelItemCount() - 1, -1, -1)
        ]
        while stack:
            item = stack.pop()
            if item is None:
                continue
            yield item
            for child_index in range(item.childCount() - 1, -1, -1):
                stack.append(item.child(child_index))

    def _tree_item_structure(self, item: QTreeWidgetItem | None) -> Structure | None:
        if item is None:
            return None

        structure = item.data(0, Qt.UserRole)
        return structure if isinstance(structure, Structure) else None

    def _format_structure_tree_label(self, structure: Structure, relationship=None) -> str:
        badges = []
        if relationship is not None:
            badges.append(f"child @ 0x{relationship.parent_member_offset:X}")
        elif structure.parent_relationships:
            badges.append("linked child")
        else:
            badges.append("root")

        if structure.provenance.kind != "manual":
            badges.append(structure.provenance.kind.replace("_", " "))
        if structure.is_auto_named:
            badges.append("auto")
        if structure.created_type_name:
            badges.append("typed")

        return f"{structure.name} [{', '.join(badges)}]"

    def add_structure_item(
        self,
        structure: Structure,
        *,
        parent: QTreeWidgetItem | None = None,
        relationship=None,
    ) -> QTreeWidgetItem:
        if self.ui is None:
            raise RuntimeError("Structure Builder UI has not been created.")

        item = QTreeWidgetItem([self._format_structure_tree_label(structure, relationship)])
        item.setData(0, Qt.UserRole, structure)
        item.setToolTip(0, structure.get_provenance_summary())
        if parent is None:
            self.ui.tree_structures.addTopLevelItem(item)
        else:
            parent.addChild(item)
        return item

    def _build_structure_tree(self) -> None:
        if self.ui is None:
            return

        tree = self.ui.tree_structures
        tree.clear()

        visible_structures = list(self._iter_visible_structures())
        if not visible_structures:
            return

        visible_names = {structure.name for structure in visible_structures}
        visible_order = {
            structure.name: index for index, structure in enumerate(visible_structures)
        }
        added_names: set[str] = set()

        def add_branch(
            structure: Structure,
            *,
            parent: QTreeWidgetItem | None = None,
            relationship=None,
            path: tuple[str, ...] = (),
        ) -> None:
            item = self.add_structure_item(
                structure,
                parent=parent,
                relationship=relationship,
            )
            added_names.add(structure.name)

            # Relationship data is a graph. Duplicate nodes under each visible
            # parent because QTreeWidget cannot share a child item across branches.
            child_relationships = sorted(
                (
                    rel
                    for rel in structure.child_relationships
                    if rel.child_structure_name in visible_names
                ),
                key=lambda rel: visible_order.get(
                    rel.child_structure_name,
                    len(visible_order),
                ),
            )
            for child_relationship in child_relationships:
                child = self.structures.get(child_relationship.child_structure_name)
                if (
                    child is None
                    or child.name == structure.name
                    or child.name in path
                ):
                    continue
                add_branch(
                    child,
                    parent=item,
                    relationship=child_relationship,
                    path=path + (structure.name,),
                )

        roots = [
            structure
            for structure in visible_structures
            if not any(
                relationship.parent_structure_name in visible_names
                for relationship in structure.parent_relationships
            )
        ]
        for structure in roots:
            add_branch(structure)

        for structure in visible_structures:
            if structure.name not in added_names:
                add_branch(structure)

        if hasattr(tree, "expandAll"):
            tree.expandAll()

    def _find_tree_items_for_structure(self, structure_name: str) -> list[QTreeWidgetItem]:
        items = []
        for item in self._iter_tree_items():
            structure = self._tree_item_structure(item)
            if structure is not None and structure.name == structure_name:
                items.append(item)
        return items

    def _select_structure_in_tree(self, structure_name: str) -> bool:
        if self.ui is None or not structure_name:
            return False

        items = self._find_tree_items_for_structure(structure_name)
        if not items:
            return False

        tree = self.ui.tree_structures
        tree.clearSelection()
        tree.setCurrentItem(items[0])
        items[0].setSelected(True)
        if hasattr(tree, "scrollToItem"):
            tree.scrollToItem(items[0])
        return True

    def _current_tree_structure(self) -> Structure | None:
        if self.ui is None:
            return None
        return self._tree_item_structure(self.ui.tree_structures.currentItem())

    def reload_structure_list(self):
        if self.ui is None:
            return

        tree = self.ui.tree_structures
        current_name = self.current_structure.name if self.current_structure else None

        blocker = QSignalBlocker(tree)
        try:
            self._build_structure_tree()
            if current_name and self._select_structure_in_tree(current_name):
                pass
            elif tree.topLevelItemCount() > 0:
                first_item = tree.topLevelItem(0)
                tree.setCurrentItem(first_item)
                first_item.setSelected(True)
        finally:
            del blocker

        selected_structure = self._current_tree_structure()
        self.set_structure(selected_structure.name if selected_structure is not None else "")
        self.update_action_states()

    def set_structure(self, structure_name: str):
        if not structure_name:
            self.current_structure = None
            self.update_structure_fields()
            return

        structure = self.structures.get(structure_name)
        if structure is None:
            self.current_structure = None
            log_warning(f"Structure {structure_name} does not exist!", True)
            self.update_structure_fields()
            return

        self.current_structure = structure
        self.update_structure_fields()

    def add_structure(self):
        name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Enter structure name:")
        self.create_structure(name)

    def _make_unique_structure_name(self, base_name: str) -> str:
        if base_name not in self.structures:
            return base_name

        copy_index = 2
        candidate = f"{base_name} Copy"
        while candidate in self.structures:
            candidate = f"{base_name} Copy {copy_index}"
            copy_index += 1
        return candidate

    def _next_auto_structure_name(self) -> str:
        index = 1
        while True:
            candidate = f"auto_struct_{index:03d}"
            if candidate not in self.structures:
                return candidate
            index += 1

    def _clone_member(self, member: AbstractMember):
        cloned_member = copy.copy(member)
        if hasattr(member, "scanned_variables"):
            cloned_member.scanned_variables = set(member.scanned_variables)
        return cloned_member

    @staticmethod
    def _normalize_member_child_links(structure: Structure) -> None:
        relationship_by_key: dict[tuple[str, int], StructureRelationship] = {
            (relationship.child_structure_name, relationship.parent_member_offset): relationship
            for relationship in structure.child_relationships
        }
        for member in structure.members:
            child_name = getattr(member, "linked_child_structure_name", None)
            if child_name is None:
                continue

            relationship = relationship_by_key.get((child_name, member.offset))
            if relationship is None:
                member.linked_child_structure_name = None
                member.child_relation_kind = None
                continue
            member.child_relation_kind = relationship.relation_kind

    def _copy_duplicate_child_relationships(
        self,
        source: Structure,
        duplicate: Structure,
    ) -> None:
        for relationship in source.child_relationships:
            child_structure_name = (
                duplicate.name
                if relationship.child_structure_name == source.name
                else relationship.child_structure_name
            )
            source_member = source.get_member_by_offset(
                relationship.parent_member_offset
            )
            parent_member_name = (
                source_member.name
                if source_member is not None
                else relationship.parent_member_name
            )
            duplicated_relationship = duplicate.add_child_relationship(
                child_structure_name=child_structure_name,
                parent_member_offset=relationship.parent_member_offset,
                parent_member_name=parent_member_name,
                relation_kind=relationship.relation_kind,
            )
            child = self.structures.get(child_structure_name)
            if child is not None:
                child.add_parent_relationship(duplicated_relationship)

        self._normalize_member_child_links(duplicate)

    def create_structure(self, name: Optional[str]):
        if name is None:
            return None

        clean_name = name.strip()
        is_auto_named = not clean_name
        if is_auto_named:
            clean_name = self._next_auto_structure_name()
        elif clean_name in self.structures:
            log_warning("That structure name already exists!", True)
            return None

        structure = Structure(clean_name)
        structure.is_auto_named = is_auto_named
        self.structures[structure.name] = structure

        if self.ui is None:
            self.current_structure = structure
        else:
            self.ui.input_filter.clear()
            self.reload_structure_list()
            if not self._select_structure_in_tree(structure.name):
                self.current_structure = structure
                self.update_structure_fields()

        self.update_action_states()
        return structure

    def prompt_create_structure(self):
        name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Enter structure name:")
        return self.create_structure(name)

    def duplicate_structure(self):
        if self.current_structure is None:
            return

        source_structure = self.current_structure
        new_name = self._make_unique_structure_name(source_structure.name)
        cloned_structure = Structure(new_name)
        cloned_structure.main_offset = source_structure.main_offset
        cloned_structure.members = [
            self._clone_member(member) for member in source_structure.members
        ]
        cloned_structure.provenance = source_structure.clone_provenance()
        cloned_structure.is_auto_named = True
        self.structures[new_name] = cloned_structure
        self._copy_duplicate_child_relationships(source_structure, cloned_structure)
        cloned_structure.refresh_collisions()

        if self.ui is not None:
            self.ui.input_filter.clear()
            self.reload_structure_list()
            if not self._select_structure_in_tree(new_name):
                self.current_structure = cloned_structure
                self.update_structure_fields()
        else:
            self.current_structure = cloned_structure

        self.update_action_states()

    def remove_structure(self):
        if self.ui is None:
            return

        structure = self._current_tree_structure()
        if structure is None:
            log_warning("No structure selected!", True)
            return

        structure_name = structure.name
        del self.structures[structure_name]
        for other_structure in self.structures.values():
            other_structure.remove_relationships_with(structure_name)

        self.reload_structure_list()
        self.update_action_states()

    def list_context_menu(self, point):
        if self.ui is None:
            return

        tree = self.ui.tree_structures
        item = tree.itemAt(point)
        if item is not None and item is not tree.currentItem():
            tree.clearSelection()
            tree.setCurrentItem(item)
            item.setSelected(True)

        menu = QMenu()
        menu.addAction("Add Structure", self.add_structure)
        menu.addAction("Focus Filter", self.focus_structure_filter)

        if item is not None:
            menu.addAction("Duplicate Structure", self.duplicate_structure)
            menu.addAction("Rename Structure", self.focus_structure_name)
            menu.addAction("Remove Structure", self.remove_structure)

        qt_exec(menu, tree.viewport().mapToGlobal(point))

    def list_selection_changed(self):
        structure = self._current_tree_structure()
        self.set_structure(structure.name if structure is not None else "")

    def _warn_unimplemented(self, action_name: str) -> None:
        log_warning(f"{action_name} is not implemented yet.", True)

    @staticmethod
    def _prepare_scan_cfunc(func_ea: int):
        try:
            cfunc = decompile(func_ea)
        except ida_hexrays.DecompilationFailure:
            log_warning(f"Failed to decompile function at {hex(func_ea)}", True)
            return None
        if cfunc is None:
            log_warning(f"Failed to decompile function at {hex(func_ea)}", True)
            return None

        from forge.api.visitor import refresh_function_tree_postorder

        return refresh_function_tree_postorder(cfunc) or cfunc




    def _build_child_scan_plan(
        self,
        member: AbstractMember | None,
        *,
        show_warnings: bool = False,
    ) -> ChildScanPlan | None:
        if self.current_structure is None or member is None:
            return None

        def warn(message: str) -> None:
            if show_warnings:
                log_warning(message, True)

        scanned_variables = sorted(
            getattr(member, "scanned_variables", set()),
            key=lambda scan_variable: (
                getattr(scan_variable, "func_ea", idaapi.BADADDR),
                getattr(scan_variable, "ea", idaapi.BADADDR),
                str(getattr(scan_variable, "name", "")),
            ),
        )
        if not scanned_variables:
            warn("The selected row does not have scan evidence for child scanning yet.")
            return None

        tinfo = getattr(member, "tinfo", None)
        if tinfo is None:
            warn("The selected row does not have enough type information to scan a child structure.")
            return None

        try:
            legal_type = is_legal_type(tinfo)
        except Exception:
            legal_type = False
        if not legal_type:
            warn("The selected row uses a type that cannot be scanned as a child structure.")
            return None

        if hasattr(tinfo, "is_ptr") and tinfo.is_ptr():
            relation_kind = "pointer"
            scan_object = StructurePointerObject(
                self.current_structure.created_type_name or self.current_structure.name,
                member.offset,
            )
        else:
            relation_kind = "embedded"
            scan_object = StructureReferenceObject(
                self.current_structure.created_type_name or self.current_structure.name,
                member.offset,
            )


        parent_struct_name = self.current_structure.created_type_name or self.current_structure.name
        if not parent_struct_name:
            parent_struct_names = sorted(
                {
                    candidate
                    for candidate in (
                        getattr(scan_variable, "_name", None)
                        for scan_variable in scanned_variables
                    )
                    if isinstance(candidate, str) and candidate
                }
            )
            if len(parent_struct_names) != 1:
                warn(
                    "Child scan currently requires a typed parent structure or unambiguous member evidence.",
                )
                return None
            parent_struct_name = parent_struct_names[0]
            scan_object = type(scan_object)(parent_struct_name, member.offset)




        function_eas = tuple(
            sorted(
                {
                    getattr(scan_variable, "func_ea", idaapi.BADADDR)
                    for scan_variable in scanned_variables
                    if getattr(scan_variable, "func_ea", idaapi.BADADDR) != idaapi.BADADDR
                }
            )
        )
        if not function_eas:
            warn("The selected row does not have any decompilable function evidence for child scanning.")
            return None

        scan_object.name = member.name
        scan_object.tinfo = tinfo
        representative = scanned_variables[0]
        expression_eas = {
            getattr(scan_variable, "ea", idaapi.BADADDR)
            for scan_variable in scanned_variables
            if getattr(scan_variable, "ea", idaapi.BADADDR) != idaapi.BADADDR
        }
        member_name = member.name or f"member_{member.offset:X}"
        root_object_ea = getattr(representative, "ea", idaapi.BADADDR)
        root_function_ea = getattr(representative, "func_ea", idaapi.BADADDR)
        return ChildScanPlan(
            scan_object=scan_object,
            function_eas=function_eas,
            relation_kind=relation_kind,
            root_object_name=f"{self.current_structure.name}.{member_name}",
            root_object_ea=root_object_ea if root_object_ea != idaapi.BADADDR else None,
            root_function_ea=(
                root_function_ea if root_function_ea != idaapi.BADADDR else None
            ),
            has_multiple_roots=len(function_eas) > 1 or len(expression_eas) > 1,
        )

    def _create_or_get_child_structure(
        self,
        member: AbstractMember,
    ) -> tuple[Structure | None, bool]:
        linked_child_name = getattr(member, "linked_child_structure_name", None)
        if linked_child_name:
            existing_child = self.structures.get(linked_child_name)
            if existing_child is not None:
                return existing_child, False
            return self.create_structure(linked_child_name), True
        return self.create_structure(""), True

    def _execute_child_scan_plan(
        self,
        child_structure: Structure,
        plan: ChildScanPlan,
    ) -> bool:
        scanned_any = False
        for func_ea in plan.function_eas:
            cfunc = self._prepare_scan_cfunc(func_ea)
            if cfunc is None:
                continue
            visitor = NewDeepScanVisitor(
                cfunc,
                child_structure.main_offset,
                plan.scan_object,
                child_structure,
                recurse_calls=True,
            )

            visitor.process()
            scanned_any = True
        return scanned_any

    @staticmethod
    def _materialize_child_member_type(
        member: AbstractMember,
        child_structure: Structure,
        relation_kind: str,
    ) -> None:
        child_type_name = child_structure.created_type_name or child_structure.name
        type_decl = f"{child_type_name} *" if relation_kind == "pointer" else child_type_name
        tinfo = parse_user_tinfo(type_decl)
        if tinfo is None:
            return

        member.tinfo = tinfo
        member.is_array = False
        if hasattr(member, "invalidate_score"):
            member.invalidate_score()

    @staticmethod
    def _materialize_child_member_type(
        member: AbstractMember,
        child_structure: Structure,
        relation_kind: str,
    ) -> None:
        child_type_name = child_structure.created_type_name or child_structure.name
        type_decl = f"{child_type_name} *" if relation_kind == "pointer" else child_type_name
        tinfo = parse_user_tinfo(type_decl)
        if tinfo is None:
            return
        member.tinfo = tinfo
        member.is_array = False
        if hasattr(member, "invalidate_score"):
            member.invalidate_score()

    @staticmethod
    def _child_scan_origin(member: AbstractMember) -> int:
        return getattr(member, "origin", 0) + member.offset

    @staticmethod
    def _link_child_structure(
        parent_structure: Structure,
        child_structure: Structure,
        member: AbstractMember,
        relation_kind: str,
    ) -> None:
        parent_member_name = member.name or f"member_{member.offset:X}"
        relationship = parent_structure.add_child_relationship(
            child_structure_name=child_structure.name,
            parent_member_offset=member.offset,
            parent_member_name=parent_member_name,
            relation_kind=relation_kind,
        )
        child_structure.add_parent_relationship(relationship)
        member.linked_child_structure_name = child_structure.name
        member.child_relation_kind = relation_kind
        StructureBuilderForm._materialize_child_member_type(member, child_structure, relation_kind)

        child_structure.add_parent_relationship(relationship)
        member.linked_child_structure_name = child_structure.name
        member.child_relation_kind = relation_kind
        StructureBuilderForm._materialize_child_member_type(member, child_structure, relation_kind)

    @staticmethod
    def _set_child_scan_provenance(
        child_structure: Structure,
        member: AbstractMember,
        plan: ChildScanPlan,
    ) -> None:
        child_structure.set_provenance(
            kind="child_scan",
            root_object_name=plan.root_object_name,
            root_object_ea=plan.root_object_ea,
            root_function_ea=plan.root_function_ea,
            source_member_offset=member.offset,
            has_multiple_roots=plan.has_multiple_roots,
        )

    def scan_child_structure(self):
        if self.current_structure is None:
            log_warning("No structure selected!", True)
            return

        selected_member = self.get_selected_member()
        if selected_member is None:
            log_warning("No structure row selected!", True)
            return

        parent_structure = self.current_structure
        plan = self._build_child_scan_plan(selected_member, show_warnings=True)
        if plan is None:
            return

        child_structure, created_now = self._create_or_get_child_structure(selected_member)
        if child_structure is None:
            return

        child_origin = self._child_scan_origin(selected_member)
        if child_structure.main_offset != child_origin:
            child_structure.set_main_offset(child_origin)

        existing_member_count = len(child_structure.members)
        scanned_any = self._execute_child_scan_plan(child_structure, plan)

        scan_produced_results = len(child_structure.members) > existing_member_count
        if not scanned_any or (created_now and not scan_produced_results):
            if created_now and child_structure.name in self.structures:
                del self.structures[child_structure.name]
            self.current_structure = parent_structure
            if self.ui is not None:
                self.reload_structure_list()
                self._select_structure_in_tree(parent_structure.name)
            self.update_action_states()
            log_warning(
                "Unable to derive child structure scan results from the selected row.",
                True,
            )
            return

        self._link_child_structure(
            parent_structure,
            child_structure,
            selected_member,
            plan.relation_kind,
        )
        if created_now or (
            child_structure.provenance.kind == "manual" and existing_member_count == 0
        ):
            self._set_child_scan_provenance(
                child_structure,
                selected_member,
                plan,
            )

        self.current_structure = child_structure
        if self.ui is not None:
            self.reload_structure_list()
            if self._select_structure_in_tree(child_structure.name):
                self.ui.tree_structures.setFocus()
        self.update_action_states()

    def open_linked_child_structure(self):
        if self.ui is None:
            return

        selected_member = self.get_selected_member()
        if selected_member is None:
            log_warning("No structure row selected!", True)
            return

        child_name = getattr(selected_member, "linked_child_structure_name", None)
        if not child_name:
            log_warning("The selected row is not linked to a child structure.", True)
            return
        if child_name not in self.structures:
            log_warning(f"Linked child structure {child_name} does not exist.", True)
            return

        self.ui.input_filter.clear()
        self.reload_structure_list()
        if self._select_structure_in_tree(child_name):
            self.ui.tree_structures.setFocus()
            return
        self.set_structure(child_name)

    def create_child_types(self):
        if self.current_structure is None:
            return

        if not self.current_structure.child_relationships:
            log_warning("Current structure has no child relationships.", True)
            return

        created_child_names: set[str] = set()
        for relationship in sorted(
            self.current_structure.child_relationships,
            key=lambda rel: (
                rel.parent_member_offset,
                rel.parent_member_name,
                rel.child_structure_name,
            ),
        ):
            child_name = relationship.child_structure_name
            if child_name in created_child_names:
                continue
            created_child_names.add(child_name)

            child_structure = self.structures.get(child_name)
            if child_structure is None:
                log_warning(f"Linked child structure {child_name} does not exist.", True)
                continue

            child_structure.create_type_if_ready(self.structures)

        self.update_structure_fields()

    def create_type_subtree(self):
        if self.current_structure is None:
            return

        self.current_structure.create_subtree_types_postorder(self.structures)
        self.update_structure_fields()

    def update_structure_fields(self):
        if self.ui is None:
            return

        selected_rows = set(self.get_selected_rows())
        scroll_value = self.ui.tbl_structure.verticalScrollBar().value()

        blocker = QSignalBlocker(self.ui.tbl_structure)
        try:
            if self.current_structure is None:
                self.ui.tbl_structure.setRowCount(0)
                self.ui.tbl_structure.setDisabled(True)
                self.ui.input_name.setText("")
            else:
                self.current_structure.refresh_collisions()
                self.ui.tbl_structure.setEnabled(True)
                self.ui.input_name.setText(self.current_structure.name)
                self.ui.tbl_structure.setRowCount(len(self.current_structure.members))

                for row, member in enumerate(self.current_structure.members):
                    self.ui.tbl_structure.setItem(
                        row,
                        Column.offset,
                        self._make_table_item(
                            f"0x{member.offset:04X} [{hex(member.size)}]"
                        ),
                    )
                    self.ui.tbl_structure.setItem(
                        row,
                        Column.type,
                        self._make_table_item(self._format_type_name(member)),
                    )
                    self.ui.tbl_structure.setItem(
                        row,
                        Column.name,
                        self._make_table_item(member.name, editable=True),
                    )
                    self.ui.tbl_structure.setItem(
                        row,
                        Column.score,
                        self._make_table_item(str(member.score)),
                    )
                    self.ui.tbl_structure.setItem(
                        row,
                        Column.comment,
                        self._make_table_item(member.comment, editable=True),
                    )

                    if self.current_structure.main_offset == member.offset:
                        self.ui.tbl_structure.item(row, Column.offset).setBackground(
                            QColor(config["form"]["origin_color"])
                        )

                    if not member.enabled:
                        set_row_background_color(
                            self.ui.tbl_structure,
                            row,
                            QColor(config["form"]["disabled_color"]),
                        )
                    elif self.current_structure.has_collision(row):
                        set_row_background_color(
                            self.ui.tbl_structure,
                            row,
                            QColor(config["form"]["collision_background_color"]),
                        )
                        set_row_foreground_color(
                            self.ui.tbl_structure,
                            row,
                            QColor(config["form"]["collision_foreground_color"]),
                        )
        finally:
            del blocker

        self._restore_selected_rows(selected_rows)
        self.ui.tbl_structure.verticalScrollBar().setValue(scroll_value)
        self.update_action_states()

    def update_action_states(self):
        if self.ui is None:
            return

        has_structure = self.current_structure is not None
        has_members = has_structure and bool(self.current_structure.members)
        has_selection = bool(self.get_selected_rows())
        selected_member = self.get_selected_member()
        linked_child_name = (
            getattr(selected_member, "linked_child_structure_name", None)
            if selected_member is not None
            else None
)
        can_open_linked_child = bool(
            linked_child_name and linked_child_name in self.structures
        )
        has_child_relationships = has_structure and bool(
            self.current_structure.child_relationships
        )

        self.ui.btn_remove.setEnabled(has_structure)
        self.ui.btn_duplicate_structure.setEnabled(has_structure)
        self.ui.btn_apply_name.setEnabled(has_structure)
        self.ui.input_name.setEnabled(has_structure)
        self.ui.input_filter.setEnabled(bool(self.structures))
        self.ui.tbl_structure.setEnabled(has_structure)

        self.ui.btn_auto_resolve.setEnabled(has_members)
        self.ui.btn_create_type.setEnabled(has_members)
        self.ui.btn_enable_rows.setEnabled(has_selection)
        self.ui.btn_disable_rows.setEnabled(has_selection)
        self.ui.btn_toggle_array.setEnabled(has_selection)
        self.ui.btn_set_origin.setEnabled(has_selection)
        self.ui.btn_remove_rows.setEnabled(has_selection)
        self.ui.btn_clear_rows.setEnabled(has_members)
        self.ui.btn_view_scanned_uses.setEnabled(has_members)
        self.ui.btn_recognize_vtable.setEnabled(isinstance(selected_member, VirtualTable))
        self.ui.btn_add_row.setEnabled(has_structure)
        self.ui.btn_duplicate_row.setEnabled(has_selection)
        self.ui.btn_edit_row.setEnabled(has_selection)

        can_scan_child = self._build_child_scan_plan(selected_member) is not None

        self.ui.btn_scan_child.setEnabled(can_scan_child)
        self.ui.btn_open_child.setEnabled(can_open_linked_child)
        self.ui.btn_create_child_types.setEnabled(has_child_relationships)
        self.ui.btn_create_subtree_types.setEnabled(has_child_relationships)

        self.ui.action_enable.setEnabled(has_selection)
        self.ui.action_disable.setEnabled(has_selection)
        self.ui.action_resolve.setEnabled(has_members)
        self.ui.action_finalize.setEnabled(has_members)
        self.ui.action_edit.setEnabled(has_selection)
        self.ui.action_add_row.setEnabled(has_structure)
        self.ui.action_duplicate_row.setEnabled(has_selection)
        self.ui.action_scan_child.setEnabled(can_scan_child)
        self.ui.action_create_child_types.setEnabled(has_child_relationships)
        self.ui.action_create_subtree_types.setEnabled(has_child_relationships)

        selection_count = len(self.get_selected_rows())
        self.ui.btn_edit_row.setText(
            "Edit Rows" if selection_count > 1 else "Edit Row"
        )
        self.ui.btn_duplicate_row.setText(
            "Duplicate Rows" if selection_count > 1 else "Duplicate Row"
        )

        self._update_summary_label()
        self._update_inspector_panel()

    def _update_summary_label(self) -> None:
        if self.current_structure is None:
            self.ui.lbl_summary.setText("No structure selected.")
            return

        stats = self.current_structure.get_stats()
        selection_count = len(self.get_selected_rows())
        self.ui.lbl_summary.setText(
            "Members: "
            f"{stats.total_members} | Enabled: {stats.enabled_members} | "
            f"Collisions: {stats.collision_count} | Uses: {stats.scanned_variable_count} | "
            f"Origin: 0x{stats.origin_offset:X} | Selected: {selection_count}"
        )

    def _update_inspector_panel(self) -> None:
        if self.current_structure is None:
            self.ui.lbl_provenance.setText("Provenance: -")
            self.ui.lbl_root_info.setText("Root: -")
            self.ui.lbl_parent_links.setText("Parents: -")
            self.ui.lbl_child_links.setText("Children: -")
            self.ui.lbl_selected_member_info.setText("Selected Row: -")
            self.ui.lbl_type_status.setText("Type Status: -")
            return

        selected_member = self.get_selected_member()
        self.ui.lbl_provenance.setText(
            f"Provenance: {self._format_structure_provenance(self.current_structure)}"
        )
        self.ui.lbl_root_info.setText(
            f"Root: {self._format_root_info(self.current_structure)}"
        )
        self.ui.lbl_parent_links.setText(
            "Parents: "
            f"{self._format_relationships(self.current_structure.parent_relationships, direction='parent')}"
        )
        self.ui.lbl_child_links.setText(
            "Children: "
            f"{self._format_relationships(self.current_structure.child_relationships, direction='child')}"
        )
        self.ui.lbl_selected_member_info.setText(
            f"Selected Row: {self._format_selected_member_info(selected_member)}"
        )
        self.ui.lbl_type_status.setText(
            f"Type Status: {self._format_type_status(self.current_structure)}"
        )

    def _format_structure_provenance(self, structure: Structure) -> str:
        summary = structure.get_provenance_summary()
        if structure.is_auto_named:
            return f"{summary} | auto-named"
        return summary

    def _format_root_info(self, structure: Structure) -> str:
        provenance = structure.provenance
        parts = [f"origin 0x{structure.main_offset:X}"]
        if provenance.root_object_name:
            parts.insert(0, provenance.root_object_name)
        if provenance.root_object_ea is not None:
            parts.append(f"ea 0x{provenance.root_object_ea:X}")
        if provenance.root_function_ea is not None:
            parts.append(f"func 0x{provenance.root_function_ea:X}")
        if provenance.source_member_offset is not None:
            parts.append(f"from 0x{provenance.source_member_offset:X}")
        return " | ".join(parts)

    def _format_relationships(self, relationships, *, direction: str) -> str:
        if not relationships:
            return "-"

        labels = set()
        for relationship in relationships:
            target_name = (
                relationship.parent_structure_name
                if direction == "parent"
                else relationship.child_structure_name
            )
            member_suffix = (
                f" ({relationship.parent_member_name})"
                if relationship.parent_member_name
                else ""
            )
            labels.add(
                f"{target_name} @ 0x{relationship.parent_member_offset:X}{member_suffix}"
            )
        return "; ".join(sorted(labels))

    def _format_selected_member_info(self, member: AbstractMember | None) -> str:
        if member is None:
            return "-"

        parts = [
            f"0x{member.offset:X}",
            member.name or "<unnamed>",
            self._format_type_name(member),
        ]
        if not member.enabled:
            parts.append("disabled")

        child_name = getattr(member, "linked_child_structure_name", None)
        if child_name:
            child_label = f"child -> {child_name}"
            relation_kind = getattr(member, "child_relation_kind", None)
            if relation_kind:
                child_label += f" ({relation_kind})"
            if child_name not in self.structures:
                child_label += " [missing]"
            parts.append(child_label)

        scanned_variables = getattr(member, "scanned_variables", None)
        if scanned_variables:
            parts.append(f"uses {len(scanned_variables)}")

        if self._build_child_scan_plan(member) is not None:
            parts.append("child scan ready")

        return " | ".join(parts)


    def _format_type_status(self, structure: Structure) -> str:
        status = (
            f"created as {structure.created_type_name}"
            if structure.created_type_name
            else "not created"
        )
        unresolved_children = structure.get_unresolved_child_names(self.structures)
        if unresolved_children:
            child_names = ", ".join(unresolved_children)
            return f"{status} | unresolved children: {child_names}"
        if structure.child_relationships:
            return f"{status} | child links ready"
        return status

    def _default_editor_values(self, member: AbstractMember | None = None) -> MemberEditorValues:
        if member is None:
            selected_member = self.get_selected_member()
            default_offset = (
                selected_member.offset + selected_member.size
                if selected_member is not None
                else self.current_structure.main_offset if self.current_structure else 0
            )
            default_type_name = (
                selected_member.type_name
                if selected_member is not None
                else "u8"
            )
            return MemberEditorValues(
                offset=default_offset,
                type_name=default_type_name,
                name="",
                comment="",
                enabled=True,
                is_array=False,
            )

        return MemberEditorValues(
            offset=member.offset,
            type_name=member.type_name,
            name=member.name,
            comment=member.comment,
            enabled=member.enabled,
            is_array=member.is_array,
        )

    def _show_member_editor(
        self,
        *,
        title: str,
        member: AbstractMember | None = None,
        values: MemberEditorValues | None = None,
    ) -> MemberEditorValues | None:
        dialog = MemberEditorDialog(
            self.ui,
            title=title,
            values=values if values is not None else self._default_editor_values(member),
        )
        if qt_exec(dialog) != QtWidgets.QDialog.Accepted:
            return None
        return dialog.get_values()

    def _show_bulk_member_editor(self) -> dict | None:
        dialog = BulkMemberEditorDialog(
            self.ui,
            selection_count=len(self.get_selected_rows()),
        )
        if qt_exec(dialog) != QtWidgets.QDialog.Accepted:
            return None
        return dialog.get_values()

    @staticmethod
    def _parse_member_tinfo(type_name: str):
        tinfo = parse_user_tinfo(type_name)
        if tinfo is None:
            log_warning(f"Failed to parse type declaration: {type_name}", True)
        return tinfo

    def _select_member(self, member: AbstractMember) -> None:
        if self.ui is None or self.current_structure is None:
            return

        try:
            row = self.current_structure.members.index(member)
        except ValueError:
            return
        self.ui.tbl_structure.selectRow(row)
        self.ui.tbl_structure.setCurrentCell(row, Column.offset)

    def _default_insert_values(
        self,
        *,
        member: AbstractMember,
        offset: int,
    ) -> MemberEditorValues:
        return MemberEditorValues(
            offset=offset,
            type_name=member.type_name,
            name="",
            comment=member.comment,
            enabled=member.enabled,
            is_array=member.is_array,
        )

    def add_manual_row(self):
        if self.current_structure is None:
            return

        values = self._show_member_editor(title="Add Structure Row")
        if values is None:
            return

        self._add_member_from_values(values)

    def add_manual_row_before(self):
        member = self.get_selected_member()
        if member is None:
            self.add_manual_row()
            return

        values = self._show_member_editor(
            title="Insert Structure Row Before",
            values=self._default_insert_values(member=member, offset=member.offset),
        )
        if values is None:
            return

        self._add_member_from_values(values)

    def add_manual_row_after(self):
        member = self.get_selected_member()
        if member is None:
            self.add_manual_row()
            return

        values = self._show_member_editor(
            title="Insert Structure Row After",
            values=self._default_insert_values(
                member=member,
                offset=member.offset + member.size,
            ),
        )
        if values is None:
            return

        self._add_member_from_values(values)

    def _add_member_from_values(self, values: MemberEditorValues) -> None:
        if self.current_structure is None:
            return

        tinfo = self._parse_member_tinfo(values.type_name)
        if tinfo is None:
            return

        member = Member(
            values.offset,
            tinfo,
            scanned_variable=None,
            origin=self.current_structure.main_offset,
        )
        member.name = values.name or member.name
        member.comment = values.comment
        member.set_enabled(values.enabled)
        member.is_array = values.is_array
        self.current_structure.add_member(member)
        self.update_structure_fields()
        self._select_member(member)

    def duplicate_selected_rows(self):
        if self.current_structure is None:
            return

        selected_members = sorted(
            self.get_selected_members(), key=lambda member: member.offset
        )
        if not selected_members:
            return

        base_offset = min(member.offset for member in selected_members)
        insert_offset = max(member.offset + member.size for member in selected_members)
        created_members = []

        for member in selected_members:
            tinfo = self._parse_member_tinfo(member.type_name)
            if tinfo is None:
                return

            new_member = Member(
                insert_offset + (member.offset - base_offset),
                tinfo,
                scanned_variable=None,
                origin=self.current_structure.main_offset,
            )
            new_member.name = member.name
            new_member.comment = member.comment
            new_member.set_enabled(member.enabled)
            new_member.is_array = member.is_array
            self.current_structure.add_member(new_member)
            created_members.append(new_member)

        self.update_structure_fields()
        if self.ui is not None:
            self.ui.tbl_structure.clearSelection()
            for member in created_members:
                self._select_member(member)

    def nudge_selected_rows(self, delta: int) -> None:
        if self.current_structure is None:
            return

        members = self.get_selected_members()
        if not members:
            return

        if any(member.offset + delta < 0 for member in members):
            log_warning("Cannot move rows to a negative offset.", True)
            return

        for member in members:
            old_offset = member.offset
            member.offset += delta
            member.invalidate_score()
            if self.current_structure.main_offset == old_offset:
                self.current_structure.set_main_offset(member.offset)

        self.current_structure.members.sort()
        self.current_structure.refresh_collisions()
        self.update_structure_fields()
        if self.ui is not None:
            self.ui.tbl_structure.clearSelection()
            for member in members:
                self._select_member(member)

    def edit_selected_row(self):
        if self.current_structure is None:
            return

        selected_members = self.get_selected_members()
        if not selected_members:
            return

        if len(selected_members) > 1:
            self.edit_selected_rows_bulk(selected_members)
            return

        member = selected_members[0]
        values = self._show_member_editor(title="Edit Structure Row", member=member)
        if values is None:
            return

        tinfo = self._parse_member_tinfo(values.type_name)
        if tinfo is None:
            return

        old_offset = member.offset
        member.offset = values.offset
        member.tinfo = tinfo
        member.name = values.name or member.name
        member.comment = values.comment
        member.enabled = values.enabled
        member.is_array = values.is_array
        member.invalidate_score()

        if self.current_structure.main_offset == old_offset:
            self.current_structure.set_main_offset(values.offset)

        self.current_structure.members.sort()
        self.current_structure.refresh_collisions()
        self.update_structure_fields()
        self._select_member(member)

    def edit_selected_rows_bulk(self, members: list[AbstractMember]) -> None:
        if self.current_structure is None:
            return

        values = self._show_bulk_member_editor()
        if values is None:
            return

        tinfo = None
        if values["type_name"]:
            tinfo = self._parse_member_tinfo(values["type_name"])
            if tinfo is None:
                return

        edited_members = []
        for member in members:
            old_offset = member.offset
            member.offset += values["offset_delta"]
            if tinfo is not None:
                member.tinfo = tinfo
            if values["comment"]:
                member.comment = values["comment"]
            if values["name_prefix"]:
                member.name = f'{values["name_prefix"]}{member.name}'

            enabled_mode = values["enabled_mode"]
            if enabled_mode == "Enable":
                member.set_enabled(True)
            elif enabled_mode == "Disable":
                member.set_enabled(False)

            array_mode = values["array_mode"]
            if array_mode == "Enable array":
                member.is_array = True
            elif array_mode == "Disable array":
                member.is_array = False
            elif array_mode == "Toggle array":
                member.switch_array_flag()

            member.invalidate_score()
            if self.current_structure.main_offset == old_offset:
                self.current_structure.set_main_offset(member.offset)
            edited_members.append(member)

        self.current_structure.members.sort()
        self.current_structure.refresh_collisions()
        self.update_structure_fields()
        if self.ui is not None:
            self.ui.tbl_structure.clearSelection()
            for member in edited_members:
                self._select_member(member)

    def structure_renamed(self):
        if self.current_structure is None:
            return

        name = self.ui.input_name.text().strip()
        old_name = self.current_structure.name
        if not name or name == old_name:
            return
        if name in self.structures:
            log_warning("That structure name already exists!", True)
            return

        if not self.current_structure.rename_created_type(old_name, name):
            return

        self.structures[name] = self.current_structure
        del self.structures[old_name]
        self.current_structure.name = name
        self.current_structure.is_auto_named = False
        for structure in self.structures.values():
            structure.rename_relationship_references(old_name, name)

        self.ui.input_filter.clear()
        self.reload_structure_list()
        if not self._select_structure_in_tree(name):
            self.set_structure(name)

    def structure_table_interaction(self, row, _column):
        if self.current_structure is None:
            return

        self.ui.tbl_structure.selectRow(row)
        self.edit_selected_row()

    def structure_table_item_changed(self, item):
        if self.current_structure is None:
            return

        row = item.row()
        if not (0 <= row < len(self.current_structure.members)):
            return

        member = self.current_structure.members[row]
        if item.column() == Column.name:
            member.name = item.text().strip() or member.name
        elif item.column() == Column.comment:
            member.comment = item.text().strip()
        else:
            return

        member.invalidate_score()
        self.update_action_states()

    def structure_table_enable_row(self, row):
        if self.current_structure is None:
            return

        rows = self.normalize_rows(row)
        if not rows:
            return

        self.current_structure.enable_members(rows)
        self.update_structure_fields()

    def structure_table_disable_row(self, row):
        if self.current_structure is None:
            return

        rows = self.normalize_rows(row)
        if not rows:
            return

        self.current_structure.disable_members(rows)
        self.update_structure_fields()

    def structure_table_toggle_array(self):
        members = self.get_selected_members()
        if not members:
            return

        for member in members:
            member.switch_array_flag()
        self.update_structure_fields()

    def structure_table_set_origin(self):
        if self.current_structure is None:
            return

        member = self.get_selected_member()
        if member is None:
            return

        self.current_structure.set_main_offset(member.offset)
        self.update_structure_fields()

    def structure_table_remove_rows(self):
        if self.current_structure is None:
            return

        rows = self.get_selected_rows()
        if not rows:
            return

        self.current_structure.remove_members(rows)
        self.update_structure_fields()

    def structure_table_clear(self):
        if self.current_structure is None or not self.current_structure.members:
            return

        reply = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            "HIDECANCEL\nClear all scanned members from the current structure?",
        )
        if reply != ida_kernwin.ASKBTN_YES:
            return

        self.current_structure.clear_members()
        self.update_structure_fields()

    @staticmethod
    def _structure_table_debug_fields(member: AbstractMember) -> list[str]:
        return [
            f"0x{member.offset:04X} [{hex(member.size)}]",
            StructureBuilderForm._format_type_name(member),
            member.name,
            str(member.score),
            member.comment,
            "yes" if member.enabled else "no",
            "yes" if member.is_array else "no",
            f"0x{member.origin:X}",
        ]

    @staticmethod
    def _scan_object_decompiled_line(
        scan_object: ScanObject,
        cfunc_cache: dict[int, ida_hexrays.cfunc_t | None],
        *,
        root: bool = False,
    ) -> str:
        func_ea = (
            getattr(scan_object, "scan_root_function_ea", idaapi.BADADDR)
            if root
            else getattr(scan_object, "func_ea", idaapi.BADADDR)
        )
        if func_ea == idaapi.BADADDR:
            return ""

        cfunc = cfunc_cache.get(func_ea)
        if func_ea not in cfunc_cache:
            cfunc = decompile(func_ea)
            cfunc_cache[func_ea] = cfunc

        if cfunc is None:
            return ""

        target_ea = (
            getattr(scan_object, "scan_root_ea", idaapi.BADADDR)
            if root
            else getattr(scan_object, "ea", idaapi.BADADDR)
        )
        if target_ea == idaapi.BADADDR:
            return ""

        for item in getattr(cfunc, "treeitems", []):
            if getattr(item, "ea", idaapi.BADADDR) != target_ea:
                continue
            try:
                line_no, _column = cfunc.find_item_coords(item)
            except Exception:
                return ""

            pseudocode = cfunc.get_pseudocode()
            tag_remove = getattr(ida_lines, "tag_remove", lambda value: value)
            if 1 <= line_no <= len(pseudocode):
                return " ".join(tag_remove(str(pseudocode[line_no - 1])).split())
            return ""

        return ""

    @staticmethod
    def _scan_object_location_label(scan_object: ScanObject, *, root: bool = False) -> str:
        func_ea = (
            getattr(scan_object, "scan_root_function_ea", idaapi.BADADDR)
            if root
            else getattr(scan_object, "func_ea", idaapi.BADADDR)
        )
        target_ea = (
            getattr(scan_object, "scan_root_ea", idaapi.BADADDR)
            if root
            else getattr(scan_object, "ea", idaapi.BADADDR)
        )
        function_name = (
            getattr(scan_object, "scan_root_function_name", None)
            if root
            else getattr(scan_object, "function_name", "")
        )
        if func_ea == idaapi.BADADDR or target_ea == idaapi.BADADDR:
            return function_name or ""
        return f"{function_name}@{hex(target_ea)}"


    def _build_structure_table_debug_csv(self) -> str:
        if self.current_structure is None:
            return ""

        members = self.get_selected_members() or list(self.current_structure.members)
        if not members:
            return ""

        cfunc_cache: dict[int, ida_hexrays.cfunc_t | None] = {}
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
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
        )


        for row, member in enumerate(members):
            scanned_variables = sorted(
                getattr(member, "scanned_variables", set()),
                key=lambda scan_object: (
                    getattr(scan_object, "func_ea", idaapi.BADADDR),
                    getattr(scan_object, "ea", idaapi.BADADDR),
                    scan_object.name,
                ),
            )
            scan_locations = []
            scan_lines = []
            scan_root_locations = []
            scan_root_lines = []
            for scan_object in scanned_variables:
                scan_locations.append(self._scan_object_location_label(scan_object))
                scan_lines.append(self._scan_object_decompiled_line(scan_object, cfunc_cache))
                scan_root_locations.append(
                    self._scan_object_location_label(scan_object, root=True)
                )
                scan_root_lines.append(
                    self._scan_object_decompiled_line(scan_object, cfunc_cache, root=True)
                )

            writer.writerow(
                [
                    self.current_structure.name,
                    row,
                    *self._structure_table_debug_fields(member),
                    len(scanned_variables),
                    "; ".join(scan_locations),
                    " || ".join(filter(None, scan_lines)),
                    len(scanned_variables),
                    "; ".join(scan_root_locations),
                    " || ".join(filter(None, scan_root_lines)),
                ]
            )


        return buffer.getvalue()

    def copy_structure_table_debug_csv(self) -> None:
        csv_text = self._build_structure_table_debug_csv()
        if not csv_text:
            log_warning("No structure rows available to export.", True)
            return

        clipboard_factory = getattr(QtWidgets.QApplication, "clipboard", None)
        if callable(clipboard_factory):
            clipboard_factory().setText(csv_text)
        else:
            copy_to_clipboard = getattr(ida_kernwin, "copy_to_clipboard", None)
            if not callable(copy_to_clipboard):
                log_warning("No clipboard API available to export CSV.", True)
                return
            copy_to_clipboard(csv_text)

        log_debug("Copied structure builder debug CSV to clipboard")


    def show_scanned_variables(self):
        if self.current_structure is None:
            return

        selected_members = self.get_selected_members()
        if selected_members:
            scanned_variables = {
                scan_object
                for member in selected_members
                for scan_object in member.scanned_variables
            }
        else:
            scanned_variables = set(
                self.current_structure.get_unique_scanned_variables(
                    self.current_structure.main_offset
                )
            )

        if not scanned_variables:
            log_warning("No scanned variables available for the current selection.", True)
            return

        chooser = ScannedVariableChooser(
            sorted(
                scanned_variables,
                key=lambda scan_object: (
                    getattr(scan_object, "func_ea", idaapi.BADADDR),
                    getattr(scan_object, "ea", idaapi.BADADDR),
                    scan_object.name,
                ),
            )
        )
        chooser.Show()

    def structure_table_recognize(self):
        member = self.get_selected_member()
        if not isinstance(member, VirtualTable):
            log_warning(
                "Recognize Structure currently only supports virtual table rows.",
                True,
            )
            return

        member.scan_virtual_functions(self.current_structure)
        self.update_structure_fields()

    def structure_table_resolve(self):
        if self.current_structure is None:
            return

        self.current_structure.auto_resolve()
        self.update_structure_fields()

    def structure_table_finalize(self):
        if self.current_structure is None:
            return

        self.current_structure.create_type_if_ready(self.structures)
        self.update_structure_fields()

    def structure_table_context_menu(self, point):
        if self.current_structure is None:
            return

        item = self.ui.tbl_structure.itemAt(point)
        if item is not None and not self.ui.tbl_structure.item(item.row(), 0).isSelected():
            self.ui.tbl_structure.selectRow(item.row())

        selected_member = self.get_selected_member()
        can_scan_child = self._build_child_scan_plan(selected_member) is not None
        can_open_child = bool(getattr(selected_member, "linked_child_structure_name", None))

        menu = QMenu()
        menu.addAction("Add Row", self.add_manual_row)
        menu.addAction("Insert Row Before", self.add_manual_row_before)
        menu.addAction("Insert Row After", self.add_manual_row_after)

        selection_count = len(self.get_selected_rows())
        edit_label = "Edit Selected Rows..." if selection_count > 1 else "Edit Row"
        edit_action = menu.addAction(edit_label, self.edit_selected_row)
        edit_action.setEnabled(bool(selection_count))

        duplicate_label = (
            "Duplicate Selected Rows" if selection_count > 1 else "Duplicate Row"
        )
        duplicate_action = menu.addAction(duplicate_label, self.duplicate_selected_rows)
        duplicate_action.setEnabled(bool(selection_count))

        enable_action = menu.addAction("Enable")
        enable_action.setEnabled(bool(self.get_selected_rows()))
        enable_action.triggered.connect(lambda: self.structure_table_enable_row(None))

        disable_action = menu.addAction("Disable")
        disable_action.setEnabled(bool(self.get_selected_rows()))
        disable_action.triggered.connect(lambda: self.structure_table_disable_row(None))

        array_action = menu.addAction("Toggle Array")
        array_action.setEnabled(bool(self.get_selected_rows()))
        array_action.triggered.connect(self.structure_table_toggle_array)

        origin_action = menu.addAction("Set As Origin")
        origin_action.setEnabled(bool(self.get_selected_rows()))
        origin_action.triggered.connect(self.structure_table_set_origin)

        remove_action = menu.addAction("Remove")
        remove_action.setEnabled(bool(self.get_selected_rows()))
        remove_action.triggered.connect(self.structure_table_remove_rows)

        nudge_up_action = menu.addAction("Move Earlier (-1)")
        nudge_up_action.setEnabled(bool(self.get_selected_rows()))
        nudge_up_action.triggered.connect(lambda: self.nudge_selected_rows(-1))

        nudge_down_action = menu.addAction("Move Later (+1)")
        nudge_down_action.setEnabled(bool(self.get_selected_rows()))
        nudge_down_action.triggered.connect(lambda: self.nudge_selected_rows(1))

        menu.addSeparator()

        resolve_action = menu.addAction("Auto Resolve")
        resolve_action.setEnabled(bool(self.current_structure.members))
        resolve_action.triggered.connect(self.structure_table_resolve)

        finalize_action = menu.addAction("Create Type")
        finalize_action.setEnabled(bool(self.current_structure.members))
        finalize_action.triggered.connect(self.structure_table_finalize)

        create_child_types_action = menu.addAction("Create Child Types")
        create_child_types_action.setEnabled(bool(self.current_structure.child_relationships))
        create_child_types_action.triggered.connect(self.create_child_types)

        create_subtree_types_action = menu.addAction("Create Type Subtree")
        create_subtree_types_action.setEnabled(bool(self.current_structure.child_relationships))
        create_subtree_types_action.triggered.connect(self.create_type_subtree)

        clear_action = menu.addAction("Clear")
        clear_action.setEnabled(bool(self.current_structure.members))
        clear_action.triggered.connect(self.structure_table_clear)

        menu.addSeparator()

        scanned_variables_action = menu.addAction("View Scanned Uses")
        scanned_variables_action.setEnabled(bool(self.current_structure.members))
        scanned_variables_action.triggered.connect(self.show_scanned_variables)

        debug_copy_action = menu.addAction("Copy Debug CSV")
        debug_copy_action.setEnabled(bool(self.current_structure.members))
        debug_copy_action.triggered.connect(self.copy_structure_table_debug_csv)

        scan_child_action = menu.addAction("Scan Child Structure")
        scan_child_action.setEnabled(can_scan_child)
        scan_child_action.triggered.connect(self.scan_child_structure)

        open_child_action = menu.addAction("Open Linked Child")
        open_child_action.setEnabled(can_open_child)
        open_child_action.triggered.connect(self.open_linked_child_structure)


        recognize_action = menu.addAction("Recognize VTable")
        recognize_action.setEnabled(isinstance(selected_member, VirtualTable))
        recognize_action.triggered.connect(self.structure_table_recognize)

        qt_exec(menu, self.ui.tbl_structure.viewport().mapToGlobal(point))


        qt_exec(menu, self.ui.tbl_structure.viewport().mapToGlobal(point))


structure_form = StructureBuilderForm()
