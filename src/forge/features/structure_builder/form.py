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
import ida_funcs
import idaapi

from forge.util.qt import QtCore, QtGui, QtWidgets, qt_exec, qt_item_flags
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
from forge.api.scan_object import ScanObject
from forge.api.scanner import NewDeepScanVisitor
from forge.api.structure import Structure, StructureRelationship
from forge.api.ui import set_row_background_color, set_row_foreground_color
from forge.features.structure_builder.child_scan import ChildScanMixin, ChildScanPlan
from forge.features.structure_builder.dialogs import (
    BulkMemberEditorDialog,
    MemberEditorDialog,
    MemberEditorValues,
)
from forge.util.logging import log_debug, log_warning
from .config import config


class Column(IntEnum):
    offset = 0
    type = 1
    name = 2
    score = 3
    comment = 4





class UI(QWidget, Ui_view_form):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

class StructureBuilderForm(ChildScanMixin, ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None
        self.ui = None
        self.structures: Dict[str, Structure] = {}
        self.current_structure: Structure | None = None
        self.layout = None
        self._shortcut_actions: list[QtGui.QAction] = []
        self._last_table_selection_signature: tuple | None = None
    def show(self):
        if self.ui is not None and not self._qt_widget_alive(self.ui):
            self._reset_ui_state()
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

    def OnClose(self, _form):
        self._reset_ui_state()

    def _reset_ui_state(self) -> None:
        self.parent = None
        self.ui = None
        self.layout = None
        self._shortcut_actions.clear()
        self._last_table_selection_signature = None

    @staticmethod
    def _qt_widget_alive(widget) -> bool:
        if widget is None:
            return False
        try:
            object_name = getattr(widget, "objectName", None)
            if callable(object_name):
                object_name()
            return True
        except RuntimeError:
            return False

    def _get_table_widget(self):
        if not self._qt_widget_alive(self.ui):
            self._reset_ui_state()
            return None

        table = getattr(self.ui, "tbl_structure", None)
        if not self._qt_widget_alive(table):
            self._reset_ui_state()
            return None
        return table

    def _get_tree_widget(self):
        if not self._qt_widget_alive(self.ui):
            self._reset_ui_state()
            return None

        tree = getattr(self.ui, "tree_structures", None)
        if not self._qt_widget_alive(tree):
            self._reset_ui_state()
            return None
        return tree

    def ensure_ui(self) -> bool:
        if self._get_table_widget() is not None and self._get_tree_widget() is not None:
            return True

        self._reset_ui_state()
        self.show()
        return self._get_table_widget() is not None and self._get_tree_widget() is not None

    def _structure_table_selection_signature(self) -> tuple | None:
        table = self._get_table_widget()
        if table is None:
            return None

        try:
            selected_rows = tuple(self.get_selected_rows())
            return (
                getattr(self.current_structure, "name", None),
                selected_rows,
                table.currentRow(),
                table.currentColumn(),
            )
        except RuntimeError:
            self._reset_ui_state()
            return None

    def _handle_structure_table_selection_change(self, *_args) -> None:
        signature = self._structure_table_selection_signature()
        if signature is not None and signature == self._last_table_selection_signature:
            return
        self._last_table_selection_signature = signature
        self.update_action_states()


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
        self.ui.tbl_structure.itemSelectionChanged.connect(
            self._handle_structure_table_selection_change
        )
        self.ui.tbl_structure.currentCellChanged.connect(
            self._handle_structure_table_selection_change
        )
        self.ui.tbl_structure.cellClicked.connect(
            self._handle_structure_table_selection_change
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
        flags = qt_item_flags(Qt.ItemIsSelectable, Qt.ItemIsEnabled)
        if editable:
            flags = qt_item_flags(flags, Qt.ItemIsEditable)
        item.setFlags(flags)
        return item

    def get_selected_rows(self) -> list[int]:
        table = self._get_table_widget()
        if table is None:
            return []

        try:
            rows = sorted({index.row() for index in table.selectedIndexes()})
            if rows:
                return rows

            current_row = table.currentRow()
            return [current_row] if current_row >= 0 else []
        except RuntimeError:
            self._reset_ui_state()
            return []

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
        table = self._get_table_widget()
        if table is None:
            return

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
        tree = self._get_tree_widget()
        if tree is None:
            return None
        return self._tree_item_structure(tree.currentItem())

    def reload_structure_list(self):
        tree = self._get_tree_widget()
        if tree is None:
            return

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

    def _refresh_all_linked_member_types(self) -> None:
        for structure in self.structures.values():
            structure.refresh_linked_member_types(self.structures)


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

        self._refresh_all_linked_member_types()
        self.update_structure_fields()

    def create_type_subtree(self):
        if self.current_structure is None:
            return

        self.current_structure.create_subtree_types_postorder(self.structures)
        self._refresh_all_linked_member_types()
        self.update_structure_fields()

    def update_structure_fields(self):
        table = self._get_table_widget()
        if table is None or self.ui is None:
            return

        selected_rows = set(self.get_selected_rows())
        if self.ui is None:
            return
        scroll_value = table.verticalScrollBar().value()

        blocker = QSignalBlocker(table)
        try:
            if self.current_structure is None:
                table.setRowCount(0)
                table.setDisabled(True)
                self.ui.input_name.setText("")
            else:
                self.current_structure.refresh_collisions()
                table.setEnabled(True)
                self.ui.input_name.setText(self.current_structure.name)
                table.setRowCount(len(self.current_structure.members))

                for row, member in enumerate(self.current_structure.members):
                    table.setItem(
                        row,
                        Column.offset,
                        self._make_table_item(
                            f"0x{member.offset:04X} [{hex(member.size)}]"
                        ),
                    )
                    table.setItem(
                        row,
                        Column.type,
                        self._make_table_item(self._format_type_name(member)),
                    )
                    table.setItem(
                        row,
                        Column.name,
                        self._make_table_item(member.name, editable=True),
                    )
                    table.setItem(
                        row,
                        Column.score,
                        self._make_table_item(str(member.score)),
                    )
                    table.setItem(
                        row,
                        Column.comment,
                        self._make_table_item(member.comment, editable=True),
                    )

                    if self.current_structure.main_offset == member.offset:
                        table.item(row, Column.offset).setBackground(
                            QColor(config["form"]["origin_color"])
                        )

                    if not member.enabled:
                        set_row_background_color(
                            table,
                            row,
                            QColor(config["form"]["disabled_color"]),
                        )
                    elif self.current_structure.has_collision(row):
                        set_row_background_color(
                            table,
                            row,
                            QColor(config["form"]["collision_background_color"]),
                        )
                        set_row_foreground_color(
                            table,
                            row,
                            QColor(config["form"]["collision_foreground_color"]),
                        )
        finally:
            del blocker

        self._restore_selected_rows(selected_rows)
        table = self._get_table_widget()
        if table is None:
            return
        table.verticalScrollBar().setValue(scroll_value)
        self.update_action_states()

    def update_action_states(self):
        if not self._qt_widget_alive(self.ui):
            self._reset_ui_state()
            return

        has_structure = self.current_structure is not None
        has_members = has_structure and bool(self.current_structure.members)
        selection_rows = self.get_selected_rows()
        has_selection = bool(selection_rows)
        selected_member = self.get_selected_member()
        if self.ui is None:
            return

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
        child_scan_plan = (
            self._build_child_scan_plan(selected_member)
            if selected_member is not None
            else None
        )
        can_scan_child = child_scan_plan is not None

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

        selection_count = len(selection_rows)
        self.ui.btn_edit_row.setText(
            "Edit Rows" if selection_count > 1 else "Edit Row"
        )
        self.ui.btn_duplicate_row.setText(
            "Duplicate Rows" if selection_count > 1 else "Duplicate Row"
        )

        self._update_summary_label()
        self._update_inspector_panel(selected_member, child_scan_plan)
        self._last_table_selection_signature = self._structure_table_selection_signature()

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

    def _update_inspector_panel(
        self,
        selected_member: AbstractMember | None = None,
        child_scan_plan=None,
    ) -> None:
        if self.current_structure is None:
            self.ui.lbl_provenance.setText("Provenance: -")
            self.ui.lbl_root_info.setText("Root: -")
            self.ui.lbl_parent_links.setText("Parents: -")
            self.ui.lbl_child_links.setText("Children: -")
            self.ui.lbl_selected_member_info.setText("Selected Row: -")
            self.ui.lbl_type_status.setText("Type Status: -")
            return

        if selected_member is None:
            selected_member = self.get_selected_member()
        if child_scan_plan is None and selected_member is not None:
            child_scan_plan = self._build_child_scan_plan(selected_member)

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
            f"Selected Row: {self._format_selected_member_info(selected_member, child_scan_ready=child_scan_plan is not None)}"
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

    def _format_selected_member_info(
        self,
        member: AbstractMember | None,
        *,
        child_scan_ready: bool = False,
    ) -> str:
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

        scanned_variables = Structure.dedupe_scanned_variables(
            getattr(member, "scanned_variables", ())
        )
        if scanned_variables:
            parts.append(f"uses {len(scanned_variables)}")

        if child_scan_ready:
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

        pseudocode = cfunc.get_pseudocode()
        tag_remove = getattr(ida_lines, "tag_remove", lambda value: value)

        def _pseudocode_line_text(entry) -> str:
            raw_line = getattr(entry, "line", None)
            if raw_line is None:
                raw_line = getattr(entry, "text", None)
            if raw_line is None:
                raw_line = entry
            return " ".join(tag_remove(str(raw_line)).split())

        def _line_for_item(item) -> str | None:
            try:
                line_no, _column = cfunc.find_item_coords(item)
            except Exception:
                return None
            if 1 <= line_no <= len(pseudocode):
                return _pseudocode_line_text(pseudocode[line_no - 1])
            return None


        candidates = []
        for item in getattr(cfunc, "treeitems", []):
            if getattr(item, "ea", idaapi.BADADDR) == target_ea:
                candidates.append(item)

        eamap = getattr(cfunc, "eamap", None)
        if not candidates and eamap is not None:
            try:
                candidates.extend(list(eamap.get(target_ea, [])))
            except Exception:
                pass

        if not candidates:
            body = getattr(cfunc, "body", None)
            if body is not None and hasattr(body, "find_closest_addr"):
                try:
                    closest_item = body.find_closest_addr(target_ea)
                except Exception:
                    closest_item = None
                if closest_item is not None:
                    candidates.append(closest_item)

        lines = []
        for item in candidates:
            line = _line_for_item(item)
            if line and line not in lines:
                lines.append(line)

        return " || ".join(lines) if lines else ""

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
        ) or (ida_funcs.get_func_name(func_ea) if func_ea != idaapi.BADADDR else "")
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
                Structure.dedupe_scanned_variables(
                    getattr(member, "scanned_variables", set())
                ),
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

        # Auto-resolve is a whole-table action; leaving stale row selection behind
        # can repaint rows with the inactive selection brush (white on some themes).
        if self.ui is not None:
            self.ui.tbl_structure.clearSelection()
            if hasattr(self.ui.tbl_structure, "setCurrentCell"):
                self.ui.tbl_structure.setCurrentCell(-1, -1)
            self.update_action_states()

    def structure_table_finalize(self):
        if self.current_structure is None:
            return

        self.current_structure.create_type_if_ready(self.structures)
        self._refresh_all_linked_member_types()
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
