from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Dict

import ida_hexrays
import ida_kernwin
import idaapi

from forge.util.qt import QtCore, QtGui, QtWidgets, qt_exec
from .ui_form import Ui_view_form

QSignalBlocker = QtCore.QSignalBlocker
Qt = QtCore.Qt
QColor = QtGui.QColor
QListWidgetItem = QtWidgets.QListWidgetItem
QMenu = QtWidgets.QMenu
QTableWidgetItem = QtWidgets.QTableWidgetItem
QWidget = QtWidgets.QWidget

from forge.api.members import AbstractMember, Member, VirtualTable, parse_user_tinfo
from forge.api.structure import Structure
from forge.api.ui import Choose, set_row_background_color, set_row_foreground_color
from forge.util.logging import log_warning
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


class StructureBuilderForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None
        self.ui = None
        self.structures: Dict[str, Structure] = {}
        self.current_structure: Structure | None = None
        self.layout = None

    def show(self):
        return ida_kernwin.PluginForm.Show(self, "Structure Builder")

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QVBoxLayout(self.parent)
        self.ui = UI(self.parent)
        self.layout.addWidget(self.ui)

        self._connect_signals()
        self._configure_table()
        self.update_action_states()
        self.update_structure_fields()

    def _connect_signals(self) -> None:
        self.ui.btn_add.clicked.connect(self.add_structure)
        self.ui.btn_remove.clicked.connect(self.remove_structure)
        self.ui.btn_apply_name.clicked.connect(self.structure_renamed)
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
        self.ui.btn_edit_row.clicked.connect(self.edit_selected_row)

        self.ui.lst_structures.itemSelectionChanged.connect(self.list_selection_changed)
        self.ui.lst_structures.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.lst_structures.customContextMenuRequested.connect(
            self.list_context_menu
        )

        self.ui.tbl_structure.cellDoubleClicked.connect(
            self.structure_table_interaction
        )
        self.ui.tbl_structure.itemChanged.connect(self.structure_table_item_changed)
        self.ui.tbl_structure.itemSelectionChanged.connect(self.update_action_states)
        self.ui.tbl_structure.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tbl_structure.customContextMenuRequested.connect(
            self.structure_table_context_menu
        )

        self.ui.action_enable.triggered.connect(
            lambda: self.structure_table_enable_row(None)
        )
        self.ui.action_disable.triggered.connect(
            lambda: self.structure_table_disable_row(None)
        )
        self.ui.action_resolve.triggered.connect(self.structure_table_resolve)
        self.ui.action_finalize.triggered.connect(self.structure_table_finalize)
        self.ui.action_edit.triggered.connect(self.edit_selected_row)
        self.ui.action_add_row.triggered.connect(self.add_manual_row)

        for action in (
            self.ui.action_enable,
            self.ui.action_disable,
            self.ui.action_resolve,
            self.ui.action_finalize,
            self.ui.action_edit,
            self.ui.action_add_row,
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

    def reload_structure_list(self):
        if self.ui is None:
            return

        current_name = self.current_structure.name if self.current_structure else None
        self.ui.lst_structures.clear()
        selected_item = None

        for structure in self.structures.values():
            item = self.add_structure_item(structure)
            if structure.name == current_name:
                selected_item = item

        if selected_item is not None:
            self.ui.lst_structures.setCurrentItem(selected_item)

        self.update_action_states()

    def add_structure_item(self, structure: Structure):
        item = QListWidgetItem(structure.name, self.ui.lst_structures)
        item.setData(Qt.UserRole, structure)
        return item

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

    def create_structure(self, name: str):
        if not name:
            return None

        clean_name = name.strip()
        if not clean_name:
            return None

        if clean_name in self.structures:
            log_warning("That structure name already exists!", True)
            return None

        structure = Structure(clean_name)
        self.structures[structure.name] = structure

        if self.ui is None:
            self.current_structure = structure
        else:
            item = self.add_structure_item(structure)
            self.ui.lst_structures.clearSelection()
            self.ui.lst_structures.setCurrentItem(item)
            item.setSelected(True)

        self.update_action_states()
        return structure

    def prompt_create_structure(self):
        name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Enter structure name:")
        return self.create_structure(name)

    def remove_structure(self):
        if self.ui is None:
            return

        item = self.ui.lst_structures.currentItem()
        if item is None:
            log_warning("No structure selected!", True)
            return

        structure = item.data(Qt.UserRole)
        if not isinstance(structure, Structure):
            log_warning("No structure selected!", True)
            return

        self.ui.lst_structures.takeItem(self.ui.lst_structures.row(item))
        del self.structures[structure.name]
        if self.current_structure == structure:
            self.set_structure("")
        self.update_action_states()

    def list_context_menu(self, point):
        menu = QMenu()
        menu.addAction("Add Structure", self.add_structure)

        item = self.ui.lst_structures.itemAt(point)
        if item is not None:
            menu.addAction("Remove Structure", self.remove_structure)

        qt_exec(menu, self.ui.lst_structures.mapToGlobal(point))

    def list_selection_changed(self):
        item = self.ui.lst_structures.currentItem()
        if item is None:
            self.set_structure("")
            return

        structure = item.data(Qt.UserRole)
        self.set_structure(structure.name if isinstance(structure, Structure) else "")

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

        self.ui.btn_remove.setEnabled(has_structure)
        self.ui.btn_apply_name.setEnabled(has_structure)
        self.ui.input_name.setEnabled(has_structure)
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
        self.ui.btn_edit_row.setEnabled(has_selection)

        self.ui.action_enable.setEnabled(has_selection)
        self.ui.action_disable.setEnabled(has_selection)
        self.ui.action_resolve.setEnabled(has_members)
        self.ui.action_finalize.setEnabled(has_members)
        self.ui.action_edit.setEnabled(has_selection)
        self.ui.action_add_row.setEnabled(has_structure)

        self._update_summary_label()

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

    def _default_editor_values(self, member: AbstractMember | None = None) -> MemberEditorValues:
        if member is None:
            default_offset = (
                self.get_selected_member().offset
                if self.get_selected_member() is not None
                else self.current_structure.main_offset if self.current_structure else 0
            )
            default_type_name = (
                self.get_selected_member().type_name
                if self.get_selected_member() is not None
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
    ) -> MemberEditorValues | None:
        dialog = MemberEditorDialog(
            self.ui,
            title=title,
            values=self._default_editor_values(member),
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

    def add_manual_row(self):
        if self.current_structure is None:
            return

        values = self._show_member_editor(title="Add Structure Row")
        if values is None:
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

    def edit_selected_row(self):
        if self.current_structure is None:
            return

        member = self.get_selected_member()
        if member is None:
            return

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

    def structure_renamed(self):
        if self.current_structure is None:
            return

        name = self.ui.input_name.text().strip()
        if not name or name == self.current_structure.name:
            return
        if name in self.structures:
            log_warning("That structure name already exists!", True)
            return

        self.structures[name] = self.current_structure
        del self.structures[self.current_structure.name]
        self.current_structure.name = name
        self.reload_structure_list()

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

        self.current_structure.pack_structure()
        self.update_structure_fields()

    def structure_table_context_menu(self, point):
        if self.current_structure is None:
            return

        item = self.ui.tbl_structure.itemAt(point)
        if item is not None and not self.ui.tbl_structure.item(item.row(), 0).isSelected():
            self.ui.tbl_structure.selectRow(item.row())

        menu = QMenu()
        menu.addAction("Add Row", self.add_manual_row)

        edit_action = menu.addAction("Edit Row", self.edit_selected_row)
        edit_action.setEnabled(bool(self.get_selected_rows()))

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

        menu.addSeparator()

        resolve_action = menu.addAction("Auto Resolve")
        resolve_action.setEnabled(bool(self.current_structure.members))
        resolve_action.triggered.connect(self.structure_table_resolve)

        finalize_action = menu.addAction("Create Type")
        finalize_action.setEnabled(bool(self.current_structure.members))
        finalize_action.triggered.connect(self.structure_table_finalize)

        clear_action = menu.addAction("Clear")
        clear_action.setEnabled(bool(self.current_structure.members))
        clear_action.triggered.connect(self.structure_table_clear)

        menu.addSeparator()

        scanned_variables_action = menu.addAction("View Scanned Uses")
        scanned_variables_action.setEnabled(bool(self.current_structure.members))
        scanned_variables_action.triggered.connect(self.show_scanned_variables)

        recognize_action = menu.addAction("Recognize VTable")
        recognize_action.setEnabled(isinstance(self.get_selected_member(), VirtualTable))
        recognize_action.triggered.connect(self.structure_table_recognize)

        qt_exec(menu, self.ui.tbl_structure.viewport().mapToGlobal(point))


structure_form = StructureBuilderForm()
