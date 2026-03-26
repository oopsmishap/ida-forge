import os
from enum import IntEnum
from pathlib import Path
from typing import Dict

import ida_hexrays
import ida_kernwin
import ida_typeinf
import idaapi
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QListWidgetItem, QMenu, QTableWidgetItem, QWidget

from forge.api.members import AbstractMember, Member, VirtualTable, parse_user_tinfo
from forge.api.structure import Structure
from forge.api.ui import Choose, set_row_background_color, set_row_foreground_color
from forge.util.logging import log_warning
from .config import config

class column(IntEnum):
    offset = 0
    type = 1
    name = 2
    score = 3
    comment = 4


class UI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # Load .ui file
        filename = os.fspath(Path(__file__).resolve().parent / "form.ui")
        uic.loadUi(filename, self)


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


class ManualMemberDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, *, offset: int = 0, type_name: str = "u8"):
        super().__init__(parent)
        self.setWindowTitle("Add Structure Row")

        self.offset_edit = QtWidgets.QLineEdit(f"0x{offset:X}")
        self.type_edit = QtWidgets.QLineEdit(type_name)
        self.name_edit = QtWidgets.QLineEdit("")
        self.comment_edit = QtWidgets.QLineEdit("")

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow("Offset", self.offset_edit)
        form_layout.addRow("Type", self.type_edit)
        form_layout.addRow("Name", self.name_edit)
        form_layout.addRow("Comment", self.comment_edit)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form_layout)
        layout.addWidget(buttons)

    def get_values(self):
        return {
            "offset": self.offset_edit.text().strip(),
            "type_name": self.type_edit.text().strip(),
            "name": self.name_edit.text().strip(),
            "comment": self.comment_edit.text().strip(),
        }


# noinspection PyArgumentList
class StructureBuilderForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.parent = None
        self.ui = None
        self.structures: Dict[str, Structure] = {}
        self.current_structure = None
        self.layout = None

    def show(self):
        return ida_kernwin.PluginForm.Show(self, "Structure Builder")

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QVBoxLayout(self.parent)
        self.ui = UI(self.parent)
        self.layout.addWidget(self.ui)

        self.ui.btn_add.clicked.connect(self.add_structure)
        self.ui.btn_remove.clicked.connect(self.remove_structure)
        self.ui.btn_apply_name.clicked.connect(self.structure_renamed)
        self.ui.pushButton_3.clicked.connect(self.structure_table_resolve)
        self.ui.pushButton_2.clicked.connect(self.structure_table_finalize)
        self.ui.pushButton_5.clicked.connect(
            lambda: self.structure_table_enable_row(None)
        )
        self.ui.pushButton_6.clicked.connect(
            lambda: self.structure_table_disable_row(None)
        )
        self.ui.pushButton_4.clicked.connect(self.structure_table_toggle_array)
        self.ui.pushButton.clicked.connect(self.structure_table_set_origin)
        self.ui.pushButton_9.clicked.connect(self.structure_table_remove_rows)
        self.ui.pushButton_10.clicked.connect(self.structure_table_clear)
        self.ui.pushButton_7.clicked.connect(self.show_scanned_variables)
        self.ui.pushButton_8.clicked.connect(self.structure_table_recognize)
        self.ui.pushButton_11.clicked.connect(self.add_manual_row)

        self.ui.lst_structures.itemSelectionChanged.connect(self.list_selection_changed)

        self.ui.tbl_structure.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows
        )
        self.ui.tbl_structure.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection
        )
        self.ui.tbl_structure.cellDoubleClicked.connect(
            self.structure_table_interaction
        )
        self.ui.tbl_structure.itemChanged.connect(self.structure_table_item_changed)
        self.ui.tbl_structure.itemSelectionChanged.connect(self.update_action_states)

        self.ui.action_enable.triggered.connect(
            lambda: self.structure_table_enable_row(None)
        )
        self.ui.tbl_structure.addAction(self.ui.action_enable)
        self.ui.action_disable.triggered.connect(
            lambda: self.structure_table_disable_row(None)
        )
        self.ui.tbl_structure.addAction(self.ui.action_disable)
        self.ui.action_resolve.triggered.connect(self.structure_table_resolve)
        self.ui.tbl_structure.addAction(self.ui.action_resolve)
        self.ui.action_finalize.triggered.connect(self.structure_table_finalize)
        self.ui.tbl_structure.addAction(self.ui.action_finalize)

        self.ui.lst_structures.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.lst_structures.customContextMenuRequested.connect(
            self.list_context_menu
        )

        self.ui.tbl_structure.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tbl_structure.customContextMenuRequested.connect(
            self.structure_table_context_menu
        )
        self.update_action_states()

    def _make_table_item(self, text: str, editable: bool = False) -> QTableWidgetItem:
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

        selected_rows = self.normalize_rows(rows)
        return [
            self.current_structure.members[row]
            for row in selected_rows
            if 0 <= row < len(self.current_structure.members)
        ]

    def get_selected_member(self):
        members = self.get_selected_members()
        return members[0] if members else None

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
        if structure_name == "":
            self.current_structure = None
            self.update_structure_fields()
            return

        if structure_name not in self.structures:
            self.current_structure = None
            log_warning(f"Structure {structure_name} does not exist!", True)
            self.update_structure_fields()
            return

        self.current_structure = self.structures[structure_name]
        self.update_structure_fields()

    def add_structure(self):
        name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Enter structure name:")
        self.create_structure(name)

    def create_structure(self, name: str):
        if not name:
            return None

        name = name.strip()
        if not name:
            return None

        if name in self.structures:
            log_warning("That structure name already exists!", True)
            return None

        structure = Structure(name)
        self.structures[structure.name] = structure

        if self.ui is not None:
            item = self.add_structure_item(structure)
            self.ui.lst_structures.clearSelection()
            self.ui.lst_structures.setCurrentItem(item)
            item.setSelected(True)
        else:
            self.current_structure = structure

        self.update_action_states()
        return structure

    def prompt_create_structure(self):
        name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Enter structure name:")
        return self.create_structure(name)

    def remove_structure(self):
        item = self.ui.lst_structures.currentItem()
        if item is None:
            log_warning("No structure selected!", True)
            return

        structure = item.data(Qt.UserRole)
        if structure is None:
            log_warning("No structure selected!", True)
            return

        self.ui.lst_structures.takeItem(self.ui.lst_structures.row(item))

        del self.structures[structure.name]
        if self.current_structure == structure:
            self.set_structure("")
        self.update_action_states()

    def list_context_menu(self, point):
        item = self.ui.lst_structures.itemAt(point)

        menu = QMenu()
        menu.addAction("Add", self.add_structure)

        if item is not None:
            menu.addAction("Remove", self.remove_structure)

        menu.exec_(self.ui.lst_structures.mapToGlobal(point))

    def list_selection_changed(self):
        item = self.ui.lst_structures.currentItem()
        if item is None:
            self.set_structure("")
            return
        structure = item.data(Qt.UserRole)
        if isinstance(structure, Structure):
            self.set_structure(structure.name)
        else:
            self.set_structure("")

    def update_structure_fields(self):
        if self.ui is None:
            return

        self.ui.tbl_structure.blockSignals(True)
        try:
            if self.current_structure is None:
                self.ui.tbl_structure.setDisabled(True)
                self.ui.txt_name.setText("")
                self.ui.tbl_structure.setRowCount(0)
            else:
                self.current_structure.refresh_collisions()
                self.ui.tbl_structure.setEnabled(True)
                self.ui.txt_name.setText(self.current_structure.name)

                self.ui.tbl_structure.setRowCount(len(self.current_structure.members))
                for row, member in enumerate(self.current_structure.members):
                    self.ui.tbl_structure.setItem(
                        row,
                        column.offset,
                        self._make_table_item(
                            f"0x{member.offset:04X} [{hex(member.size)}]"
                        ),
                    )
                    self.ui.tbl_structure.setItem(
                        row, column.type, self._make_table_item(member.type_name)
                    )
                    self.ui.tbl_structure.setItem(
                        row, column.name, self._make_table_item(member.name)
                    )
                    self.ui.tbl_structure.setItem(
                        row, column.score, self._make_table_item(f"{member.score}")
                    )
                    self.ui.tbl_structure.setItem(
                        row, column.comment, self._make_table_item(member.comment)
                    )

                    if self.current_structure.main_offset == member.offset:
                        self.ui.tbl_structure.item(row, column.offset).setBackground(
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
            self.ui.tbl_structure.blockSignals(False)
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
        self.ui.txt_name.setEnabled(has_structure)
        self.ui.tbl_structure.setEnabled(has_structure)

        self.ui.pushButton_3.setEnabled(has_members)
        self.ui.pushButton_2.setEnabled(has_members)
        self.ui.pushButton_5.setEnabled(has_selection)
        self.ui.pushButton_6.setEnabled(has_selection)
        self.ui.pushButton_4.setEnabled(has_selection)
        self.ui.pushButton.setEnabled(has_selection)
        self.ui.pushButton_9.setEnabled(has_selection)
        self.ui.pushButton_10.setEnabled(has_members)
        self.ui.pushButton_7.setEnabled(has_members)
        self.ui.pushButton_8.setEnabled(isinstance(selected_member, VirtualTable))
        self.ui.pushButton_11.setEnabled(has_structure)

    def _default_manual_row_offset(self) -> int:
        member = self.get_selected_member()
        if member is not None:
            return member.offset
        if self.current_structure is not None:
            return self.current_structure.main_offset
        return 0

    @staticmethod
    def _parse_offset(text: str) -> int | None:
        try:
            return int(text, 0)
        except ValueError:
            return None

    def add_manual_row(self):
        if self.current_structure is None:
            return

        selected_member = self.get_selected_member()
        default_type = selected_member.type_name if selected_member is not None else "u8"
        dialog = ManualMemberDialog(
            self.ui,
            offset=self._default_manual_row_offset(),
            type_name=default_type,
        )
        if dialog.exec_() != QtWidgets.QDialog.Accepted:
            return

        values = dialog.get_values()
        offset = self._parse_offset(values["offset"])
        if offset is None:
            log_warning(f"Invalid offset: {values['offset']}", True)
            return

        tinfo = parse_user_tinfo(values["type_name"])
        if tinfo is None:
            log_warning(f"Failed to parse type declaration: {values['type_name']}", True)
            return

        member = Member(
            offset,
            tinfo,
            scanned_variable=None,
            origin=self.current_structure.main_offset,
        )
        if values["name"]:
            member.name = values["name"]
        member.comment = values["comment"]
        self.current_structure.add_member(member)
        self.update_structure_fields()

    def structure_renamed(self):
        if self.current_structure is None:
            return

        name = self.ui.txt_name.toPlainText().strip()
        if not name or name == self.current_structure.name:
            return
        if name in self.structures:
            log_warning("That structure name already exists!", True)
            return

        self.structures[name] = self.current_structure
        del self.structures[self.current_structure.name]
        self.current_structure.name = name
        self.reload_structure_list()

    def structure_table_interaction(self, row, col):
        if self.current_structure is None:
            return

        if col == column.type:
            member = self.current_structure.members[row]
            member.activate()
            self.current_structure.refresh_collisions()
            self.update_structure_fields()
        elif col == column.name or col == column.comment:
            item = self.ui.tbl_structure.item(row, col)
            item.setFlags(item.flags() | Qt.ItemIsEditable)
            self.ui.tbl_structure.editItem(item)

    def structure_table_item_changed(self, item):
        if self.current_structure is None:
            return

        row = item.row()
        col = item.column()
        member = self.current_structure.members[row]
        if col == column.name:
            member.name = item.text()
        elif col == column.comment:
            member.comment = item.text()
        elif col == column.type:
            tinfo = parse_user_tinfo(item.text())
            if tinfo is not None:
                member.tinfo = tinfo
                member.is_array = False
                member.invalidate_score()
            else:
                log_warning(f"Failed to parse type declaration: {item.text()}", True)

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

        members = self.get_selected_members()
        if members:
            scanned_variables = {
                scanned_variable
                for member in members
                for scanned_variable in member.scanned_variables
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
                key=lambda item: (item.func_ea, item.ea, item.name),
            )
        )
        chooser.Show()

    def structure_table_recognize(self):
        member = self.get_selected_member()
        if member is None:
            return

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
        item = self.ui.tbl_structure.itemAt(point)
        if item is None:
            return

        row = item.row()
        self.ui.tbl_structure.selectRow(row)

        menu = QMenu()

        enable_action = menu.addAction("Enable")
        enable_action.triggered.connect(lambda: self.structure_table_enable_row(row))

        disable_action = menu.addAction("Disable")
        disable_action.triggered.connect(lambda: self.structure_table_disable_row(row))

        array_action = menu.addAction("Toggle Array")
        array_action.triggered.connect(self.structure_table_toggle_array)

        add_row_action = menu.addAction("Add Row")
        add_row_action.triggered.connect(self.add_manual_row)

        origin_action = menu.addAction("Set As Origin")
        origin_action.triggered.connect(self.structure_table_set_origin)

        remove_action = menu.addAction("Remove")
        remove_action.triggered.connect(self.structure_table_remove_rows)

        resolve_action = menu.addAction("Resolve")
        resolve_action.triggered.connect(self.structure_table_resolve)

        finalize_action = menu.addAction("Finalize")
        finalize_action.triggered.connect(self.structure_table_finalize)

        scanned_variables_action = menu.addAction("View Scanned Variables")
        scanned_variables_action.triggered.connect(self.show_scanned_variables)

        recognize_action = menu.addAction("Recognize Structure")
        recognize_action.setEnabled(isinstance(self.get_selected_member(), VirtualTable))
        recognize_action.triggered.connect(self.structure_table_recognize)

        menu.exec_(self.ui.tbl_structure.viewport().mapToGlobal(point))


structure_form = StructureBuilderForm()
