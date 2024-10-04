import os
from enum import IntEnum
from pathlib import Path
from typing import Dict

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QWidget, QMenu, QTableWidgetItem, QListWidgetItem

from PyQt5 import uic, QtWidgets
from forge.api.structure import Structure
from forge.api.ui import set_row_background_color, set_row_foreground_color
from forge.util.logging import *
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

        # Connect signals
        # Buttons
        self.ui.btn_add.clicked.connect(self.add_structure)
        self.ui.btn_remove.clicked.connect(self.remove_structure)
        self.ui.btn_apply_name.clicked.connect(self.structure_renamed)

        # List
        self.ui.lst_structures.itemSelectionChanged.connect(self.list_selection_changed)

        # Table
        self.ui.tbl_structure.cellDoubleClicked.connect(
            self.structure_table_interaction
        )
        self.ui.tbl_structure.itemChanged.connect(self.structure_table_item_changed)

        # Actions
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

        # Context menu
        # Structure List
        self.ui.lst_structures.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.lst_structures.customContextMenuRequested.connect(
            self.list_context_menu
        )

        # Structure Table
        self.ui.tbl_structure.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tbl_structure.customContextMenuRequested.connect(
            self.structure_table_context_menu
        )

    def reload_structure_list(self):
        self.ui.lst_structures.clear()
        for structure in self.structures.values():
            self.add_structure_item(structure)

    def add_structure_item(self, structure: Structure):
        item = QListWidgetItem(structure.name, self.ui.lst_structures)
        item.setData(Qt.UserRole, structure)
        return item

    def set_structure(self, structure_name: str):
        if structure_name == "":
            self.current_structure = None
            return

        if structure_name not in self.structures:
            self.current_structure = None
            log_warning(f"Structure {structure_name} does not exist!", True)
            return

        self.current_structure = self.structures[structure_name]
        self.update_structure_fields()

    def add_structure(self):
        name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Enter structure name:")
        if name in self.structures.keys():
            log_warning("That structure name already exists!", True)
            return
        structure = Structure(name)
        self.structures[structure.name] = structure

        item = self.add_structure_item(structure)
        self.ui.lst_structures.clearSelection()
        self.ui.lst_structures.setCurrentItem(item)
        item.setSelected(True)

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
        if type(structure) is Structure:
            self.set_structure(structure.name)
        else:
            self.set_structure("")

    def update_structure_fields(self):
        if self.current_structure is None:
            self.ui.tbl_structure.setDisabled(True)
            self.ui.txt_name.setText("")
            self.ui.tbl_structure.setRowCount(0)
            self.current_structure = None
        else:
            self.current_structure.refresh_collisions()
            self.ui.tbl_structure.setEnabled(True)
            self.ui.txt_name.setText(self.current_structure.name)

            self.ui.tbl_structure.setRowCount(len(self.current_structure.members))
            for row, member in enumerate(self.current_structure.members):
                self.ui.tbl_structure.setItem(
                    row,
                    column.offset,
                    QTableWidgetItem(f"0x{member.offset:04X} [{hex(member.size)}]"),
                )
                self.ui.tbl_structure.setItem(
                    row, column.type, QTableWidgetItem(member.type_name)
                )
                self.ui.tbl_structure.setItem(
                    row, column.name, QTableWidgetItem(member.name)
                )
                self.ui.tbl_structure.setItem(
                    row, column.score, QTableWidgetItem(member.score)
                )
                self.ui.tbl_structure.setItem(
                    row, column.comment, QTableWidgetItem(member.comment)
                )

                # Color table
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

    def structure_renamed(self):
        name = self.ui.txt_name.toPlainText()
        if name == self.current_structure.name:
            return
        if name in self.structures.keys():
            log_warning("That structure name already exists!", True)
            return

        self.structures[name] = self.current_structure
        del self.structures[self.current_structure.name]
        self.current_structure.name = name
        self.reload_structure_list()

    def structure_table_interaction(self, row, col):
        if col == column.name or col == column.comment:
            item = self.ui.tbl_structure.item(row, col)
            item.setFlags(item.flags() | Qt.ItemIsEditable)
            self.ui.tbl_structure.editItem(item)

    def structure_table_item_changed(self, item):
        row = item.row()
        col = item.column()
        if col == column.name:
            self.current_structure.members[row].name = item.text()
        elif col == column.comment:
            self.current_structure.members[row].comment = item.text()
        # TODO: Handle type changes
        self.ui.tbl_structure.setItem(row, col, item)

    def structure_table_enable_row(self, row):
        if row is None:
            row = self.ui.tbl_structure.currentRow()
        self.current_structure.enable_members(row)
        self.current_structure.refresh_collisions()
        self.update_structure_fields()

    def structure_table_disable_row(self, row):
        if row is None:
            row = self.ui.tbl_structure.currentRow()
        self.current_structure.disable_members(row)
        self.current_structure.refresh_collisions()
        self.update_structure_fields()

    def structure_table_resolve(self):
        self.current_structure.auto_resolve()
        self.update_structure_fields()

    def structure_table_finalize(self):
        self.current_structure.pack_structure()
        self.update_structure_fields()

    def structure_table_context_menu(self, point):
        item = self.ui.tbl_structure.itemAt(point)
        if item is None:
            return

        row = item.row()

        self.ui.action_enable.triggered.connect(
            lambda: self.structure_table_enable_row(row)
        )
        self.ui.action_disable.triggered.connect(
            lambda: self.structure_table_disable_row(row)
        )

        menu = QMenu()

        menu.addAction(self.structure_table_enable_row)
        menu.addAction(self.structure_table_disable_row)
        menu.addAction(self.structure_table_resolve)
        menu.addAction(self.structure_table_finalize)

        if item is not None:
            pass

        menu.exec_(self.ui.tbl_structure.viewport().mapToGlobal(point))


structure_form = StructureBuilderForm()
