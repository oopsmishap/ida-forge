import re

import ida_diskio
import ida_kernwin

from forge.util.qt import QtGui, QtWidgets

from .templated_types import TemplatedTypes
from .ui_form import Ui_templated_types_form

from forge.util.logging import *

QFontDatabase = QtGui.QFontDatabase


class UI(QtWidgets.QWidget, Ui_templated_types_form):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)


# noinspection PyArgumentList
class TemplatedTypesForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self._parent = None
        self.ui = None
        self.stl_form_layout = None
        self.template_types = TemplatedTypes()

    def show(self):
        return ida_kernwin.PluginForm.Show(self, "Templated Types")

    def OnCreate(self, form):
        self._parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout(self._parent)

        self.ui = UI(self._parent)
        layout.addWidget(self.ui)

        font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        font.setPointSize(11)
        self.ui.stl_struct_view.setFont(font)

        self.ui.btn_reload_stl_list.clicked.connect(self.reload_stl_list)
        self.ui.btn_open_stl_toml.clicked.connect(self.open_dialog_stl_file)
        self.ui.stl_list.currentRowChanged.connect(self.update_form)

        self.stl_form_layout = QtWidgets.QFormLayout()
        self.ui.stl_widget.setLayout(self.stl_form_layout)

        self.reload_stl_list()
        if self.ui.stl_list.count() > 0:
            self.ui.stl_list.setCurrentRow(0)
        self.update_form()

    def update_form(self):
        if self.ui is None:
            return

        try:
            current_item = self.ui.stl_list.currentItem()
            if current_item is None:
                self.ui.stl_title_fields.setText("Selected Type: ")
                self.ui.stl_title_struct.setText("Creating Type: ")
                self.ui.stl_struct_view.clear()
                return

            key = current_item.text()
            self.ui.stl_title_fields.setText(f"Selected Type: {key}")
            types = self.template_types.get_types(key) or []

            while self.stl_form_layout.count():
                item = self.stl_form_layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

            for t in types:
                type_edit = QtWidgets.QLineEdit()
                name_edit = QtWidgets.QLineEdit()
                self.stl_form_layout.addRow(f"{t} Type", type_edit)
                self.stl_form_layout.addRow(f"{t} Name", name_edit)
                type_edit.textChanged.connect(lambda _text, k=key: self.reload_stl_struct(k))
                name_edit.textChanged.connect(lambda _text, k=key: self.reload_stl_struct(k))

            btn_set_type = QtWidgets.QPushButton("Create Type")
            self.stl_form_layout.addRow(btn_set_type)
            btn_set_type.clicked.connect(lambda: self.create_stl_type(key))

            self.reload_stl_struct(key)
        except Exception:
            pass

    def reload_stl_list(self):
        if self.ui is None:
            return

        self.ui.type_list_label.setText(f"Type List: {self.template_types.file_name}")
        self.ui.stl_list.clear()
        if self.template_types.reload_types():
            log_info(f"Opening: {self.template_types.file_path}")
            for item in self.template_types.keys:
                self.ui.stl_list.addItem(item)

    def reload_stl_struct(self, key):
        if self.ui is None:
            return

        try:
            struct = self.template_types.get_struct(key)
            base_name = "Creating Type: " + self.template_types.get_base_name(key)
            args = self.get_stl_args(key)
            self.ui.stl_struct_view.setPlainText(struct.format(*args))
            self.ui.stl_title_struct.setText(base_name.format(*args))
        except Exception:
            pass

    def get_stl_args(self, key):
        args = ()
        for w in self.ui.stl_widget.findChildren(QtWidgets.QLineEdit):
            arg = w.text()
            if arg == "":
                arg = "$void$"
            args = args + (arg,)
        return args

    def create_stl_type(self, key):
        args = self.get_stl_args(key)

        for i in range(len(args)):
            if not re.match(r"^[a-zA-Z_]([\w_](::){0,2})+(?<!:)\**$", args[i]):
                log_warning(f"Type name {args[i]} is an invalid type name", True)
                return
            else:
                if not re.match(r"^\w+$", args[i]):
                    log_warning(f"Type name {args[i]} is an invalid name", True)
                    return

        self.template_types.set_type(key, args)
        self.reload_stl_struct(key)

    def open_dialog_stl_file(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(
            None, "Open TOML file", ida_diskio.get_user_idadir(), "Toml file (*.toml)"
        )
        self.template_types.set_file_path(file_name[0])
        self.reload_stl_list()


templated_types_form = TemplatedTypesForm()
