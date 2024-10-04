import re

import ida_diskio
import ida_kernwin
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtGui import QFontDatabase

from .templated_types import TemplatedTypes

from forge.util.logging import *


# noinspection PyArgumentList
class TemplatedTypesForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self._parent = None
        self.type_list_label = None
        self.stl_title_fields = None
        self.stl_title_struct = None
        self.stl_struct_view = None
        self.stl_list = None
        self.stl_widget = None
        self.stl_form_layout = None
        self.template_types = TemplatedTypes()

    def show(self):
        return ida_kernwin.PluginForm.Show(self, "Templated Types")

    def OnCreate(self, form):
        self._parent = self.FormToPyQtWidget(form)

        layout = QtWidgets.QGridLayout()

        self.type_list_label = QtWidgets.QLabel(
            f"Type List: {self.template_types.file_name}"
        )
        layout.addWidget(self.type_list_label, 0, 0)

        self.stl_title_fields = QtWidgets.QLabel("Selected Type: ")
        layout.addWidget(self.stl_title_fields, 0, 1)

        self.stl_title_struct = QtWidgets.QLabel("Creating Type: ")
        layout.addWidget(self.stl_title_struct, 0, 2)

        self.stl_struct_view = QtWidgets.QTextEdit()
        self.stl_struct_view.setReadOnly(True)
        font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        font.setPointSize(11)
        # font = QtGui.QFont(QFontDatabase.FixedFont, 11)
        self.stl_struct_view.setFont(font)
        layout.addWidget(self.stl_struct_view, 1, 2)

        self.stl_list = QtWidgets.QListWidget()
        for item in self.template_types.keys:
            self.stl_list.addItem(item)
        self.stl_list.setFixedWidth(300)
        self.stl_list.setCurrentRow(0)
        self.stl_list.currentRowChanged.connect(self.update_form)
        layout.addWidget(self.stl_list, 1, 0)

        self.stl_widget = QtWidgets.QWidget()
        layout.addWidget(self.stl_widget, 1, 1)

        btn_reload_stl_list = QtWidgets.QPushButton("Reload Templated Types TOML")
        btn_reload_stl_list.setFixedWidth(300)
        btn_reload_stl_list.clicked.connect(self.reload_stl_list)
        layout.addWidget(btn_reload_stl_list, 2, 0)

        btn_open_stl_toml = QtWidgets.QPushButton("Open Templated Types TOML")
        btn_reload_stl_list.setFixedWidth(300)
        btn_open_stl_toml.clicked.connect(self.open_dialog_stl_file)
        layout.addWidget(btn_open_stl_toml, 3, 0)

        self.stl_form_layout = QtWidgets.QFormLayout()

        layout.setColumnStretch(1, 1)
        layout.setColumnStretch(2, 1)

        self._parent.setLayout(layout)

        self.update_form()

    def update_form(self):
        # wrapped in a try/except, as exception is thrown when TOML is refreshed
        try:
            # get key and update title
            key = self.stl_list.currentItem().text()
            self.stl_title_fields.setText("Selected Type: {}".format(key))
            types = self.template_types.get_types(key)

            # remove previous widgets from layout... QT needs to do this
            for i in reversed(range(self.stl_form_layout.count())):
                self.stl_form_layout.itemAt(i).widget().setParent(None)

            # for each template type we add a type & name field
            for t in types:
                e1 = QtWidgets.QLineEdit()
                e2 = QtWidgets.QLineEdit()
                self.stl_form_layout.addRow(QtWidgets.QLabel("{0} Type".format(t)), e1)
                self.stl_form_layout.addRow(QtWidgets.QLabel("{0} Name".format(t)), e2)
                e1.textChanged.connect(lambda: self.reload_stl_struct(key))
                e2.textChanged.connect(lambda: self.reload_stl_struct(key))

            # add the button and apply layout to widget
            btn_set_type = QtWidgets.QPushButton("Create Type")
            self.stl_form_layout.addRow(btn_set_type)
            self.stl_widget.setLayout(self.stl_form_layout)

            self.reload_stl_struct(key)

            # connect a callback to the button
            btn_set_type.clicked.connect(lambda: self.create_stl_type(key))
        except:
            pass

    def reload_stl_list(self):
        self.type_list_label.setText(f"Type List: {self.template_types.file_name}")
        self.stl_list.clear()
        if self.template_types.reload_types():
            log_info(f"Opening: {self.template_types.file_path}")
            for item in self.template_types.keys:
                self.stl_list.addItem(item)

    def reload_stl_struct(self, key):
        try:
            struct = self.template_types.get_struct(key)
            base_name = "Creating Type: " + self.template_types.get_base_name(key)
            args = self.get_stl_args(key)
            self.stl_struct_view.setPlainText(struct.format(*args))
            self.stl_title_struct.setText(base_name.format(*args))
        except:
            pass

    def get_stl_args(self, key):
        args = ()
        # collect text in the text boxes push into tuple
        for w in self.stl_widget.findChildren(QtWidgets.QLineEdit):
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
            # name line edit
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
