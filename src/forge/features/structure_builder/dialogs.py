from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays
import ida_kernwin
import idaapi

from forge.api.ui import Choose
from forge.util.logging import log_warning
from forge.util.qt import QtWidgets


@dataclass
class MemberEditorValues:
    offset: int
    type_name: str
    name: str
    comment: str
    enabled: bool
    is_array: bool


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
