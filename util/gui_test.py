import json
import os
from PyQt5.QtGui import QColor, QPainter, QBrush
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QColorDialog,
    QGroupBox,
    QHBoxLayout,
    QSizePolicy,
)


class QColorEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, QColor):
            return {"__QColor__": True, "rgba": obj.rgba()}
        return super().default(obj)


def qcolor_decoder(obj):
    if "__QColor__" in obj:
        color = QColor()
        color.setRgba(obj["rgba"])
        return color
    return obj


class ColorButton(QPushButton):
    def __init__(self, color, key, data):
        super().__init__()
        self.color = color
        self.key = key
        self.data = data
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.clicked.connect(self.choose_color)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setBrush(QBrush(self.color))
        painter.drawRect(0, 0, self.width(), self.height())

    def choose_color(self):
        new_color = QColorDialog.getColor(self.color)
        if new_color.isValid():
            self.color = new_color
            self.data[self.key] = new_color
            self.update()


def build_ui_from_dict(data):
    def add_widgets(layout, data):
        for key, value in data.items():
            if isinstance(value, bool):
                checkbox = QCheckBox(key)
                checkbox.setChecked(value)
                checkbox.stateChanged.connect(
                    lambda state, key=key: data.__setitem__(key, bool(state))
                )
                layout.addWidget(checkbox)
            elif isinstance(value, str):
                label = QLabel(key)
                edit = QLineEdit(value)
                edit.textChanged.connect(
                    lambda text, key=key: data.__setitem__(key, text)
                )
                layout.addWidget(label)
                layout.addWidget(edit)
            elif isinstance(value, dict):
                group_box = QGroupBox(key)
                group_box_layout = QVBoxLayout()
                group_box.setLayout(group_box_layout)
                add_widgets(group_box_layout, value)
                layout.addWidget(group_box)
            elif isinstance(value, QColor):
                color_layout = QHBoxLayout()
                label = QLabel(key)
                color_button = ColorButton(value, key, data)
                color_layout.addWidget(label)
                color_layout.addWidget(color_button)
                color_layout.addStretch()
                layout.addLayout(color_layout)

    window = QWidget()
    layout = QVBoxLayout()
    add_widgets(layout, data)

    save_button = QPushButton("Save")
    save_button.clicked.connect(lambda: save_and_close(data, window))
    cancel_button = QPushButton("Cancel")
    cancel_button.clicked.connect(window.close)
    button_layout = QHBoxLayout()
    button_layout.addWidget(save_button)
    button_layout.addWidget(cancel_button)
    layout.addLayout(button_layout)

    window.setLayout(layout)
    window.show()
    return window


def save_and_close(data, window):
    save_data_to_file(data)
    window.close()


def save_data_to_file(data):
    with open("data.json", "w") as f:
        json.dump(data, f, cls=QColorEncoder)


def load_data_from_file(filename: str, default_data: dict) -> dict:
    def validate_and_update(d: dict, default: dict):
        if not isinstance(d, dict) or not isinstance(default, dict):
            raise ValueError("The provided data must be a dictionary.")
        for key in d:
            if key not in default:
                raise KeyError(f"Invalid key '{key}' found in the loaded data.")
            if isinstance(d[key], dict):
                validate_and_update(d[key], default[key])
        default.update(d)

    if os.path.exists(filename):
        with open(filename, "r") as f:
            loaded_data = json.load(f, object_hook=qcolor_decoder)
            validate_and_update(loaded_data, default_data)
    return default_data


# Example usage
default_data = {
    "enabled": True,
    "show_structure_form_hotkey": "Alt+Shift+F9",
    "shallow_scan_hotkey": "Alt+S",
    "deep_scan_hotkey": "Shift+Alt+S",
    "form": {
        "origin_color": QColor("#006699"),
        "disabled_color": QColor("#999999"),
        "collision": {
            "foreground_color": QColor("#F0DB2B"),
            "background_color": QColor("#CC4B4B"),
        },
    },
}


def Start():
    data = load_data_from_file("data.json", default_data)
    ui = build_ui_from_dict(data)
    ui.show()


if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)
    window = Start()
    app.exec_()
