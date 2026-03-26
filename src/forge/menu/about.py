from pathlib import Path

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QDialog, QGridLayout, QLabel, QVBoxLayout, QWidget

from forge.api.ui_actions import UIMenuAction, register_action
from forge.plugin import AUTHOR, PLUGIN_NAME, VERSION_STRING


class AboutWindow(QDialog):
    def __init__(self):
        super().__init__()
        img_path = Path(__file__).resolve().parent.parent / "img"
        about_img_path = img_path / "forge_256px.png"
        about_icon_path = img_path / "forge_64px.png"

        forge_icon = QIcon(str(about_icon_path))
        self.setWindowTitle("About Forge")
        self.setWindowIcon(forge_icon)
        self.setFixedSize(300, 375)

        layout = QVBoxLayout(self)

        forge_img = QPixmap(str(about_img_path))
        image_label = QLabel(self)
        image_label.resize(forge_img.width(), forge_img.height())
        image_label.setPixmap(forge_img)
        image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(image_label)

        plugin_label = QLabel("Plugin Name:")
        author_label = QLabel("Author:")
        version_label = QLabel("Version:")

        plugin_name = QLabel(f"{PLUGIN_NAME}")
        author_name = QLabel(f"{AUTHOR}")
        version_num = QLabel(f"{VERSION_STRING}")

        grid_layout = QGridLayout()
        grid_layout.addWidget(plugin_label, 0, 0)
        grid_layout.addWidget(plugin_name, 0, 1)
        grid_layout.addWidget(author_label, 1, 0)
        grid_layout.addWidget(author_name, 1, 1)
        grid_layout.addWidget(version_label, 2, 0)
        grid_layout.addWidget(version_num, 2, 1)
        grid_layout.setAlignment(Qt.AlignCenter)

        grid_widget = QWidget()
        grid_widget.setLayout(grid_layout)

        layout.addWidget(grid_widget)

        self.show()


@register_action
class AboutAction(UIMenuAction):
    name = "About"
    tooltip = "Show the about dialogue"

    def activate(self, ctx):
        AboutWindow().exec_()
        return 0
