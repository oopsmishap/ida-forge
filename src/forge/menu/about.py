# TODO: as this is not a feature menu item it needs to be refactored to load manually, benefit
#       is that I can force the menu item to be at the bottom of the menu

import os

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QLabel, QGridLayout, QWidget, QDialog, QVBoxLayout
from PyQt5.QtGui import QPixmap, QIcon

from forge.api.ui_actions import UIMenuAction, register_action
from forge.plugin import *


class AboutWindow(QDialog):
    def __init__(self):
        super().__init__()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        img_path = os.path.join(script_dir, "..", "img")
        about_img_path = os.path.abspath(os.path.join(img_path, "forge_256px.png"))
        about_icon_path = os.path.abspath(os.path.join(img_path, "forge_64px.png"))

        forge_icon = QIcon(about_icon_path)
        self.setWindowTitle("About Forge")
        self.setWindowIcon(forge_icon)
        self.setFixedSize(300, 375)

        layout = QVBoxLayout(self)

        forge_img = QPixmap(about_img_path)
        image_label = QLabel(self)
        image_label.resize(forge_img.width(), forge_img.height())
        image_label.setPixmap(forge_img)
        image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(image_label)

        # Create labels for plugin name, author, and version
        plugin_label = QLabel("Plugin Name:")
        author_label = QLabel("Author:")
        version_label = QLabel("Version:")

        # Create labels for plugin data (replace with your own data)
        plugin_name = QLabel(f"{PLUGIN_NAME}")
        author_name = QLabel(f"{AUTHOR}")
        version_num = QLabel(f"{VERSION_STRING}")

        # Create a grid layout with two columns and three rows
        grid_layout = QGridLayout()
        grid_layout.addWidget(
            plugin_label, 0, 0
        )  # add plugin name label to first column, first row
        grid_layout.addWidget(
            plugin_name, 0, 1
        )  # add plugin name label to second column, first row
        grid_layout.addWidget(
            author_label, 1, 0
        )  # add author label to first column, second row
        grid_layout.addWidget(
            author_name, 1, 1
        )  # add author label to second column, second row
        grid_layout.addWidget(
            version_label, 2, 0
        )  # add version label to first column, third row
        grid_layout.addWidget(
            version_num, 2, 1
        )  # add version label to second column, third row
        grid_layout.setAlignment(Qt.AlignCenter)

        grid_widget = QWidget()
        grid_widget.setLayout(grid_layout)

        layout.addWidget(grid_widget)

        self.show()


@register_action
class AboutAction(UIMenuAction):
    name = "About"
    tooltip = "Show the about dialogue"

    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        AboutWindow().exec_()
        return 0
