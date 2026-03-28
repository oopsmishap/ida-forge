from pathlib import Path

from forge.util.qt import QtCore, QtGui, QtWidgets, qt_exec

from forge.api.ui_actions import UIMenuAction, register_action
from forge.plugin import AUTHOR, PLUGIN_NAME, VERSION_STRING


class AboutWindow(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        img_path = Path(__file__).resolve().parent.parent / "img"
        about_img_path = img_path / "forge_256px.png"
        about_icon_path = img_path / "forge_64px.png"

        forge_icon = QtGui.QIcon(str(about_icon_path))
        self.setWindowTitle("About Forge")
        self.setWindowIcon(forge_icon)
        self.setFixedSize(300, 375)

        layout = QtWidgets.QVBoxLayout(self)

        forge_img = QtGui.QPixmap(str(about_img_path))
        image_label = QtWidgets.QLabel(self)
        image_label.resize(forge_img.width(), forge_img.height())
        image_label.setPixmap(forge_img)
        image_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(image_label)

        plugin_label = QtWidgets.QLabel("Plugin Name:")
        author_label = QtWidgets.QLabel("Author:")
        version_label = QtWidgets.QLabel("Version:")

        plugin_name = QtWidgets.QLabel(f"{PLUGIN_NAME}")
        author_name = QtWidgets.QLabel(f"{AUTHOR}")
        version_num = QtWidgets.QLabel(f"{VERSION_STRING}")

        grid_layout = QtWidgets.QGridLayout()
        grid_layout.addWidget(plugin_label, 0, 0)
        grid_layout.addWidget(plugin_name, 0, 1)
        grid_layout.addWidget(author_label, 1, 0)
        grid_layout.addWidget(author_name, 1, 1)
        grid_layout.addWidget(version_label, 2, 0)
        grid_layout.addWidget(version_num, 2, 1)
        grid_layout.setAlignment(QtCore.Qt.AlignCenter)

        grid_widget = QtWidgets.QWidget()
        grid_widget.setLayout(grid_layout)

        layout.addWidget(grid_widget)

        self.show()


@register_action
class AboutAction(UIMenuAction):
    name = "About"
    tooltip = "Show the about dialogue"

    def activate(self, ctx):
        qt_exec(AboutWindow())
        return 0
