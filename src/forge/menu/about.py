from pathlib import Path

from forge.util.qt import QtGui, QtWidgets, qt_exec

from forge.api.ui_actions import UIMenuAction, register_action
from forge.plugin import AUTHOR, PLUGIN_NAME, VERSION_STRING
from .ui_about import Ui_about_window


class AboutWindow(QtWidgets.QDialog, Ui_about_window):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        img_path = Path(__file__).resolve().parent.parent / "img"
        about_img_path = img_path / "forge_256px.png"
        about_icon_path = img_path / "forge_64px.png"

        forge_icon = QtGui.QIcon(str(about_icon_path))
        self.setWindowIcon(forge_icon)
        self.setFixedSize(300, 375)

        forge_img = QtGui.QPixmap(str(about_img_path))
        self.image_label.resize(forge_img.width(), forge_img.height())
        self.image_label.setPixmap(forge_img)

        self.plugin_name.setText(PLUGIN_NAME)
        self.author_name.setText(AUTHOR)
        self.version_num.setText(VERSION_STRING)

        self.show()


@register_action
class AboutAction(UIMenuAction):
    name = "About"
    tooltip = "Show the about dialogue"
    menu_path = "Actions"

    def activate(self, ctx):
        qt_exec(AboutWindow())
        return 0