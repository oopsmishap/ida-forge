# standalone ui helper classes / functions

import ida_kernwin
from PyQt5 import QtWidgets, QtCore


class Choose(ida_kernwin.Choose):
    def __init__(self, items, title, cols, icon=-1):
        super().__init__(title, cols, flags=ida_kernwin.Choose.CH_MODAL, icon=icon)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class ClickableQLabel(QtWidgets.QLabel):
    clicked = QtCore.pyqtSignal()
    doubleClicked = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QLabel.__init__(self, parent)

    def mousePressEvent(self, ev):
        self.clicked.emit()

    def mouseDoubleClickEvent(self, ev):
        self.doubleClicked.emit()


class EnterPressQTableWidget(QtWidgets.QTableWidget):
    cellEnterPressed = QtCore.pyqtSignal(int, int)

    def __init__(self, parent=None):
        super(EnterPressQTableWidget, self).__init__(parent)

    def keyPressEvent(self, event):
        if event.key() in [QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter]:
            row = self.currentRow()
            column = self.currentColumn()
            if row >= 0 and column >= 0:
                self.cellEnterPressed.emit(row, column)
                return
        super(EnterPressQTableWidget, self).keyPressEvent(event)


def main_window():
    tform = ida_kernwin.get_current_widget()

    if not tform:
        tform = ida_kernwin.find_widget("Output window")

    widget = ida_kernwin.PluginForm.FormToPyQtWidget(tform)
    window = widget.window()
    return window


def main_menu():
    win = main_window()
    return win.findChild(QtWidgets.QMenuBar)


def set_row_background_color(table, row, color):
    for i in range(table.columnCount()):
        table.item(row, i).setBackground(color)


def set_row_foreground_color(table, row, color):
    for i in range(table.columnCount()):
        table.item(row, i).setForeground(color)
