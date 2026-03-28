"""Qt compatibility helpers for IDA versions using PyQt5 or PySide6."""

from __future__ import annotations

QT_BINDING: str

try:
    from PySide6 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PySide6"
    Signal = QtCore.Signal

    try:
        from PySide6.QtUiTools import QUiLoader
    except ImportError:
        QUiLoader = None

    def load_ui(path: str, parent=None):
        if QUiLoader is None:
            raise RuntimeError("Qt .ui loading is not available for this PySide6 build")

        file = QtCore.QFile(path)
        if not file.open(QtCore.QIODevice.ReadOnly):
            raise RuntimeError(f"Failed to open UI file: {path}")

        try:
            loader = QUiLoader()
            widget = loader.load(file, parent)
        finally:
            file.close()

        if widget is None:
            raise RuntimeError(f"Failed to load UI file: {path}")
        return widget

except ImportError:
    import PyQt5.QtCore as QtCore
    import PyQt5.QtGui as QtGui
    import PyQt5.QtWidgets as QtWidgets

    QT_BINDING = "PyQt5"
    Signal = QtCore.pyqtSignal

    try:
        import PyQt5.uic as uic
    except ImportError:
        uic = None

    def load_ui(path: str, parent=None):
        if uic is None:
            raise RuntimeError("Qt .ui loading is not available for this PyQt5 build")
        widget = uic.loadUi(path, parent)
        return widget if widget is not None else parent


def qt_exec(widget, *args, **kwargs):
    """Call exec()/exec_() depending on the active Qt binding."""
    if hasattr(widget, "exec"):
        return widget.exec(*args, **kwargs)
    return widget.exec_(*args, **kwargs)
