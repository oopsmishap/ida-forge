"""Qt compatibility helpers for IDA versions using PyQt5 or PySide6."""

from __future__ import annotations

QT_BINDING: str

try:
    from PySide6 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PySide6"
    Signal = QtCore.Signal
except ImportError:
    from PyQt5 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PyQt5"
    Signal = QtCore.pyqtSignal


def qt_exec(widget, *args, **kwargs):
    """Call exec()/exec_() depending on the active Qt binding."""
    if hasattr(widget, "exec"):
        return widget.exec(*args, **kwargs)
    return widget.exec_(*args, **kwargs)
