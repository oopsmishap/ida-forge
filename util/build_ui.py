#!/usr/bin/env python3
"""Generate Python wrappers from Qt Designer .ui files.

`form.ui` remains the source of truth. The generated Python is committed so the
plugin does not depend on runtime `.ui` loading inside IDA.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI_FILES = [
    (
        ROOT / "src/forge/features/structure_builder/form.ui",
        ROOT / "src/forge/features/structure_builder/ui_form.py",
    ),
    (
        ROOT / "src/forge/features/templated_types/form.ui",
        ROOT / "src/forge/features/templated_types/ui_form.py",
    ),
    (
        ROOT / "src/forge/menu/about.ui",
        ROOT / "src/forge/menu/ui_about.py",
    ),
]


def find_uic() -> list[str] | None:
    candidates = [
        ["pyside6-uic"],
        ["pyside2-uic"],
        ["pyuic5"],
        [sys.executable, "-m", "PySide6.scripts.uic"],
        [sys.executable, "-m", "PyQt5.uic.pyuic"],
    ]
    for cmd in candidates:
        probe = cmd[0]
        if probe == sys.executable:
            try:
                subprocess.run(cmd + ["--help"], check=True, capture_output=True)
                return cmd
            except Exception:
                continue
        if shutil.which(probe):
            return cmd
    return None


def build_one(uic_cmd: list[str], src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        uic_cmd + [str(src)],
        check=True,
        capture_output=True,
        text=True,
    )
    content = result.stdout
    content = re.sub(
        r"from PySide6\.QtCore import \([\s\S]*?\)\n"
        r"from PySide6\.QtGui import \([\s\S]*?\)\n"
        r"from PySide6\.QtWidgets import \([\s\S]*?\)\n",
        "from forge.util.qt import QtCore, QtGui, QtWidgets\n\n"
        "QCoreApplication = QtCore.QCoreApplication\n"
        "QMetaObject = QtCore.QMetaObject\n"
        "QPoint = QtCore.QPoint\n"
        "QRect = QtCore.QRect\n"
        "QSize = QtCore.QSize\n"
        "Qt = QtCore.Qt\n"
        "QAction = QtGui.QAction\n"
        "QBrush = QtGui.QBrush\n"
        "QColor = QtGui.QColor\n"
        "QConicalGradient = QtGui.QConicalGradient\n"
        "QCursor = QtGui.QCursor\n"
        "QFont = QtGui.QFont\n"
        "QFontDatabase = QtGui.QFontDatabase\n"
        "QGradient = QtGui.QGradient\n"
        "QIcon = QtGui.QIcon\n"
        "QImage = QtGui.QImage\n"
        "QKeySequence = QtGui.QKeySequence\n"
        "QLinearGradient = QtGui.QLinearGradient\n"
        "QPainter = QtGui.QPainter\n"
        "QPalette = QtGui.QPalette\n"
        "QPixmap = QtGui.QPixmap\n"
        "QRadialGradient = QtGui.QRadialGradient\n"
        "QTransform = QtGui.QTransform\n"
        "QApplication = QtWidgets.QApplication\n"
        "QFrame = QtWidgets.QFrame\n"
        "QDialog = QtWidgets.QDialog\n"
        "QFrame = QtWidgets.QFrame\n"
        "QGridLayout = QtWidgets.QGridLayout\n"
        "QHBoxLayout = QtWidgets.QHBoxLayout\n"
        "QHeaderView = QtWidgets.QHeaderView\n"
        "QLabel = QtWidgets.QLabel\n"
        "QLayout = QtWidgets.QLayout\n"
        "QLineEdit = QtWidgets.QLineEdit\n"
        "QListWidget = QtWidgets.QListWidget\n"
        "QListWidgetItem = QtWidgets.QListWidgetItem\n"
        "QPushButton = QtWidgets.QPushButton\n"
        "QSizePolicy = QtWidgets.QSizePolicy\n"
        "QSpacerItem = QtWidgets.QSpacerItem\n"
        "QTableWidget = QtWidgets.QTableWidget\n"
        "QTableWidgetItem = QtWidgets.QTableWidgetItem\n"
        "QTextEdit = QtWidgets.QTextEdit\n"
        "QVBoxLayout = QtWidgets.QVBoxLayout\n"
        "QWidget = QtWidgets.QWidget\n",
        content,
        count=1,
    )
    content = re.sub(
        r"from PyQt5 import QtCore, QtGui, QtWidgets\n",
        "from forge.util.qt import QtCore, QtGui, QtWidgets\n",
        content,
        count=1,
    )
    dst.write_text(content, encoding="utf-8")


def main() -> int:
    uic_cmd = find_uic()
    if uic_cmd is None:
        print(
            "No Qt UI compiler found. Install one of: pyside6-uic, pyside2-uic, pyuic5, "
            "or a Python package exposing PySide6.scripts.uic / PyQt5.uic.pyuic.",
            file=sys.stderr,
        )
        return 1

    print(f"Using UI compiler: {' '.join(uic_cmd)}")
    for src, dst in UI_FILES:
        print(f"Generating {dst.relative_to(ROOT)} from {src.relative_to(ROOT)}")
        build_one(uic_cmd, src, dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
