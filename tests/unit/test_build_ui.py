from __future__ import annotations

import subprocess

import pytest

import build_ui


def test_find_uic_prefers_installed_binary(monkeypatch):
    monkeypatch.setattr(
        build_ui.shutil,
        "which",
        lambda cmd: f"/tmp/{cmd}" if cmd == "pyside2-uic" else None,
    )

    assert build_ui.find_uic() == ["pyside2-uic"]


def test_build_one_rewrites_pyside6_imports(tmp_path, monkeypatch):
    source = tmp_path / "form.ui"
    source.write_text("<ui/>", encoding="utf-8")
    destination = tmp_path / "ui_form.py"
    generated = """
from PySide6.QtCore import (QCoreApplication, QRect)
from PySide6.QtGui import (QAction, QIcon)
from PySide6.QtWidgets import (QApplication, QWidget)

class Ui_Form(object):
    pass
""".lstrip()

    monkeypatch.setattr(
        build_ui.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=generated),
    )

    build_ui.build_one(["fake-uic"], source, destination)
    content = destination.read_text(encoding="utf-8")

    assert "from forge.util.qt import QtCore, QtGui, QtWidgets" in content
    assert "from PySide6" not in content
    assert "class Ui_Form(object):" in content
    assert content.count("QFrame = QtWidgets.QFrame") == 1


def test_build_one_rewrites_pyqt5_imports(tmp_path, monkeypatch):
    source = tmp_path / "form.ui"
    source.write_text("<ui/>", encoding="utf-8")
    destination = tmp_path / "ui_form.py"
    generated = """
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Form(object):
    pass
""".lstrip()

    monkeypatch.setattr(
        build_ui.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=generated),
    )

    build_ui.build_one(["fake-uic"], source, destination)
    content = destination.read_text(encoding="utf-8")

    assert "from forge.util.qt import QtCore, QtGui, QtWidgets" in content
    assert "from PyQt5" not in content


def test_main_returns_error_when_no_uic_is_available(monkeypatch, capsys):
    monkeypatch.setattr(build_ui, "find_uic", lambda: None)

    assert build_ui.main() == 1
    assert "No Qt UI compiler found" in capsys.readouterr().err



def test_find_uic_falls_back_to_python_module(monkeypatch):
    monkeypatch.setattr(build_ui.shutil, "which", lambda _cmd: None)

    def fake_run(cmd, check, capture_output):
        assert cmd[:3] == [build_ui.sys.executable, "-m", "PySide6.scripts.uic"]
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(build_ui.subprocess, "run", fake_run)

    assert build_ui.find_uic() == [build_ui.sys.executable, "-m", "PySide6.scripts.uic"]



def test_build_one_propagates_subprocess_errors(tmp_path, monkeypatch):
    source = tmp_path / "form.ui"
    source.write_text("<ui/>", encoding="utf-8")
    destination = tmp_path / "ui_form.py"

    def fail_run(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(build_ui.subprocess, "run", fail_run)

    with pytest.raises(subprocess.CalledProcessError):
        build_ui.build_one(["fake-uic"], source, destination)



def test_main_builds_all_registered_ui_files(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(build_ui, "find_uic", lambda: ["fake-uic"])
    monkeypatch.setattr(build_ui, "build_one", lambda cmd, src, dst: calls.append((tuple(cmd), src, dst)))

    assert build_ui.main() == 0
    assert len(calls) == len(build_ui.UI_FILES)
    assert all(call[0] == ("fake-uic",) for call in calls)
    assert "Generating" in capsys.readouterr().out
