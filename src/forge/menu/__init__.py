"""Helpers for loading Forge menu modules."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from types import ModuleType


def load_menu_modules() -> list[ModuleType]:
    """Import every menu module in this package and return the loaded modules."""
    menu_root = Path(__file__).resolve().parent
    package_name = __name__
    loaded_modules: list[ModuleType] = []

    for module_info in pkgutil.iter_modules([str(menu_root)]):
        loaded_modules.append(importlib.import_module(f"{package_name}.{module_info.name}"))

    return loaded_modules
