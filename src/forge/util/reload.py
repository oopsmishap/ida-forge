# https://github.com/OALabs/hashdb-ida/blob/d2aae6fdb24b62096d02729795d3b18a573fa53e/src/hashdb/utilities/reload.py
import sys
import importlib
from types import ModuleType


def reload_module(module: ModuleType):
    """
    Reloads a given module.

    :param module: The module to reload.
    """
    importlib.reload(module)


def recursive_reload(module: ModuleType):
    """
    Recursively reloads a module and its submodules.

    :param module: The module to recursively reload.
    """
    module_name = module.__name__
    module_names = [name for name in sys.modules.keys() if name.startswith(module_name)]

    for name in module_names:
        reload_module(sys.modules[name])
