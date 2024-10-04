import importlib
import os
from pathlib import Path

from forge.api import cache
from forge.api.ui_actions import UIActionManager
from forge.api.hooks import HexRaysHookManager
from forge.feature_manager import FeatureManager
from forge.util.logging import *


class ForgeCore:
    def __init__(self):
        log_debug("Initializing Forge")
        self._menu_root = Path(__file__).parent / "menu"
        self._loaded_features = []
        self._feature_manager = FeatureManager()

    def load(self):
        log_debug("Loading Forge")
        cache.initialize_cache()
        self._feature_manager.load_features()
        UIActionManager.get().initialize()
        HexRaysHookManager.get().initialize()
        self._load_menu()

    def unload(self):
        log_debug("Unloading Forge")
        UIActionManager.get().finalize()
        HexRaysHookManager.get().finalize()

    def _load_menu(self):
        # TODO: This is a bit of a hack, we should probably just have a
        #       menu.py file that we import and then register the menu
        log_debug(f"Loading menu items from: {self._menu_root}")
        for item in os.listdir(self._menu_root):
            feature_path = self._menu_root / item
            if not os.path.isdir(feature_path):
                module_name = f"forge.menu.{item[:-3]}"
                log_debug(f"Loading menu item: {module_name}")
                importlib.import_module(module_name)
