from forge.api import cache
from forge.api.hooks import HexRaysHookManager
from forge.api.ui_actions import UIActionManager
from forge.feature_manager import FeatureManager
from forge.menu import load_menu_modules
from forge.util.logging import log_debug


class ForgeCore:
    def __init__(self):
        """Create the plugin core and its shared managers."""
        self._feature_manager = FeatureManager()
        self._ui_action_manager = UIActionManager.get()
        self._hook_manager = HexRaysHookManager.get()

    def load(self):
        """Initialize plugin state and register actions/hooks."""
        log_debug("Loading Forge")
        cache.initialize_cache()
        self._feature_manager.load_features()
        self._load_menu()
        self._ui_action_manager.initialize()
        self._hook_manager.initialize()

    def show_menu(self) -> bool:
        """Attach registered actions to IDA's menu bar when the UI is ready."""
        return self._ui_action_manager.show_menu()

    def unload(self) -> None:
        """Unregister UI actions and hooks."""
        log_debug("Unloading Forge")
        self._ui_action_manager.finalize()
        self._hook_manager.finalize()

    @staticmethod
    def _load_menu() -> None:
        """Import menu modules so their actions register with the action manager."""
        load_menu_modules()
