import ida_hexrays
import ida_idaapi
from ida_idp import IDP_INTERFACE_VERSION

import forge
from forge.core import ForgeCore as Core
from forge.plugin import PLUGIN_COMMENT, PLUGIN_HELP
from forge.util.logging import *
from forge.util.versions import is_ida_version_supported, is_python_version_supported
from forge.util.reload import recursive_reload

global forge_plugin_instance
forge_plugin_instance = None

def PLUGIN_ENTRY():
    return ForgePlugin()


class ForgePlugin(ida_idaapi.plugin_t):
    """IDAPython plugin structure."""
    version: int = IDP_INTERFACE_VERSION
    flags: int = ida_idaapi.PLUGIN_KEEP
    comment: str = PLUGIN_COMMENT
    help: str = PLUGIN_HELP
    wanted_name: str = PLUGIN_NAME
    wanted_hotkey: str = ''

    _core: Core = None

    def init(self):
        global forge_plugin_instance
        if not is_python_version_supported():
            log_warning("Unsupported Python version")
            return ida_idaapi.PLUGIN_SKIP
        
        if not is_ida_version_supported():
            log_warning("Unsupported IDA version")
            return ida_idaapi.PLUGIN_SKIP

        if not ida_hexrays.init_hexrays_plugin():
            log_warning("Failed to initialize Hex-Rays SDK")
            return ida_idaapi.PLUGIN_SKIP
        
        recursive_reload(forge)
        self._core = Core()
        self._core.load()

        log_debug(f'{self.wanted_name} loaded successfully!')
        
        # Register the plugin instance globally
        forge_plugin_instance = self

        return ida_idaapi.PLUGIN_KEEP

    def run():
        log_warning(f'This plugin cannot be ran as a script')

    def term(self):
        self._core.unload()

    @property
    def core(self):
        """
        Makes the core instance accessible from within the global plugin instance.
        :return: The core instance.
        """
        return self._core
    
    def reload(self):
        """
        Hot-reloads the plugin.
        """
        log_debug(f'Reloading {self.wanted_name}')

        self._core.unload()
        del self._core

        recursive_reload(forge)

        from forge.core import ForgeCore as Core
        self._core = Core()
        self._core.load()

        log_debug(f'{self.wanted_name} reloaded successfully!')


