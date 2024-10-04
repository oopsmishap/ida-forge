# hot_reload.py
import idaapi
import importlib
import sys
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

PLUGIN_NAME = "Forge"

def unload_plugin():
    idaapi.terminate_plugin(PLUGIN_NAME)
    logger.debug("Plugin unloaded")

def load_plugin():
    importlib.invalidate_caches()
    importlib.import_module(PLUGIN_NAME)
    importlib.reload(sys.modules[PLUGIN_NAME])
    logger.debug("Plugin loaded")

def reload_plugin():
    unload_plugin()
    load_plugin()

if __name__ == "__main__":
    reload_plugin()