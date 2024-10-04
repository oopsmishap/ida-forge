from typing import Dict

import ida_hexrays

from forge.util.logging import *
from forge.util.singleton import Singleton


class HexRaysHook(ida_hexrays.Hexrays_Hooks):
    name: str = None
    """
    Base class for implementing Hex-Rays hooks.
    """

    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)


@Singleton
class HexRaysHookManager:
    """
    A manager for registering and unregistering Hex-Rays hooks.
    """

    def __init__(self):
        self._hooks: Dict[str, HexRaysHook] = {}
        # register all HexRaysHook subclasses

    def register(self, hook: HexRaysHook) -> None:
        """
        Registers a Hex-Rays hook.

        :param hook: The hook to register.
        """
        self._hooks[hook.name] = hook

    def initialize(self):
        """
        Initializes the Hex-Rays hook manager.
        """
        for hook_name, hook in self._hooks.items():
            log_debug(f"Hooked handler: {hook_name}")
            hook.hook()
        log_debug("Initialized Hex-Rays hook manager")

    def finalize(self):
        """
        Finalizes the Hex-Rays hook manager.
        """
        for hook_name, hook in self._hooks.items():
            hook.unhook()
            log_debug(f"Unhooked handler: {hook_name}")

    def disable(self, hook_name: str) -> None:
        """
        Disables a hook.

        :param hook_name: The name of the hook to disable.
        """
        hook = self._hooks[hook_name]
        hook.unhook()
        log_debug(f"Disabled handler: {hook_name}")

    def enable(self, hook_name: str) -> None:
        """
        Enables a hook.

        :param hook_name: The name of the hook to enable.
        """
        hook = self._hooks[hook_name]
        hook.hook()
        log_debug(f"Enabled handler: {hook_name}")


def register_hook(hook) -> None:
    """
    Registers a Hex-Rays hook with the hook manager.

    :param hook: The hook to register.
    """
    hook_manager = HexRaysHookManager.get()
    instance = hook()
    hook_manager.register(instance)
    log_debug(f"Registered hook: {hook.name}")
