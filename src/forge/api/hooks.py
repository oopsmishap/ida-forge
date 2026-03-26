from __future__ import annotations

import ida_hexrays

from forge.util.logging import log_debug
from forge.util.singleton import Singleton


class HexRaysHook(ida_hexrays.Hexrays_Hooks):
    """Base class for Hex-Rays hooks registered by the plugin."""

    name: str = None

    def __init__(self):
        super().__init__()


@Singleton
class HexRaysHookManager:
    """
    A manager for registering and unregistering Hex-Rays hooks.
    """

    def __init__(self):
        self._hooks: dict[str, HexRaysHook] = {}

    def register(self, hook: HexRaysHook) -> None:
        """Register a Hex-Rays hook instance."""
        if not hook.name:
            raise ValueError("Hex-Rays hooks must define a name")
        self._hooks[hook.name] = hook

    def initialize(self):
        """Hook every registered Hex-Rays handler."""
        for hook_name, hook in self._hooks.items():
            log_debug(f"Hooked handler: {hook_name}")
            hook.hook()
        log_debug("Initialized Hex-Rays hook manager")

    def finalize(self):
        """Unhook every registered Hex-Rays handler."""
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


def register_hook(hook: type[HexRaysHook]) -> type[HexRaysHook]:
    """Decorator that instantiates and registers a Hex-Rays hook class."""
    hook_manager = HexRaysHookManager.get()
    instance = hook()
    hook_manager.register(instance)
    log_debug(f"Registered hook: {instance.name}")
    return hook
