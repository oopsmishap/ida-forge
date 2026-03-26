from __future__ import annotations

import re
from typing import TypeVar

import ida_hexrays
import ida_kernwin

from forge.plugin import PLUGIN_ACTIONS_PREFIX, PLUGIN_NAME
from forge.util.logging import log_debug, log_warning
from forge.util.singleton import Singleton


TAction = TypeVar("TAction")


@Singleton
class UIActionManager:
    """Manage plugin actions, popup hooks, and top-level menu attachment."""

    def __init__(self):
        self._actions: list[UIAction] = []
        self._popup_actions: list[HexraysPopupRequestHandler] = []
        self._menu_actions: list[UIMenuAction] = []
        self._main_menu_name = f"{PLUGIN_ACTIONS_PREFIX}_menu"
        self._main_menu_created = False
        self._attached_menu_actions: set[str] = set()

    def register(self, action: UIAction | UIMenuAction) -> None:
        """Register an action instance with the appropriate internal list."""
        if isinstance(action, UIMenuAction):
            self._menu_actions.append(action)
        elif isinstance(action, HexRaysPopupAction):
            self._actions.append(action)
            self._popup_actions.append(HexraysPopupRequestHandler(action))
        elif isinstance(action, UIAction):
            self._actions.append(action)
        else:
            raise TypeError(f"Unsupported action type: {type(action)}")

    def initialize(self) -> None:
        """Register actions with IDA and install popup hooks."""
        for action in self._actions:
            self._register_action(
                ida_kernwin.action_desc_t(
                    action.name,
                    action.description,
                    action,
                    action.hotkey,
                )
            )

        for popup_action in self._popup_actions:
            popup_action.hook()

        for menu_action in self._menu_actions:
            self._register_action(
                ida_kernwin.action_desc_t(
                    menu_action.id,
                    menu_action.name,
                    menu_action,
                    menu_action.hotkey,
                    menu_action.tooltip,
                )
            )

        log_debug("Initialized UI actions")

    def show_menu(self) -> bool:
        """Create the top-level menu and attach registered menu actions."""
        if not self._ensure_main_menu():
            return False

        for menu_action in self._menu_actions:
            self._attach_menu_action(menu_action)

        return True

    def finalize(self) -> None:
        """Unregister actions and remove the plugin menu."""
        for action in self._actions:
            ida_kernwin.unregister_action(action.name)

        for popup_action in self._popup_actions:
            popup_action.unhook()

        for menu_action in self._menu_actions:
            ida_kernwin.unregister_action(menu_action.id)

        if self._main_menu_created:
            ida_kernwin.delete_menu(self._main_menu_name)

        self._main_menu_created = False
        self._attached_menu_actions.clear()

    @staticmethod
    def _register_action(action_desc: ida_kernwin.action_desc_t) -> None:
        """Register a single action descriptor with IDA."""
        ida_kernwin.register_action(action_desc)

    def _ensure_main_menu(self) -> bool:
        """Ensure the plugin's top-level menu exists."""
        if self._main_menu_created:
            return True

        try:
            self._main_menu_created = ida_kernwin.create_menu(
                self._main_menu_name,
                PLUGIN_NAME,
            )
        except Exception as e:
            log_warning(f"Could not create menu '{PLUGIN_NAME}': {e}")
            return False

        if not self._main_menu_created:
            log_warning(f"IDA rejected creation of menu '{PLUGIN_NAME}'")
            return False

        return True

    def _attach_menu_action(self, menu_action: UIMenuAction) -> None:
        """Attach a registered action to the plugin menu once."""
        if menu_action.id in self._attached_menu_actions:
            return

        try:
            attached = ida_kernwin.attach_action_to_menu(
                menu_action.menu_path,
                menu_action.id,
                0,
            )
        except Exception as e:
            log_warning(f"Could not attach action {menu_action.id}: {e}")
            return

        if not attached:
            log_warning(f"IDA rejected menu attachment: {menu_action.id}")
            return

        self._attached_menu_actions.add(menu_action.id)


def register_action(action: type[TAction]) -> type[TAction]:
    """Decorator that instantiates and registers an action class."""
    action_manager = UIActionManager.get()
    instance = action()
    action_manager.register(instance)
    log_debug(f"Registered action: {instance.name}")
    return action


class HexraysPopupRequestHandler(ida_hexrays.Hexrays_Hooks):
    """Attach a registered action to the Hex-Rays popup menu."""

    def __init__(self, action: "HexRaysPopupAction"):
        super().__init__()
        self._action = action

    def populating_popup(self, widget, popup_handle, hx_view):
        if self._action.check(hx_view):
            ida_kernwin.attach_action_to_popup(
                widget,
                popup_handle,
                self._action.name,
                None,
            )
        return 0


class UIMenuAction(ida_kernwin.action_handler_t):
    """Base class for actions shown under the Forge top-level menu."""

    name: str = None
    tooltip: str = None
    menu_path: str = None
    hotkey: str = None

    def __init__(self):
        super().__init__()
        self.menu_path = (
            f"{PLUGIN_NAME}/{self.menu_path}" if self.menu_path else f"{PLUGIN_NAME}"
        )
        self.id = f"{PLUGIN_NAME}:{re.sub('[^A-Za-z0-9]+', '_', self.name)}"

    def activate(self, ctx):
        raise NotImplementedError()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB


class UIAction(ida_kernwin.action_handler_t):
    """Base class for reusable IDA actions."""

    description: str = None
    hotkey: str = None

    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        raise NotImplementedError()

    def check(self, hx_view: ida_hexrays.vdui_t):
        raise NotImplementedError()

    def update(self, ctx):
        raise NotImplementedError()

    @property
    def name(self) -> str:
        return f"{PLUGIN_NAME}:{self.__class__.__name__}"


class HexRaysXrefAction(UIAction):
    """Action available in pseudocode and structure windows."""

    def update(self, ctx):
        if ctx.widget_type in (ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_STRUCTS):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class HexRaysPopupAction(UIAction):
    """Action available from the Hex-Rays right-click popup."""

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE
            else ida_kernwin.AST_DISABLE_FOR_WIDGET
        )
