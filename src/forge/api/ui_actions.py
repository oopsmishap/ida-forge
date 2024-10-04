import re
from typing import List

import ida_hexrays
import ida_kernwin

from forge.api.ui import main_menu
from forge.util.singleton import Singleton
from forge.util.logging import *


@Singleton
class UIActionManager:
    """
    A singleton class to manage all actions in the plugin.
    """

    def __init__(self):
        """
        Constructs a new UIActionManager object.
        """
        self._actions: List[UIAction] = []
        self._popup_actions: List[HexraysPopupRequestHandler] = []
        self._menu_actions: List[UIMenuAction] = []
        self._parent_menu = main_menu()
        self._main_menu_created = False
        self._main_menu = None

    def register(self, action):
        """
        Registers the specified action.

        :param action: The action to register.
        """
        if isinstance(action, UIMenuAction):
            self._menu_actions.append(action)
        elif isinstance(action, HexRaysPopupAction):
            self._actions.append(action)
            self._popup_actions.append(HexraysPopupRequestHandler(action))
        elif isinstance(action, UIAction):
            self._actions.append(action)
        else:
            raise TypeError(f"Unsupported action type: {type(action)}")

    def initialize(self):
        """
        Initializes all actions registered with the manager.
        """
        # register all actions with IDA
        for action in self._actions:
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    action.name, action.description, action, action.hotkey
                )
            )
        # install hexrays hooks for popup actions
        for popup_action in self._popup_actions:
            popup_action.hook()
        # register all menu actions with IDA
        for menu_action in self._menu_actions:
            # if this is the first menu action, create the main menu
            if not self._main_menu_created:
                self._main_menu = self._parent_menu.addMenu(PLUGIN_NAME)
                self._main_menu_created = True
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    menu_action.id,
                    menu_action.name,
                    menu_action,
                    menu_action.hotkey,
                    menu_action.tooltip,
                )
            )
            ida_kernwin.attach_action_to_menu(menu_action.menu_path, menu_action.id, 0)
        log_debug("Initialized Hex-Rays action manager")

    def finalize(self):
        """
        Finalizes all actions registered with the manager.
        """
        # unregister all actions with IDA
        [ida_kernwin.unregister_action(action.name) for action in self._actions]
        [popup_action.unhook() for popup_action in self._popup_actions]
        if self._main_menu_created:
            [
                ida_kernwin.unregister_action(menu_action.id)
                for menu_action in self._menu_actions
            ]
            self._parent_menu.removeAction(self._main_menu.menuAction())


def register_action(action):
    """
    Registers the specified action with the action manager.

    :param action: The action to register.
    """
    action_manager = UIActionManager.get()
    instance = action()
    action_manager.register(instance)
    log_debug(f"Registered action: {instance.name}")


class HexraysPopupRequestHandler(ida_hexrays.Hexrays_Hooks):
    """
    A class to add an action to the Hex-Rays popup menu.
    """

    def __init__(self, action):
        """
        Constructs a new HexraysPopupRequestHandler object.

        :param action: The action to add to the popup menu.
        """
        super().__init__()
        self._action = action

    def populating_popup(self, widget, popup_handle, hx_view):
        """
        Populates the specified popup menu.

        :param widget: The widget to attach the action to.
        :param popup_handle: The handle to the popup menu.
        :param hx_view: The hexrays_widget_t object.
        :return: 0.
        """
        # check if the action should be added to the popup menu
        if self._action.check(hx_view):
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle, self._action.name, None
            )
        return 0


class UIMenuAction(ida_kernwin.action_handler_t):
    name: str = None
    tooltip: str = None
    menu_path: str = None
    hotkey: str = None

    def __init__(self):
        super().__init__()
        self.menu_path = (
            f"{PLUGIN_NAME}/{self.menu_path}" if self.menu_path else f"{PLUGIN_NAME}"
        )
        # prepend the plugin name to the action id and replace any non-alphanumeric characters with underscores
        self.id = f"{PLUGIN_NAME}:{re.sub('[^A-Za-z0-9]+', '_', self.name)}"
        log_debug(f"{self.name} loaded! id: {self.id}, menu_path: {self.menu_path}")

    def activate(self, ctx):
        raise NotImplementedError()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB


class UIAction(ida_kernwin.action_handler_t):
    """
    Convenience wrapper for creating custom IDA _actions. Inherits from ida_kernwin.action_handler_t and
    adds a name property for easy registration with the UIActionManager.

    This is an abstract base class that must be subclassed to implement the activate, check, and update methods.
    """

    description: str = None
    hotkey: str = None

    def __init__(self):
        """
        Initializes an instance of the UIAction class.
        """
        super().__init__()
        log_debug(
            f"{self.__class__.__name__} loaded! description: {self.description}, hotkey: {self.hotkey}"
        )

    def activate(self, ctx):
        """
        Activate an action. This function implements the menu behavior of an action. It is called when the action
        is triggered, from a menu, from a popup menu, from the toolbar, or programmatically.

        :param ctx: ida_kernwin.action_update_ctx_t (C++ only).
        :return: Non-zero value: all IDA windows will be refreshed.
        """
        raise NotImplementedError()

    def check(self, hx_view: ida_hexrays.vdui_t):
        """
        Check whether the action should be available.

        :param hx_view: ida_hexrays.vdui_t: HexRays view object.
        :return: True if the action should be available, False otherwise.
        """
        raise NotImplementedError()

    def update(self, ctx):
        """
        Update an action. This is called when the context of the UI changed, and we need to let the action update some
        of its properties if needed (label, icon, ...). In addition, this lets IDA know whether the action is enabled,
        and when it should be queried for availability again. Note: This callback is not meant to change anything in
        the application's state, except by calling one (or many) of the "update_action_*()" functions on this very
        action.

        :param ctx: ida_kernwin.action_update_ctx_t (C++ only).
        :return: UIAction name prefixed with plugin name.
        """
        raise NotImplementedError()

    @property
    def name(self):
        """
        Returns the name of the action.

        :return: The name of the action prefixed with the plugin name.
        """
        return f"{PLUGIN_NAME}:{self.__class__.__name__}"


class HexRaysXrefAction(UIAction):
    """
    Wrapper around UIAction. Represents an action that can be added to the context menu after right-clicking in the
    Hex-Rays window. Has a `check` method that should tell whether the action should be added to the context menu
    when different members are right-clicked. Children of this class can also be fired by a hotkey without right-clicking
    if one is provided in the `hotkey` static member.
    """

    def __init__(self):
        """
        Initializes an instance of the HexRaysXrefAction class.
        """
        super().__init__()

    def activate(self, ctx):
        """
        Activates the action. This method is called when the action is triggered, from a menu, from a popup menu,
        from the toolbar, or programmatically.

        :param ctx: ida_kernwin.action_update_ctx_t (C++ only).
        """
        raise NotImplementedError()

    def check(self, hx_view: ida_hexrays.vdui_t):
        """
        Checks whether the action should be added to the context menu when different members are right-clicked.

        :param hx_view: ida_hexrays.vdui_t: HexRays view object.
        :return: True if the action should be added to the context menu, False otherwise.
        """
        raise NotImplementedError()

    def update(self, ctx):
        """
        Updates the action. This method is called when the context of the UI changed, and we need to let the action
        update some of its properties if needed (label, icon, ...). In addition, this lets IDA know whether the action
        is enabled, and when it should be queried for availability again. Note: This callback is not meant to change
        anything in the application's state, except by calling one (or many) of the "update_action_*()" functions on
        this very action.

        :param ctx: ida_kernwin.action_update_ctx_t (C++ only).
        :return: A value that specifies whether the action is enabled or disabled for the current widget. This value
            can be one of `ida_kernwin.AST_ENABLE`, `ida_kernwin.AST_ENABLE_FOR_WIDGET`, or
            `ida_kernwin.AST_DISABLE_FOR_WIDGET`.
        """
        if (
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE
            or ctx.widget_type == ida_kernwin.BWN_STRUCTS
        ):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class HexRaysPopupAction(UIAction):
    """
    Wrapper around UIAction. Represents an action that can be added to the context menu after right-clicking in the
    Hex-Rays window. Has a `check` method that should tell whether the action should be added to the context menu
    when different members are right-clicked. Children of this class can also be fired by a hotkey without right-clicking
    if one is provided in the `hotkey` static member.
    """

    def __init__(self):
        """
        Initializes an instance of the HexRaysPopupAction class.
        """
        super().__init__()

    def activate(self, ctx):
        """
        Activates the action. This method is called when the action is triggered, from a menu, from a popup menu,
        from the toolbar, or programmatically.

        :param ctx: ida_kernwin.action_update_ctx_t (C++ only).
        """
        raise NotImplementedError()

    def check(self, hx_view: ida_hexrays.vdui_t):
        """
        Checks whether the action should be added to the context menu when different members are right-clicked.

        :param hx_view: ida_hexrays.vdui_t: HexRays view object.
        :return: True if the action should be added to the context menu, False otherwise.
        """
        raise NotImplementedError()

    def update(self, ctx):
        """
        Updates the action. This method is called when the context of the UI changed, and we need to let the action
        update some of its properties if needed (label, icon, ...). In addition, this lets IDA know whether the action
        is enabled, and when it should be queried for availability again. Note: This callback is not meant to change
        anything in the application's state, except by calling one (or many) of the "update_action_*()" functions on
        this very action.

        :param ctx: ida_kernwin.action_update_ctx_t (C++ only).
        :return: A value that specifies whether the action is enabled or disabled for the current widget. This value
            can be one of `ida_kernwin.AST_ENABLE`, `ida_kernwin.AST_ENABLE_FOR_WIDGET`, or
            `ida_kernwin.AST_DISABLE_FOR_WIDGET`.
        """
        return (
            ida_kernwin.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE
            else ida_kernwin.AST_DISABLE_FOR_WIDGET
        )
