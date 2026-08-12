
from forge.api.ui_actions import UIMenuAction, register_action

from .config import config


@register_action
class ShowStructureFormAction(UIMenuAction):
    name = "Templated Types"
    hotkey = config["show_form_hotkey"]
    tooltip = "Show the Templated Types form"
    menu_path = ""  # Empty string means it will be a top-level menu item

    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        # Local import: the form is Qt-based and only exists in GUI sessions;
        # keeping it out of module scope lets the headless forge_api facade
        # import this package without any Qt.
        from .form import templated_types_form

        templated_types_form.show()
        return 0
