
from forge.api.ui_actions import UIMenuAction, register_action

from .config import config
from .form import templated_types_form


@register_action
class ShowStructureFormAction(UIMenuAction):
    name = "Templated Types"
    hotkey = config["show_form_hotkey"]
    tooltip = "Show the Templated Types form"
    menu_path = ""  # Empty string means it will be a top-level menu item

    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        templated_types_form.show()
        return 0
