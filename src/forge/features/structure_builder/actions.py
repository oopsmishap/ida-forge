import ida_hexrays

from forge.api.scan_object import ScanObject
from forge.api.scanner import NewShallowScanVisitor, NewDeepScanVisitor
from forge.api.visitor import FunctionTouchVisitor
from forge.api.ui_actions import register_action, UIMenuAction, HexRaysPopupAction
from forge.api.hexrays import is_legal_type
from forge.util.logging import *
from .config import config
from .form import structure_form


@register_action
class ShowStructureFormAction(UIMenuAction):
    name = "Structure Builder"
    hotkey = config["show_structure_form_hotkey"]
    tooltip = "Show the Structure Builder form"
    menu_path = ""  # Empty string means it will be a top-level menu item

    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        structure_form.show()
        return 0


class StructureBuilderAction(HexRaysPopupAction):
    def __init__(self):
        super().__init__()

    def create_scan_object(
        self, cfunc: ida_hexrays.cfunc_t, ctree_item: ida_hexrays.ctree_item_t
    ):
        obj = ScanObject.create(cfunc, ctree_item)
        if is_legal_type(obj.tinfo):
            return obj

    def check(self, hx_view: ida_hexrays.vdui_t):
        return structure_form.current_structure is not None


@register_action
class ShallowScanAction(StructureBuilderAction):
    name = "Shallow Scan"
    description = "Shallow Scan"
    hotkey = config["shallow_scan_hotkey"]

    def activate(self, ctx):
        if structure_form.current_structure is None:
            # TODO: Allow user to create a new structure instead of warnning them
            log_warning(
                "No structure selected!\n Please select a structure first within the structure builder form.",
                True,
            )
            return

        hx_view: ida_hexrays.vdui_t = ida_hexrays.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = structure_form.current_structure.main_offset

        obj = ScanObject.create(cfunc, hx_view.item)
        if obj:
            visitor = NewShallowScanVisitor(
                cfunc, origin, obj, structure_form.current_structure
            )
            visitor.process()
            structure_form.update_structure_fields()


@register_action
class DeepScanAction(StructureBuilderAction):
    name = "Deep Scan"
    description = "Deep Scan"
    hotkey = config["deep_scan_hotkey"]

    def activate(self, ctx):
        if structure_form.current_structure is None:
            # TODO: Allow user to create a new structure instead of warnning them
            log_warning(
                "No structure selected!\n Please select a structure first within the structure builder form.",
                True,
            )
            return

        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = structure_form.current_structure.main_offset

        obj = self.create_scan_object(cfunc, hx_view.item)
        if obj:
            if FunctionTouchVisitor(cfunc).process():
                hx_view.refresh_view(True)
            visitor = NewDeepScanVisitor(
                hx_view.cfunc, origin, obj, structure_form.current_structure
            )
            visitor.process()
            structure_form.update_structure_fields()
