import ida_hexrays
import idaapi

from forge.api.hexrays import decompile, get_funcs_referencing_address, is_legal_type
from forge.api.scan_object import GlobalVariableObject, ObjectType, ScanObject
from forge.api.scanner import NewShallowScanVisitor, NewDeepScanVisitor
from forge.api.visitor import FunctionTouchVisitor
from forge.api.ui_actions import register_action, UIMenuAction, HexRaysPopupAction
from forge.util.logging import log_warning
from .config import config
from .form import structure_form


@register_action
class ShowStructureFormAction(UIMenuAction):
    name = "Structure Builder"
    hotkey = config["show_structure_form_hotkey"]
    tooltip = "Show the Structure Builder form"
    menu_path = ""  # Empty string means it will be a top-level menu item

    def activate(self, ctx):
        structure_form.show()
        return 0


class StructureBuilderAction(HexRaysPopupAction):
    def create_scan_object(
        self, cfunc: ida_hexrays.cfunc_t, ctree_item: ida_hexrays.ctree_item_t
    ):
        obj = ScanObject.create(cfunc, ctree_item)
        if obj and is_legal_type(obj.tinfo):
            return obj

    def check(self, hx_view: ida_hexrays.vdui_t):
        return self.create_scan_object(hx_view.cfunc, hx_view.item) is not None

    @staticmethod
    def _prepare_function(cfunc: ida_hexrays.cfunc_t) -> ida_hexrays.cfunc_t:
        FunctionTouchVisitor(cfunc).process()
        refreshed_cfunc = decompile(cfunc.entry_ea)
        return refreshed_cfunc or cfunc

    @staticmethod
    def _provenance_kind_for_object(obj: ScanObject) -> str:
        if obj.id == ObjectType.global_object:
            return "global_root"
        if obj.id in (ObjectType.structure_pointer, ObjectType.structure_reference):
            return "upward_resolved_root"
        return "confirmed_root"

    @staticmethod
    def _set_root_scan_provenance(
        obj: ScanObject,
        *,
        root_function_ea: int | None,
        has_multiple_roots: bool = False,
    ) -> None:
        structure = structure_form.current_structure
        if structure is None or structure.provenance.kind != "manual":
            return

        root_object_ea = None
        if obj.id == ObjectType.global_object:
            root_object_ea = getattr(obj, "object_ea", None)
        else:
            candidate_ea = getattr(obj, "ea", idaapi.BADADDR)
            if candidate_ea != idaapi.BADADDR:
                root_object_ea = candidate_ea

        structure.set_provenance(
            kind=StructureBuilderAction._provenance_kind_for_object(obj),
            root_object_name=getattr(obj, "name", None),
            root_object_ea=root_object_ea,
            root_function_ea=root_function_ea,
            has_multiple_roots=has_multiple_roots,
        )

    @staticmethod
    def _ensure_structure_selected() -> bool:
        if structure_form.current_structure is not None:
            return True

        structure_form.show()
        created_structure = structure_form.prompt_create_structure()
        if created_structure is not None:
            return True

        log_warning(
            "No structure selected.\nPlease select or create a structure first.",
            True,
        )
        return False


@register_action
class ShallowScanAction(StructureBuilderAction):
    name = "Shallow Scan"
    description = "Shallow Scan"
    hotkey = config["shallow_scan_hotkey"]

    def activate(self, ctx):
        if not self._ensure_structure_selected():
            return

        hx_view: ida_hexrays.vdui_t = ida_hexrays.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = structure_form.current_structure.main_offset

        obj = self.create_scan_object(cfunc, hx_view.item)
        if obj:
            self._set_root_scan_provenance(obj, root_function_ea=cfunc.entry_ea)
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

    @staticmethod
    def _clone_global_object(obj):
        cloned = GlobalVariableObject(obj.object_ea)
        cloned.name = obj.name
        cloned.tinfo = obj.tinfo
        return cloned

    def _scan_global_references(self, obj, origin):
        xref_functions = sorted(get_funcs_referencing_address(obj.object_ea))
        if not xref_functions:
            log_warning(
                f"No function references found for global {obj.name} @ {hex(obj.object_ea)}",
                True,
            )
            return

        self._set_root_scan_provenance(
            obj,
            root_function_ea=xref_functions[0] if len(xref_functions) == 1 else None,
            has_multiple_roots=len(xref_functions) > 1,
        )

        for func_ea in xref_functions:
            cfunc = decompile(func_ea)
            if cfunc is None:
                continue

            prepared_cfunc = self._prepare_function(cfunc)
            visitor = NewDeepScanVisitor(
                prepared_cfunc,
                origin,
                self._clone_global_object(obj),
                structure_form.current_structure,
            )
            visitor.process()

    def activate(self, ctx):
        if not self._ensure_structure_selected():
            return

        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = structure_form.current_structure.main_offset

        obj = self.create_scan_object(cfunc, hx_view.item)
        if obj:
            if obj.id == ObjectType.global_object:
                self._scan_global_references(obj, origin)
            else:
                prepared_cfunc = self._prepare_function(cfunc)
                self._set_root_scan_provenance(
                    obj,
                    root_function_ea=prepared_cfunc.entry_ea,
                )
                if prepared_cfunc.entry_ea == cfunc.entry_ea:
                    hx_view.refresh_view(True)
                visitor = NewDeepScanVisitor(
                    prepared_cfunc, origin, obj, structure_form.current_structure
                )
                visitor.process()
            structure_form.update_structure_fields()
