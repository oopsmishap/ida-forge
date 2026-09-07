from __future__ import annotations

import ida_hexrays
import ida_idaapi
import ida_kernwin

from forge.api.hexrays import decompile, get_funcs_referencing_address, is_legal_type
from forge.api.scan_object import GlobalVariableObject, ObjectType, ScanObject
from forge.api.scanner import NewShallowScanVisitor
from forge.api.ui_actions import HexRaysPopupAction, UIMenuAction, register_action
from forge.util.logging import log_info, log_warning

from .child_scan import HierarchyScanRequest
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
        from forge.api.visitor import refresh_function_tree
        return refresh_function_tree(cfunc) or cfunc

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
            candidate_ea = getattr(obj, "ea", ida_idaapi.BADADDR)
            if candidate_ea != ida_idaapi.BADADDR:
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

        # Auto-create a scan-target structure with no modal: an empty name
        # triggers the auto-naming path in StructureBuilderForm.create_structure
        # (is_auto_named = not clean_name), so no name prompt or form show().
        created_structure = structure_form.create_structure("")
        if created_structure is not None:
            log_info(
                f"Forge: scanning into new structure '{created_structure.name}' "
                "(rename it from the Structure Builder when ready)"
            )
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
            log_info(
                f"Forge: shallow-scanned '{obj.name}' into "
                f"'{structure_form.current_structure.name}'"
            )
            structure_form.update_structure_fields()
            hx_view.refresh_view(True)


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

    def _scan_global_references(self, obj, max_depth):
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

        skipped_roots = []
        requests = []
        for func_ea in xref_functions:
            cfunc = decompile(func_ea)
            if cfunc is None:
                skipped_roots.append(func_ea)
                continue

            prepared_cfunc = self._prepare_function(cfunc)
            requests.append(
                HierarchyScanRequest(
                    cfunc=prepared_cfunc,
                    obj=self._clone_global_object(obj),
                    source_base=0,
                )
            )

        if requests:
            structure_form._run_deep_hierarchy_scan(
                structure_form.current_structure,
                requests,
                max_depth=max_depth,
            )

        if skipped_roots:
            skipped = ", ".join(hex(ea) for ea in skipped_roots)
            log_warning(
                f"Skipped global scan roots that could not be decompiled: {skipped}",
                True,
            )

        log_info(
            f"Forge: deep-scanned '{obj.name}' across "
            f"{len(xref_functions)} referencing function(s) into "
            f"'{structure_form.current_structure.name}'"
        )

    @staticmethod
    def _prompt_scan_depth() -> int | None:
        default = config.get_class_config(type(config)).get("default_deep_scan_depth", 0)
        result = ida_kernwin.ask_str(
            str(default), ida_kernwin.HIST_TYPE,
            "Scan depth (0 = unlimited):",
        )
        if result is None:
            return None
        result = result.strip()
        if not result:
            return 0
        try:
            return int(result)
        except ValueError:
            return default

    def _run(self, ctx, max_depth: int | None) -> None:
        if not self._ensure_structure_selected():
            return

        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc

        obj = self.create_scan_object(cfunc, hx_view.item)
        if not obj:
            return

        if obj.id == ObjectType.global_object:
            self._scan_global_references(obj, max_depth)
        else:
            prepared_cfunc = self._prepare_function(cfunc)
            self._set_root_scan_provenance(
                obj,
                root_function_ea=prepared_cfunc.entry_ea,
            )
            if prepared_cfunc.entry_ea == cfunc.entry_ea:
                hx_view.refresh_view(True)
            structure_form._run_deep_hierarchy_scan(
                structure_form.current_structure,
                (
                    HierarchyScanRequest(
                        cfunc=prepared_cfunc,
                        obj=obj,
                        source_base=0,
                    ),
                ),
                max_depth=max_depth,
            )
            log_info(
                f"Forge: deep-scanned '{obj.name}' into "
                f"'{structure_form.current_structure.name}'"
            )
            hx_view.refresh_view(True)
        structure_form.update_structure_fields()

    def activate(self, ctx):
        default_depth = config.get_class_config(type(config)).get(
            "default_deep_scan_depth", 0
        )
        max_depth = None if default_depth <= 0 else default_depth
        self._run(ctx, max_depth)


@register_action
class DeepScanCustomDepthAction(DeepScanAction):
    name = "Deep Scan (Custom Depth)"
    description = "Deep Scan (Custom Depth)"
    hotkey = config["deep_scan_custom_depth_hotkey"]

    def activate(self, ctx):
        depth = self._prompt_scan_depth()
        if depth is None:
            return
        max_depth = None if depth <= 0 else depth
        self._run(ctx, max_depth)


@register_action
class FinalizeStructureAction(HexRaysPopupAction):
    name = "Finalize Structure"
    description = "Finalize Structure"
    hotkey = config["finalize_hotkey"]

    def check(self, hx_view: ida_hexrays.vdui_t):
        structure = structure_form.current_structure
        return structure is not None and bool(structure.members)

    def activate(self, ctx):
        structure = structure_form.current_structure
        if structure is None:
            log_warning(
                "No structure selected.\nScan a variable first.",
                True,
            )
            return

        structure.auto_resolve()
        tinfo = structure.create_type_if_ready(
            structure_form.structures, headless=True
        )
        structure_form.update_structure_fields()

        hx_view = ida_hexrays.get_widget_vdui(ctx.widget)
        if tinfo is not None:
            stats = structure.get_stats()
            log_info(
                f"Forge: created type '{structure.name}' "
                f"({stats.enabled_members} members)"
            )
            if hx_view is not None:
                hx_view.refresh_view(True)
        else:
            log_warning(
                f"Forge: could not finalize '{structure.name}'; "
                "see the Output window for details.",
                True,
            )
