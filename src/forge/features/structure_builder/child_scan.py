from __future__ import annotations

import copy
from dataclasses import dataclass
from types import SimpleNamespace

import ida_hexrays
import idaapi

from forge.api.hexrays import decompile, is_legal_type
from forge.api.members import AbstractMember, parse_user_tinfo
from forge.api.scan_object import (
    ObjectType,
    ScanObject,
    StructurePointerObject,
    StructureReferenceObject,
 )
from forge.api.scanner import NewDeepScanVisitor
from forge.api.structure import Structure
from forge.util.logging import log_warning



from .dialogs import ScannedVariableChooser



def _form_module():
    from importlib import import_module

    return import_module("forge.features.structure_builder.form")

@dataclass(frozen=True)
class ChildScanPlan:
    scan_object: ScanObject
    function_eas: tuple[int, ...]
    relation_kind: str
    root_object_name: str
    root_object_ea: int | None
    root_function_ea: int | None
    has_multiple_roots: bool
    scan_variables: tuple[ScanObject, ...] = ()



class ChildScanMixin:
    @staticmethod
    def _warn_unimplemented(action_name: str) -> None:
        log_warning(f"{action_name} is not implemented yet.", True)

    @staticmethod
    def _prepare_scan_cfunc(func_ea: int):
        try:
            cfunc = decompile(func_ea)
        except ida_hexrays.DecompilationFailure:
            log_warning(f"Failed to decompile function at {hex(func_ea)}", True)
            return None
        if cfunc is None:
            log_warning(f"Failed to decompile function at {hex(func_ea)}", True)
            return None

        from forge.api.visitor import refresh_function_tree_postorder

        return refresh_function_tree_postorder(cfunc) or cfunc

    @staticmethod
    def _resolve_scan_variable_target(
        cfunc: ida_hexrays.cfunc_t, scan_variable: ScanObject
    ) -> ScanObject | None:
        target_ea = getattr(scan_variable, "ea", idaapi.BADADDR)
        if target_ea == idaapi.BADADDR:
            return None

        candidates = []
        for item in getattr(cfunc, "treeitems", []):
            if getattr(item, "ea", idaapi.BADADDR) == target_ea:
                candidates.append(item)

        eamap = getattr(cfunc, "eamap", None)
        if not candidates and eamap is not None:
            try:
                candidates.extend(list(eamap.get(target_ea, [])))
            except Exception:
                pass

        if not candidates:
            body = getattr(cfunc, "body", None)
            if body is not None and hasattr(body, "find_closest_addr"):
                try:
                    closest_item = body.find_closest_addr(target_ea)
                except Exception:
                    closest_item = None
                if closest_item is not None:
                    candidates.append(closest_item)

        for item in candidates:
            resolved = ScanObject.create(cfunc, item)
            if resolved is not None:
                return resolved

        return None

    @staticmethod
    def _normalize_scan_variable(scan_variable: ScanObject) -> ScanObject:
        if getattr(scan_variable, "id", None) is not None:
            return scan_variable

        proxy = SimpleNamespace(
            name=getattr(scan_variable, "name", None),
            ea=getattr(scan_variable, "ea", idaapi.BADADDR),
            func_ea=getattr(scan_variable, "func_ea", idaapi.BADADDR),
            tinfo=getattr(scan_variable, "tinfo", None),
            scan_root_ea=getattr(scan_variable, "scan_root_ea", idaapi.BADADDR),
            scan_root_function_ea=getattr(
                scan_variable, "scan_root_function_ea", idaapi.BADADDR
            ),
            scan_root_function_name=getattr(scan_variable, "scan_root_function_name", None),
        )

        legacy_lvar = getattr(scan_variable, "_ScannedVariableObject__lvar", None)
        if legacy_lvar is not None:
            proxy.id = ObjectType.local_variable
            proxy.lvar = legacy_lvar
            return proxy

        legacy_obj_ea = getattr(scan_variable, "_ScannedGlobalObject__obj_ea", None)
        if legacy_obj_ea is not None:
            proxy.id = ObjectType.global_object
            proxy.object_ea = legacy_obj_ea
            return proxy

        legacy_struct_name = getattr(scan_variable, "_ScannedStructureMemberObject__struct_name", None)
        legacy_struct_offset = getattr(
            scan_variable, "_ScannedStructureMemberObject__struct_offset", None
        )
        if legacy_struct_name is not None and legacy_struct_offset is not None:
            proxy.id = ObjectType.structure_reference
            proxy.struct_name = legacy_struct_name
            proxy.offset = legacy_struct_offset
            return proxy

        return proxy

    @staticmethod
    def _seed_scan_object_from_evidence(
        scan_object: ScanObject, evidence: ScanObject
    ) -> ScanObject | None:
        evidence_ea = getattr(evidence, "ea", idaapi.BADADDR)
        evidence_func_ea = getattr(evidence, "func_ea", idaapi.BADADDR)
        if evidence_ea == idaapi.BADADDR or evidence_func_ea == idaapi.BADADDR:
            return None

        seeded = copy.copy(scan_object)
        seeded.ea = evidence_ea
        seeded.func_ea = evidence_func_ea
        seeded.scan_root_ea = getattr(
            evidence, "scan_root_ea", getattr(seeded, "scan_root_ea", idaapi.BADADDR)
        )
        seeded.scan_root_function_ea = getattr(
            evidence,
            "scan_root_function_ea",
            getattr(seeded, "scan_root_function_ea", idaapi.BADADDR),
        )
        seeded.scan_root_function_name = getattr(
            evidence,
            "scan_root_function_name",
            getattr(seeded, "scan_root_function_name", None),
        )
        return seeded

    @staticmethod
    def _seed_evidence(scan_variable: ScanObject) -> ScanObject:
        seeded = copy.copy(scan_variable)
        root_ea = getattr(scan_variable, "scan_root_ea", idaapi.BADADDR)
        if root_ea != idaapi.BADADDR:
            seeded.ea = root_ea
        root_func_ea = getattr(scan_variable, "scan_root_function_ea", idaapi.BADADDR)
        if root_func_ea != idaapi.BADADDR:
            seeded.func_ea = root_func_ea
        return seeded





    def _build_child_scan_plan(
        self,
        member: AbstractMember | None,
        *,
        show_warnings: bool = False,
    ) -> ChildScanPlan | None:
        if self.current_structure is None or member is None:
            return None

        def warn(message: str) -> None:
            if show_warnings:
                log_warning(message, True)

        scanned_variables = sorted(
            getattr(member, "scanned_variables", set()),
            key=lambda scan_variable: (
                getattr(scan_variable, "func_ea", idaapi.BADADDR),
                getattr(scan_variable, "ea", idaapi.BADADDR),
                str(getattr(scan_variable, "name", "")),
            ),
        )
        if not scanned_variables:
            warn("The selected row does not have scan evidence for child scanning yet.")
            return None

        seeded_scan_variables = tuple(
            self._seed_evidence(self._normalize_scan_variable(scan_variable))
            for scan_variable in scanned_variables
        )

        tinfo = getattr(member, "tinfo", None)
        if tinfo is None:
            warn("The selected row does not have enough type information to scan a child structure.")
            return None

        try:
            legal_type = is_legal_type(tinfo)
        except Exception:
            legal_type = False
        if not legal_type:
            warn("The selected row uses a type that cannot be scanned as a child structure.")
            return None

        if hasattr(tinfo, "is_ptr") and tinfo.is_ptr():
            relation_kind = "pointer"
            scan_object = StructurePointerObject(
                self.current_structure.created_type_name or self.current_structure.name,
                member.offset,
            )
        else:
            relation_kind = "embedded"
            scan_object = StructureReferenceObject(
                self.current_structure.created_type_name or self.current_structure.name,
                member.offset,
            )

        parent_struct_name = self.current_structure.created_type_name or self.current_structure.name
        if not parent_struct_name:
            parent_struct_names = sorted(
                {
                    candidate
                    for candidate in (
                        getattr(scan_variable, "_name", None)
                        for scan_variable in scanned_variables
                    )
                    if isinstance(candidate, str) and candidate
                }
            )
            if len(parent_struct_names) != 1:
                warn(
                    "Child scan currently requires a typed parent structure or unambiguous member evidence.",
                )
                return None
            parent_struct_name = parent_struct_names[0]
            scan_object = type(scan_object)(parent_struct_name, member.offset)

        function_eas = tuple(
            sorted(
                {
                    getattr(scan_variable, "func_ea", idaapi.BADADDR)
                    for scan_variable in seeded_scan_variables
                    if getattr(scan_variable, "func_ea", idaapi.BADADDR) != idaapi.BADADDR
                }
            )
        )
        if not function_eas:
            warn("The selected row does not have any decompilable function evidence for child scanning.")
            return None

        scan_object.name = member.name
        scan_object.tinfo = tinfo
        representative = seeded_scan_variables[0]
        expression_eas = {
            getattr(scan_variable, "ea", idaapi.BADADDR)
            for scan_variable in seeded_scan_variables
            if getattr(scan_variable, "ea", idaapi.BADADDR) != idaapi.BADADDR
        }
        member_name = member.name or f"member_{member.offset:X}"
        root_object_ea = getattr(representative, "ea", idaapi.BADADDR)
        root_function_ea = getattr(representative, "func_ea", idaapi.BADADDR)
        return ChildScanPlan(
            scan_object=scan_object,
            function_eas=function_eas,
            relation_kind=relation_kind,
            root_object_name=f"{self.current_structure.name}.{member_name}",
            root_object_ea=root_object_ea if root_object_ea != idaapi.BADADDR else None,
            root_function_ea=(
                root_function_ea if root_function_ea != idaapi.BADADDR else None
            ),
            has_multiple_roots=len(function_eas) > 1 or len(expression_eas) > 1,
            scan_variables=seeded_scan_variables,
        )



    def _create_or_get_child_structure(
        self,
        member: AbstractMember,
    ) -> tuple[Structure | None, bool]:
        linked_child_name = getattr(member, "linked_child_structure_name", None)
        if linked_child_name:
            existing_child = self.structures.get(linked_child_name)
            if existing_child is not None:
                return existing_child, False
            return self.create_structure(linked_child_name), True
        return self.create_structure(""), True

    def _execute_child_scan_plan(
        self,
        child_structure: Structure,
        plan: ChildScanPlan,
    ) -> bool:
        scanned_any = False
        visitor_cls = getattr(_form_module(), "NewDeepScanVisitor", NewDeepScanVisitor)
        evidence_by_function: dict[int, list[ScanObject]] = {}
        for scan_variable in getattr(plan, "scan_variables", ()) or ():
            normalized = self._normalize_scan_variable(scan_variable)
            func_ea = getattr(normalized, "func_ea", idaapi.BADADDR)
            if func_ea == idaapi.BADADDR:
                continue
            evidence_by_function.setdefault(func_ea, []).append(normalized)
        for func_ea in plan.function_eas:
            cfunc = self._prepare_scan_cfunc(func_ea)
            if cfunc is None:
                continue
            scan_variables = evidence_by_function.get(func_ea) or [plan.scan_object]
            for scan_variable in scan_variables:
                seeded_scan_object = self._seed_scan_object_from_evidence(
                    plan.scan_object, scan_variable
                )
                if seeded_scan_object is None:
                    log_warning(
                        f"Skipping child scan evidence without a usable location in {hex(func_ea)}",
                        True,
                    )
                    continue
                visitor = visitor_cls(
                    cfunc,
                    child_structure.main_offset,
                    seeded_scan_object,
                    child_structure,
                    recurse_calls=True,
                )
                visitor.process()
                scanned_any = True
        return scanned_any



    @staticmethod
    def _materialize_child_member_type(
        member: AbstractMember,
        child_structure: Structure,
        relation_kind: str,
    ) -> None:
        child_type_name = child_structure.created_type_name or child_structure.name
        type_decl = f"{child_type_name} *" if relation_kind == "pointer" else child_type_name
        parse_tinfo = getattr(_form_module(), "parse_user_tinfo", parse_user_tinfo)
        tinfo = parse_tinfo(type_decl)
        if tinfo is None:
            return

        member.tinfo = tinfo
        member.is_array = False
        if hasattr(member, "invalidate_score"):
            member.invalidate_score()

    @staticmethod
    def _child_scan_origin(member: AbstractMember) -> int:
        return getattr(member, "origin", 0) + member.offset

    @staticmethod
    def _link_child_structure(
        parent_structure: Structure,
        child_structure: Structure,
        member: AbstractMember,
        relation_kind: str,
    ) -> None:
        parent_member_name = member.name or f"member_{member.offset:X}"
        relationship = parent_structure.add_child_relationship(
            child_structure_name=child_structure.name,
            parent_member_offset=member.offset,
            parent_member_name=parent_member_name,
            relation_kind=relation_kind,
        )
        child_structure.add_parent_relationship(relationship)
        member.linked_child_structure_name = child_structure.name
        member.child_relation_kind = relation_kind
        ChildScanMixin._materialize_child_member_type(member, child_structure, relation_kind)

    @staticmethod
    def _set_child_scan_provenance(
        child_structure: Structure,
        member: AbstractMember,
        plan: ChildScanPlan,
    ) -> None:
        child_structure.set_provenance(
            kind="child_scan",
            root_object_name=plan.root_object_name,
            root_object_ea=plan.root_object_ea,
            root_function_ea=plan.root_function_ea,
            source_member_offset=member.offset,
            has_multiple_roots=plan.has_multiple_roots,
        )

    def scan_child_structure(self):
        if self.current_structure is None:
            log_warning("No structure selected!", True)
            return

        selected_member = self.get_selected_member()
        if selected_member is None:
            log_warning("No structure row selected!", True)
            return

        parent_structure = self.current_structure
        plan = self._build_child_scan_plan(selected_member, show_warnings=True)
        if plan is None:
            return

        child_structure, created_now = self._create_or_get_child_structure(selected_member)
        if child_structure is None:
            return

        child_origin = self._child_scan_origin(selected_member)
        if child_structure.main_offset != child_origin:
            child_structure.set_main_offset(child_origin)

        existing_member_count = len(child_structure.members)
        scanned_any = self._execute_child_scan_plan(child_structure, plan)

        scan_produced_results = len(child_structure.members) > existing_member_count
        if not scanned_any or (created_now and not scan_produced_results):
            if created_now and child_structure.name in self.structures:
                del self.structures[child_structure.name]
            self.current_structure = parent_structure
            if self.ui is not None:
                self.reload_structure_list()
                self._select_structure_in_tree(parent_structure.name)
            self.update_action_states()
            log_warning(
                "Unable to derive child structure scan results from the selected row.",
                True,
            )
            return

        self._link_child_structure(
            parent_structure,
            child_structure,
            selected_member,
            plan.relation_kind,
        )
        if created_now or (
            child_structure.provenance.kind == "manual" and existing_member_count == 0
        ):
            self._set_child_scan_provenance(
                child_structure,
                selected_member,
                plan,
            )

        self.current_structure = child_structure
        if self.ui is not None:
            self.reload_structure_list()
            if self._select_structure_in_tree(child_structure.name):
                self.ui.tree_structures.setFocus()
        self.update_action_states()

    def show_scanned_variables(self):
        if self.current_structure is None:
            return

        selected_members = self.get_selected_members()
        if selected_members:
            scanned_variables = {
                scan_object
                for member in selected_members
                for scan_object in member.scanned_variables
            }
        else:
            scanned_variables = set(
                self.current_structure.get_unique_scanned_variables(
                    self.current_structure.main_offset
                )
            )

        if not scanned_variables:
            log_warning("No scanned variables available for the current selection.", True)
            return

        chooser = ScannedVariableChooser(
            sorted(
                scanned_variables,
                key=lambda scan_object: (
                    getattr(scan_object, "func_ea", idaapi.BADADDR),
                    getattr(scan_object, "ea", idaapi.BADADDR),
                    scan_object.name,
                ),
            )
        )
        chooser.Show()
