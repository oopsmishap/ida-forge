from __future__ import annotations

import bisect
import itertools
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, replace

import ida_kernwin
import ida_typeinf
import idaapi

try:  # plugin runs under standalone unit tests without the IDA undo module
    import ida_undo
except ImportError:
    ida_undo = None  # type: ignore[assignment]

import forge.api.types as forge_types
from forge.api.domain import current_database as _current_domain_database
from forge.api.domain import try_domain_method as _try_domain_method
from forge.api.hexrays import create_udt_padding_member
from forge.api.members import (
    AbstractMember,
    VirtualTable,
    materialize_linked_child_member_type,
    parse_user_tinfo,
)
from forge.util.logging import log_debug, log_error, log_warning


def _strip_pragma_decl(cdecl: str) -> str:
    """Drop a leading ``#pragma pack(...)`` line (parse_decl accepts no
    preprocessor lines; idc_parse_types does)."""
    return re.sub(r"^#pragma pack\([^\n]*\)\s*", "", cdecl, count=1)

def _member_pack_size(member) -> int:
    """Pack-time byte size, tolerant of duck-typed members (test fakes).

    Real members expose ``effective_size()`` (pack-resolved — R2.1); test
    doubles and older shapes only carry a stored ``size``. Collision math
    must use the pack size so a placeholder-poisoned member is not treated
    as non-colliding.
    """
    effective = getattr(member, "effective_size", None)
    if callable(effective):
        return effective()
    return getattr(member, "size", 1)

def _apply_lvar_pointer_type(func_ea: int, var: str, structure_name: str) -> bool:
    """Retype the local named ``var`` in ``func_ea`` to ``Name *`` (R3.8).

    Row-based fallback of the F.1 variable apply: the persisted scan
    rows carry (func_ea, var); the live lvar is matched by NAME (the
    live path matches by location/defea, which the rows do not store).
    Commits through the same ``modify_user_lvar_info(MLI_TYPE)``
    mechanism, so the effect is identical after a database reload.
    """
    import ida_hexrays

    from forge.api.hexrays import decompile as _decompile
    from forge.api.members import parse_user_tinfo

    try:
        cfunc = _decompile(func_ea)
        if cfunc is None:
            return False
        lvar = next(
            (
                candidate
                for candidate in cfunc.get_lvars()
                if getattr(candidate, "name", None) == var
            ),
            None,
        )
        if lvar is None:
            return False
        tinfo = parse_user_tinfo(f"{structure_name} *")
        if tinfo is None:
            return False
        lvi = ida_hexrays.lvar_saved_info_t()
        lvi.ll = ida_hexrays.lvar_locator_t(lvar.location, lvar.defea)
        lvi.type = tinfo
        modified = ida_hexrays.modify_user_lvar_info(
            cfunc.entry_ea, ida_hexrays.MLI_TYPE, lvi
        )
        # F9 (2026-09 review): a failed retype must not be recorded as an
        # applied site — return the API's verdict, not an unconditional True.
        return bool(modified)
    except Exception:  # noqa: BLE001 — row-based apply is best-effort
        return False


def _apply_ea_pointer_type(ea: int, tinfo) -> bool:
    """Apply ``tinfo`` at a recorded global site (R3.8 row fallback)."""
    try:
        return bool(
            ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
        )
    except Exception:  # noqa: BLE001 — best-effort
        return False


@contextmanager
def _type_write_undo(action: str):
    """Run a destructive type write inside an IDA undo snapshot.

    ``ida_undo`` is not available under the unit-test environment, so the
    guard keeps the module importable everywhere; the snapshot means a bad
    ``auto_resolve``/``set_cdecl`` result can be reverted with a single
    IDA ``undo`` (everything from the begin to the end point).
    """
    if ida_undo is None:
        yield
        return
    try:
        ida_undo.begin_undo_action(action)
    except Exception:  # noqa: BLE001 — undo may be unsupported mid-transaction
        yield
        return
    try:
        yield
    finally:
        # best-effort undo bookkeeping
        with suppress(Exception):
            ida_undo.end_undo_action()


@dataclass(frozen=True)
class StructureStats:
    total_members: int
    enabled_members: int
    collision_count: int
    scanned_variable_count: int
    origin_offset: int


@dataclass
class StructureProvenance:
    kind: str = "manual"
    root_object_name: str | None = None
    root_object_ea: int | None = None
    root_function_ea: int | None = None
    # Argument index of the root call-argument observation (aggregate
    # identity: (root_function_ea, root_argument_index) identifies a
    # reconstructed aggregate across scans).
    root_argument_index: int | None = None
    source_member_offset: int | None = None
    # Address of the root vtable (hierarchy identity: ("vtable", ea, -1)).
    root_vtable_ea: int | None = None
    has_multiple_roots: bool = False
    roots: list[dict] = field(default_factory=list)

@dataclass
class StructureRelationship:
    parent_structure_name: str
    child_structure_name: str
    parent_member_offset: int
    parent_member_name: str
    relation_kind: str = "pointer"


class Structure:
    def __init__(self, name: str):
        self.name = name
        self.main_offset = 0
        self.members: list[AbstractMember] = []
        # Largest safely-known byte extent of the layout (hierarchy commit
        # grows children to the widest evidence before linking).
        self.conservative_extent: int = 0
        self.collisions: list[bool] = []
        self.is_auto_named: bool = False
        self.created_type_name: str | None = None
        # R3.2 (recovery eval round 2, F1): store structures pack byte
        # layouts by default (pack=1); None opts out (natural alignment).
        self.pack: int | None = 1
        # R3.5: sites the last commit applied the pointer type to
        # (populated by _apply_scanned_variable_types).
        self.last_apply_sites: list[dict] = []
        self.scan_sites_rows: list[dict] = []
        self.provenance: StructureProvenance = StructureProvenance()
        self.parent_relationships: list[StructureRelationship] = []
        self.child_relationships: list[StructureRelationship] = []
        # Binary C++ ABI evidence (vtable/RTTI/base-subobject metadata).
        # Kept detached from IDA tinfo handles so it survives catalog reload.
        self.abi_metadata: dict = {}

    def add_member(self, member: AbstractMember) -> None:
        """Insert a member while keeping the structure ordered by offset/type."""
        if not hasattr(member, "linked_child_structure_name"):
            member.linked_child_structure_name = None
        if not hasattr(member, "child_relation_kind"):
            member.child_relation_kind = None
        if member in self.members:
            return
        bisect.insort(self.members, member)
        self.refresh_collisions()

    def set_provenance(
        self,
        *,
        kind: str,
        root_object_name: str | None = None,
        root_object_ea: int | None = None,
        root_function_ea: int | None = None,
        root_argument_index: int | None = None,
        source_member_offset: int | None = None,
        root_vtable_ea: int | None = None,
        has_multiple_roots: bool = False,
    ) -> None:
        self.provenance = StructureProvenance(
            kind=kind,
            root_object_name=root_object_name,
            root_object_ea=root_object_ea,
            root_function_ea=root_function_ea,
            root_argument_index=root_argument_index,
            source_member_offset=source_member_offset,
            root_vtable_ea=root_vtable_ea,
            has_multiple_roots=has_multiple_roots,
        )

    def clone_provenance(self) -> StructureProvenance:
        return replace(self.provenance)

    def get_member_by_offset(self, offset: int) -> AbstractMember | None:
        return next((member for member in self.members if member.offset == offset), None)

    def add_child_relationship(
        self,
        *,
        child_structure_name: str,
        parent_member_offset: int,
        parent_member_name: str,
        relation_kind: str = "pointer",
    ) -> StructureRelationship:
        relationship = StructureRelationship(
            parent_structure_name=self.name,
            child_structure_name=child_structure_name,
            parent_member_offset=parent_member_offset,
            parent_member_name=parent_member_name,
            relation_kind=relation_kind,
        )
        existing = next(
            (
                rel
                for rel in self.child_relationships
                if rel.child_structure_name == child_structure_name
                and rel.parent_member_offset == parent_member_offset
            ),
            None,
        )
        if existing is None:
            self.child_relationships.append(relationship)
            return relationship
        return existing

    def add_parent_relationship(self, relationship: StructureRelationship) -> None:
        if any(
            rel.parent_structure_name == relationship.parent_structure_name
            and rel.parent_member_offset == relationship.parent_member_offset
            and rel.child_structure_name == relationship.child_structure_name
            for rel in self.parent_relationships
        ):
            return
        self.parent_relationships.append(relationship)

    def refresh_linked_member_types(
        self, structures_by_name: Mapping[str, Structure]
    ) -> bool:
        for relationship in self.child_relationships:
            child = structures_by_name.get(relationship.child_structure_name)
            if child is None or child.created_type_name is None:
                continue

            member = self.get_member_by_offset(relationship.parent_member_offset)
            if member is None:
                continue

            relation_kind = (
                getattr(member, "child_relation_kind", None) or relationship.relation_kind
            )
            if materialize_linked_child_member_type(
                member, child.created_type_name, relation_kind
            ):
                continue

            member_name = member.name or f"member_{member.offset:X}"
            log_warning(
                f"Failed to materialize linked child type {child.created_type_name} for {self.name}.{member_name}",
                True,
            )
            return False

        return True


    def remove_relationships_with(self, structure_name: str) -> None:
        self.child_relationships = [
            rel for rel in self.child_relationships if rel.child_structure_name != structure_name
        ]
        self.parent_relationships = [
            rel for rel in self.parent_relationships if rel.parent_structure_name != structure_name
        ]
        for member in self.members:
            if getattr(member, "linked_child_structure_name", None) == structure_name:
                member.linked_child_structure_name = None
                member.child_relation_kind = None

    def rename_relationship_references(self, old_name: str, new_name: str) -> None:
        for relationship in self.child_relationships:
            if relationship.parent_structure_name == old_name:
                relationship.parent_structure_name = new_name
            if relationship.child_structure_name == old_name:
                relationship.child_structure_name = new_name
        for relationship in self.parent_relationships:
            if relationship.parent_structure_name == old_name:
                relationship.parent_structure_name = new_name
            if relationship.child_structure_name == old_name:
                relationship.child_structure_name = new_name
        for member in self.members:
            if getattr(member, "linked_child_structure_name", None) == old_name:
                member.linked_child_structure_name = new_name
            # E4 (eval review 2026-08-13): member type strings that name
            # the renamed structure must follow it, or the next pack
            # re-parse (see Member._resolve_pack_tinfo) resolves a stale
            # declaration and rebuilds the member as ``#NN *``.
            src = getattr(member, "decl_src", None)
            if src and re.search(rf"\b{re.escape(old_name)}\b", src):
                new_src = re.sub(rf"\b{re.escape(old_name)}\b", new_name, src)
                member.decl_src = new_src
                refreshed = parse_user_tinfo(new_src)
                if refreshed is not None:
                    member.tinfo = refreshed


    def rename_created_type(self, old_name: str, new_name: str) -> bool:
        if self.created_type_name != old_name or old_name == new_name:
            return True

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_named_type(ida_typeinf.get_idati(), old_name):
            log_warning(
                f"Created type {old_name} is missing; leaving the type name unchanged.",
                True,
            )
            return True

        rename_result = tinfo.rename_type(new_name)
        if rename_result != 0:
            log_warning(
                f"Failed to rename created type {old_name} to {new_name}: {rename_result}",
                True,
            )
            return False

        self.created_type_name = new_name
        return True

    def get_linked_child_names(self) -> list[str]:
        return sorted({rel.child_structure_name for rel in self.child_relationships})

    def has_linked_children(self) -> bool:
        return bool(self.child_relationships)

    def get_provenance_summary(self) -> str:
        parts = [self.provenance.kind.replace("_", " ")]
        if self.provenance.root_object_name:
            parts.append(self.provenance.root_object_name)
        if self.provenance.source_member_offset is not None:
            parts.append(f"member @ 0x{self.provenance.source_member_offset:X}")
        if self.provenance.root_argument_index is not None:
            parts.append(f"argument {self.provenance.root_argument_index + 1}")
        if self.provenance.has_multiple_roots:
            parts.append("multiple roots")
        return " | ".join(parts)

    def get_unresolved_child_names(
        self,
        structures_by_name: Mapping[str, Structure],
    ) -> list[str]:
        return sorted(
            {
                relationship.child_structure_name
                for relationship in self.child_relationships
                if (
                    child := structures_by_name.get(
                        relationship.child_structure_name
                    )
                )
                is None
                or child.created_type_name is None
            }
        )

    def _iter_child_relationships(self) -> Iterator[StructureRelationship]:
        yield from sorted(
            self.child_relationships,
            key=lambda relationship: (
                relationship.parent_member_offset,
                relationship.parent_member_name,
                relationship.child_structure_name,
            ),
        )

    def iter_child_structures(
        self,
        structures_by_name: Mapping[str, Structure],
    ) -> Iterator[Structure]:
        seen_child_names: set[str] = set()
        for relationship in self._iter_child_relationships():
            child = structures_by_name.get(relationship.child_structure_name)
            if child is None or child.name in seen_child_names:
                continue
            seen_child_names.add(child.name)
            yield child

    def can_create_type(
        self,
        structures_by_name: Mapping[str, Structure],
    ) -> bool:
        return not self.get_unresolved_child_names(structures_by_name)

    def create_type_if_ready(
        self,
        structures_by_name: Mapping[str, Structure],
        *,
        start: int | None = None,
        end: int | None = None,
        headless: bool = False,
    ) -> ida_typeinf.tinfo_t | None:
        unresolved_child_names = self.get_unresolved_child_names(structures_by_name)
        if unresolved_child_names:
            child_names = ", ".join(unresolved_child_names)
            log_warning(
                f"Cannot create type for {self.name}: unresolved child structures: {child_names}",
                True,
            )
            return None
        if not self.refresh_linked_member_types(structures_by_name):
            return None
        # R3.9: ONE commit core for GUI and headless — build_cdecl ->
        # set_cdecl (which applies at scan sites). The GUI path adds the
        # editable pack dialog on top; the commit underneath is identical,
        # so "create via the form" and "create_type()" cannot diverge.
        if headless:
            # Headless path (idalib workers / forge_api): commit the built
            # declaration directly with an explicit overwrite. Never the
            # dialog path, whose ida_kernwin dialogs return None headless
            # and turned finalize into a 0-diagnostic failure.
            return self._pack_commit(start, end, overwrite=True)
        return self.pack_structure(start=start, end=end)

    def _pack_commit(self, start, end, *, overwrite: bool) -> ida_typeinf.tinfo_t | None:
        """Shared commit: build the packed cdecl and commit it via set_cdecl.

        The single place build layout -> declaration text -> set_cdecl
        (commit + apply-to-scan-sites) happens, for the API verbs and the
        GUI pack dialog alike (R3.9). Returns the committed tinfo.
        """
        start_index = self.get_main_offset_index() if start is None else start
        origin = (
            self.members[start_index].offset
            if start_index < len(self.members)
            else 0
        )
        result = self.build_cdecl(start, end)
        if result is None:
            return None
        _, cdecl = result
        return self.set_cdecl(cdecl, origin, overwrite=overwrite)

    def create_subtree_types_postorder(
        self,
        structures_by_name: Mapping[str, Structure],
        *,
        visited: set[str] | None = None,
        headless: bool = False,
    ) -> tuple[bool, list[str], str | None]:
        """Create every type in the subtree postorder (children first).

        Returns ``(ok, created_names, error)`` — E9 (eval review
        2026-08-13): callers could not distinguish "child missing" from a
        real commit failure, and a partially-created subtree reported
        ``ok=False`` with no reason. ``created_names`` lists every
        structure whose type committed; ``error`` is the first failure
        reason (unresolved child, cycle, or the exception text), None when
        the whole subtree committed.
        """
        completed = visited if visited is not None else set()
        stack: list[str] = []
        created_names: list[str] = []
        error: str | None = None

        def _walk(structure: Structure) -> bool:
            nonlocal error
            if structure.name in completed:
                return True
            if structure.name in stack:
                cycle_start = stack.index(structure.name)
                cycle_path = " -> ".join([*stack[cycle_start:], structure.name])
                log_warning(
                    f"Cycle detected while creating type subtree: {cycle_path}",
                    True,
                )
                error = error or f"cycle: {cycle_path}"
                return False

            stack.append(structure.name)
            try:
                for child_structure in structure.iter_child_structures(structures_by_name):
                    if not _walk(child_structure):
                        log_warning(
                            f"Cannot create subtree for {structure.name}: "
                            f"child subtree {child_structure.name} "
                            "could not be finalized",
                            True,
                        )
                        error = error or (
                            f"child subtree {child_structure.name} "
                            "could not be finalized"
                        )
                        return False

                if structure.create_type_if_ready(
                    structures_by_name, headless=headless
                ) is None:
                    unresolved = structure.get_unresolved_child_names(
                        structures_by_name
                    )
                    error = error or (
                        f"unresolved children: {', '.join(unresolved)}"
                        if unresolved
                        else f"type creation failed for {structure.name}"
                    )
                    return False

                completed.add(structure.name)
                created_names.append(structure.name)
                return True
            except Exception as exc:  # noqa: BLE001 — subtree walk must not abort the batch
                error = error or f"{type(exc).__name__}: {exc}"
                return False
            finally:
                stack.pop()

        ok = _walk(self)
        return ok, created_names, error

    def has_collision(self, index: int) -> bool:
        return 0 <= index < len(self.collisions) and self.collisions[index]

    def refresh_collisions(self) -> None:
        self.collisions = [False] * len(self.members)
        current_index = next(
            (index for index, member in enumerate(self.members) if member.enabled),
            None,
        )
        if current_index is None:
            return

        for next_index in range(current_index + 1, len(self.members)):
            next_member = self.members[next_index]
            if not next_member.enabled:
                continue

            current_member = self.members[current_index]
            if current_member.offset + _member_pack_size(current_member) > next_member.offset:
                self.collisions[current_index] = True
                self.collisions[next_index] = True

                current_end = current_member.offset + _member_pack_size(current_member)
                next_end = next_member.offset + _member_pack_size(next_member)
                if current_end < next_end:
                    current_index = next_index
            else:
                current_index = next_index

    def get_next_enabled(self, index: int) -> int:
        for candidate in range(index + 1, len(self.members)):
            if self.members[candidate].enabled:
                return candidate
        return -1

    def calculate_array_size(self, index: int) -> int:
        next_enabled = self.get_next_enabled(index)
        if next_enabled == -1:
            return 0

        member = self.members[index]
        # F10 (2026-09 review): use the same duck-typed pack-size helper as
        # refresh_collisions/build_cdecl so collision flags and pack math
        # agree (and duck-typed members without effective_size() work).
        pack_size = _member_pack_size(member)
        if pack_size <= 0:
            return 0

        span = self.members[next_enabled].offset - member.offset
        if span <= pack_size:
            return 0
        return span // pack_size

    def clear_members(self) -> None:
        self.members.clear()
        self.collisions.clear()
        self.main_offset = 0

    def set_main_offset(self, offset: int) -> None:
        self.main_offset = offset

    def get_main_offset_index(self) -> int:
        for index, member in enumerate(self.members):
            if member.offset >= self.main_offset:
                return index
        return 0

    def get_name(self) -> str:
        virtual_tables = [
            member
            for member in self.members
            if isinstance(member, VirtualTable) and member.has_nice_vtable_name
        ]

        if len(virtual_tables) == 1:
            return virtual_tables[0].vtable_name.replace("_vtbl", "")

        if len(virtual_tables) > 1:
            log_warning(
                "Multiple candidates for structure name: "
                f"{[vt.vtable_name for vt in virtual_tables]}. Setting to {self.name}."
            )
        return self.name

    @staticmethod
    def dedupe_scanned_variables(scan_objects) -> list:
        unique_scan_objects = {}
        for scan_object in scan_objects:
            if scan_object is None:
                continue

            identity_key = getattr(scan_object, "identity_key", None)
            if callable(identity_key):
                key = identity_key()
            else:
                key = (
                    getattr(scan_object, "func_ea", None),
                    getattr(scan_object, "ea", None),
                    getattr(scan_object, "id", None),
                    getattr(scan_object, "name", None),
                )
            unique_scan_objects[key] = scan_object
        return list(unique_scan_objects.values())

    def get_unique_scanned_variables(self, origin: int = 0) -> list:
        scan_objects = itertools.chain.from_iterable(
            member.scanned_variables
            for member in self.members
            if member.origin == origin
        )
        return self.dedupe_scanned_variables(scan_objects)

    def get_stats(self) -> StructureStats:
        self.refresh_collisions()
        return StructureStats(
            total_members=len(self.members),
            enabled_members=sum(1 for member in self.members if member.enabled),
            collision_count=sum(1 for has_collision in self.collisions if has_collision),
            scanned_variable_count=len(
                self.get_unique_scanned_variables(self.main_offset)
            ),
            origin_offset=self.main_offset,
        )

    def disable_members(self, indices: int | Sequence[int]) -> None:
        if isinstance(indices, int):
            indices = [indices]
        for index in indices:
            if 0 <= index < len(self.members):
                self.members[index].set_enabled(False)
        self.refresh_collisions()

    def enable_members(self, indices: int | Sequence[int]) -> None:
        if isinstance(indices, int):
            indices = [indices]
        for index in indices:
            if 0 <= index < len(self.members):
                self.members[index].set_enabled(True)
        self.refresh_collisions()

    def remove_members(self, indices: int | Sequence[int]) -> None:
        if isinstance(indices, int):
            indices = [indices]
        for index in sorted(set(indices), reverse=True):
            if 0 <= index < len(self.members):
                removed_member = self.members[index]
                del self.members[index]
                if removed_member.offset == self.main_offset:
                    self.main_offset = self.members[0].offset if self.members else 0
        self.refresh_collisions()

    def auto_resolve_preview(self) -> list[AbstractMember]:
        """Return the members :meth:`auto_resolve` would disable.

        Pure read-only walk of the collision-resolution heuristic, so the UI
        can confirm the change before the destructive disable happens.
        """
        disabled: list[AbstractMember] = []
        current_member = None
        for member in self.members:
            if not member.enabled:
                continue
            if current_member is None:
                current_member = member
                continue
            if current_member.has_collision(member):
                if member.score <= current_member.score:
                    disabled.append(member)
                    continue
                disabled.append(current_member)
            current_member = member
        return disabled

    def auto_resolve(self) -> list[AbstractMember]:
        """Resolve overlapping members by score, disabling the colliding half.

        Returns the members that were disabled so callers can preview the
        change before committing it.
        """
        disabled = self.auto_resolve_preview()
        for member in disabled:
            member.set_enabled(False)
        self.refresh_collisions()
        return disabled

    def iter_packable_members(
        self, start: int | None = None
    ) -> Iterator[tuple[int, AbstractMember]]:
        start_index = self.get_main_offset_index() if start is None else start
        origin = (
            self.members[start_index].offset if start_index < len(self.members) else 0
        )
        for index in range(start_index, len(self.members)):
            member = self.members[index]
            if member.enabled and member.offset >= origin:
                yield index, member

    def build_cdecl(self, start: int | None = None, end: int | None = None):
        """Build the packed C declaration for the enabled members.

        Returns ``(struct_name, cdecl)`` with ``cdecl`` the ``print_tinfo``
        declaration (callers add the ``#pragma pack`` wrapper), or ``None``
        when packing is impossible (empty structure / no packable members).

        This is the non-interactive packing core shared by
        :meth:`pack_structure` (which adds the name/rewrite dialogs on top)
        and the headless ``forge_api`` facade (which packs and applies via
        :meth:`set_cdecl` directly).
        """
        if not self.members:
            log_warning("Structure is empty", True)
            return None

        self.refresh_collisions()
        struct_name = self.get_name() or self.name
        if not struct_name:
            log_warning("Structure has no usable name to pack.", True)
            return None

        start_index = self.get_main_offset_index() if start is None else start
        origin = (
            self.members[start_index].offset if start_index < len(self.members) else 0
        )
        packable_members = list(self.iter_packable_members(start_index))
        if end is not None:
            packable_members = [
                (index, member)
                for index, member in packable_members
                if index <= end
            ]
        if not packable_members:
            log_warning("No enabled members are available to create a type.", True)
            return None

        log_debug(f"Packing structure {struct_name}")

        final_tinfo = ida_typeinf.tinfo_t()
        udt_data = ida_typeinf.udt_type_data_t()
        current_offset = origin

        for index, member in packable_members:
            # R3.8: a member whose type resolves to void can never commit
            # — IDA's parser rejects it ("Void type is forbidden here")
            # with a message that says nothing about WHICH member. Skip
            # it loudly so the failure is diagnosable instead.
            # R3.10: a member with NO tinfo at all renders as bare `void`
            # through tinfo_t(None) — same parser failure, and is_void()
            # is not callable on it. Treat None like void.
            member_tinfo = getattr(member, "tinfo", None)
            is_void = getattr(member_tinfo, "is_void", None)
            if member_tinfo is None or (callable(is_void) and is_void()):
                reason = (
                    "has no type (tinfo is None)" if member_tinfo is None else "is void-typed"
                )
                log_warning(
                    f"Skipping member {member.name} at 0x{member.offset:x} "
                    f"in {struct_name} — {reason}; IDA forbids committing "
                    "it; set a real type or disable the member."
                )
                continue

            gap_size = member.offset - current_offset
            if gap_size > 0:
                udt_data.push_back(
                    create_udt_padding_member(current_offset - origin, gap_size)
                )

            if member.is_array:
                explicit_count = getattr(member, "array_count", None)
                array_size = explicit_count or self.calculate_array_size(index)
                if array_size > 1:
                    udt_data.push_back(member.get_udt_member(array_size, offset=origin))
                    # F10: duck-typed pack size, consistent with the scalar path.
                    current_offset = (
                        member.offset + _member_pack_size(member) * array_size
                    )
                    continue

            udt_data.push_back(member.get_udt_member(offset=origin))
            current_offset = member.offset + _member_pack_size(member)

        final_tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
        cdecl = ida_typeinf.print_tinfo(
            None,
            4,
            5,
            ida_typeinf.PRTYPE_MULTI
            | ida_typeinf.PRTYPE_TYPE
            | ida_typeinf.PRTYPE_SEMI,
            final_tinfo,
            struct_name,
            None,
        )
        if not cdecl:
            raise RuntimeError("Failed to generate C declaration")
        return struct_name, cdecl

    def pack_structure(self, start: int | None = None, end: int | None = None):
        """GUI Create-Type flow: editable dialog over the SAME commit core.

        The only GUI-specific parts are the name prompt and the editable
        declaration dialog (``ask_text``); the layout build and commit
        (set_cdecl + apply-at-scan-sites) are the same functions the
        headless path uses, so the form and the API cannot diverge (R3.9).
        """
        if not self.members:
            log_warning("Structure is empty", True)
            return None

        self.refresh_collisions()
        struct_name = self.get_name()
        if not struct_name:
            struct_name = ida_kernwin.ask_str("", ida_kernwin.HIST_TYPE, "Struct name:")
            if not struct_name:
                return None
            # ``build_cdecl`` derives its name from ``get_name() or
            # self.name`` — persist the prompted name so an unnamed
            # ``Structure("")`` can actually be packed (R4 name flow).
            self.name = struct_name

        start_index = self.get_main_offset_index() if start is None else start
        origin = (
            self.members[start_index].offset if start_index < len(self.members) else 0
        )

        result = self.build_cdecl(start, end)
        if result is None:
            return None
        _, cdecl = result

        edited_cdecl = ida_kernwin.ask_text(
            0x10000,
            f"#pragma pack(push, 1)\n{cdecl}",
            "The following new type will be created",
        )
        if not edited_cdecl:
            log_warning("No type definition was provided", True)
            return None
        return self.set_cdecl(edited_cdecl, origin)

    @staticmethod
    def _extract_type_name(cdecl: str) -> str | None:
        match = re.search(r"\b(struct|union|enum)\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)", cdecl)
        if match:
            return match.group(2)
        return None

    @staticmethod
    def _declaration_parses(cdecl: str) -> bool:
        """True when ``cdecl`` parses as a C type declaration.

        Used to gate the destructive overwrite path in :meth:`set_cdecl`.
        ``parse_decl`` returns the declared name on success and ``None`` on
        failure (``PT_SIL`` keeps IDA quiet about malformed edits).
        """
        domain_db = _current_domain_database(required=False)
        handled, parsed = _try_domain_method(
            domain_db,
            "types",
            "parse_one_declaration",
            None,
            cdecl,
            capability="types.declaration_validation",
            unavailable_reason=(
                "ida-domain declaration validator unavailable on this build/session"
            ),
            failure_reason="ida-domain declaration validation rejected the declaration",
        )
        if handled:
            # F8 (2026-09 review): an available validator that returns None
            # is an AUTHORITATIVE rejection — never fall through to the SDK
            # retry, which could accept what the domain validator refused.
            return parsed is not None
        try:
            out_tif = ida_typeinf.tinfo_t()
            parsed_name = ida_typeinf.parse_decl(
                out_tif,
                ida_typeinf.get_idati(),
                cdecl,
                ida_typeinf.PT_TYP | ida_typeinf.PT_SIL,
            )
        except Exception:  # noqa: BLE001 — version/format tolerance
            return False
        return parsed_name is not None

    @staticmethod
    def _load_named_type(name: str) -> ida_typeinf.tinfo_t | None:
        domain_db = _current_domain_database(required=False)
        handled, domain_tinfo = _try_domain_method(
            domain_db,
            "types",
            "get_by_name",
            name,
            capability="types.named_type_reload",
            unavailable_reason=(
                "ida-domain named type lookup unavailable on this build/session"
            ),
            failure_reason="ida-domain named type reload failed on this build/session",
        )
        if handled:
            return domain_tinfo
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_named_type(ida_typeinf.get_idati(), name):
            return tinfo
        return None

    def _apply_scanned_variable_types(
        self, structure_name: str, origin: int
    ) -> ida_typeinf.tinfo_t | None:
        tinfo = self._load_named_type(structure_name)
        if tinfo is None:
            log_error(f"Created type {structure_name}, but failed to load it back.")
            self.last_apply_sites = []
            return None

        ptr_tinfo = ida_typeinf.tinfo_t()
        ptr_tinfo.create_ptr(tinfo)

        # R3.5: record every site the type just got applied to, so the
        # facade can report commit visibility (create_type's
        # ``applied_sites``). A commit with zero sites means the store
        # members carry no scanned variables — re-scan INTO this
        # structure before committing.
        applied: list[dict] = []
        failed: list = []
        seen_targets: set[tuple] = set()
        for scan_object in self.get_unique_scanned_variables(origin):
            identity_key = getattr(scan_object, "identity_key", None)
            target_key = (
                identity_key()
                if callable(identity_key)
                else (
                    getattr(scan_object, "func_ea", None),
                    getattr(scan_object, "ea", None),
                    getattr(scan_object, "id", None),
                    getattr(scan_object, "name", None),
                )
            )
            if target_key in seen_targets:
                continue
            seen_targets.add(target_key)
            try:
                scan_object.apply_type(ptr_tinfo)
            except Exception as exc:  # noqa: BLE001 — one bad site must not abort the apply
                from forge.util.logging import log_debug

                log_debug(
                    f"apply failed for {scan_object!r} after commit: {exc}"
                )
                failed.append(scan_object)
                continue
            applied.append(self._scan_site_row(scan_object))

        # R3.8: when the live scan objects are gone (catalog reload /
        # warm reopen — scan objects are never serialized, only their
        # rows), re-apply from the PERSISTED rows (netnode payload):
        # locals via modify_user_lvar_info by (func_ea, var), globals
        # via the recorded ea. Keeps the GUI's "apply across scanned
        # locations" and headless commits alive across sessions.
        if not seen_targets and self.scan_sites_rows:
            from forge.api.hexrays import is_code as _is_code

            for row in self.scan_sites_rows:
                var = row.get("var")
                func_ea = row.get("func_ea")
                site_ea = row.get("ea")
                is_global_ea = (
                    site_ea
                    and site_ea not in (None, 0, idaapi.BADADDR)
                    and not _is_code(site_ea)
                )
                ok = False
                if var and func_ea and func_ea != idaapi.BADADDR and not is_global_ea:
                    ok = _apply_lvar_pointer_type(func_ea, var, structure_name)
                elif is_global_ea:
                    ok = _apply_ea_pointer_type(site_ea, tinfo)
                if ok:
                    applied.append(dict(row))
                else:
                    failed.append(row)

        if failed and not applied:
            log_warning(
                f"Applied the committed type to none of the recorded "
                f"scan sites (structure {structure_name}); re-scan into "
                f"the structure (deep_scan with structure={structure_name!r}) "
                "or call reapply after the sites are recorded."
            )
        self.last_apply_sites = applied
        return tinfo

    @staticmethod
    def _scan_site_row(scan_object) -> dict:
        tinfo = getattr(scan_object, "tinfo", None)
        type_str = None
        dstr = getattr(tinfo, "dstr", None)
        if callable(dstr):
            try:
                type_str = dstr()
            except Exception:  # noqa: BLE001 — degraded tinfo
                type_str = None
        # Globals: the persisted site address must be the OBJECT address
        # (``_obj_ea``), not the referencing expression's instruction
        # address (``ea``) — the reload fallback re-applies at this
        # address and ``_is_code(expression_ea)`` is True, so a global
        # persisted by ``ea`` is misclassified as code and never retyped.
        site_ea = getattr(scan_object, "_obj_ea", None)
        if site_ea is None:
            site_ea = getattr(scan_object, "ea", idaapi.BADADDR)
        return {
            "func_ea": getattr(scan_object, "func_ea", idaapi.BADADDR),
            "var": getattr(scan_object, "name", None),
            "ea": site_ea,
            "type": type_str,
        }

    def set_cdecl(
        self, cdecl: str, origin: int = 0, *, overwrite: bool | None = None
    ):
        """Create/overwrite the IDA type from ``cdecl`` and apply it.

``overwrite`` controls the behavior when ``structure_name`` already
        exists as an IDA type: ``None`` asks the user (GUI flow, shown from
        :meth:`pack_structure`), ``True`` overwrites without asking, and
        ``False`` aborts. The headless ``forge_api`` facade always passes an
        explicit bool so it never raises a Qt dialog.
        """
        # R3.2 (recovery eval round 2, F1): the store packs structure
        # layouts by default. Every commit path lands here, so one wrap
        # covers the facade create_type/finalize*/create_child_types and
        # the GUI (already-wrapped text skips the wrap; the GUI keeps its
        # fixed pack(1) dialog behavior). idc_parse_types accepts the
        # pragma line; parse_decl-based gates strip it below.
        if self.pack and not cdecl.lstrip().startswith("#pragma pack"):
            cdecl = f"#pragma pack(push, {self.pack})\n{cdecl}"
        structure_name = self._extract_type_name(cdecl)
        if not structure_name:
            log_warning("Failed to determine type name from the declaration.", True)
            return None
        with _type_write_undo(f"forge: set type {structure_name}"):
            return self._set_cdecl_impl(cdecl, structure_name, origin, overwrite)

    def _set_cdecl_impl(
        self,
        cdecl: str,
        structure_name: str,
        origin: int = 0,
        overwrite: bool | None = None,
    ) -> ida_typeinf.tinfo_t | None:
        if forge_types.create_type(structure_name, cdecl):
            self.created_type_name = structure_name
            log_debug(f"Created type {structure_name}")
            return self._apply_scanned_variable_types(structure_name, origin)

        if overwrite is False:
            log_warning(
                f"Type {structure_name} already exists; skipping (overwrite disabled).",
                True,
            )
            return None

        # Local import: Qt (and its QMessageBox confirm) is only needed by the
        # GUI dialog path. The headless forge_api facade always passes an
        # explicit bool, so importing forge.util.qt here keeps the module (and
        # everything that imports it) importable without any Qt at all.
        from forge.util.qt import QtWidgets

        if overwrite is True:
            reply = QtWidgets.QMessageBox.Yes
        else:
            reply = QtWidgets.QMessageBox.question(
                None,
                "Overwrite existing type?",
                f"Type {structure_name} already exists. Overwrite?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            )
        if reply != QtWidgets.QMessageBox.Yes:
            log_error(
                f"Structure {structure_name} probably already exists. Please check manually.",
                True,
            )
            return None

        # The overwrite flow used to delete the old type before creating the
        # new one. Validate the edited declaration first so a malformed edit
        # cannot destroy the existing type (the DB would end up with no
        # type at all — which silently breaks child scans on the parent).
        if not self._declaration_parses(_strip_pragma_decl(cdecl)):
            log_error(
                "The edited declaration could not be parsed; "
                f"the existing type {structure_name} was kept.",
                True,
            )
            return None

        # R3.1 (eval review 2026-08-15): overwrite is an UPDATE, not a
        # delete. ``update_named_type`` replaces the type in place — the
        # ordinal survives, so every applied item / typedef consumer keeps
        # referencing the type (delete+recreate by ordinal left applied
        # globals pointing at a deleted type on the idalib worker).
        update_fn = getattr(ida_typeinf, "update_named_type", None)
        if callable(update_fn):
            try:
                parsed = ida_typeinf.tinfo_t()
                if ida_typeinf.parse_decl(
                    parsed,
                    ida_typeinf.get_idati(),
                    _strip_pragma_decl(cdecl),
                    ida_typeinf.PT_TYP | ida_typeinf.PT_SIL,
                ) and update_fn(ida_typeinf.get_idati(), structure_name, parsed):
                    self.created_type_name = structure_name
                    log_debug(f"Updated type {structure_name} in place")
                    return self._apply_scanned_variable_types(
                        structure_name, origin
                    )
            except Exception as exc:  # noqa: BLE001 — fall back to delete+recreate
                log_debug(
                    f"in-place update unavailable for {structure_name}: {exc}"
                )

        if not self._delete_named_type(structure_name):
            log_error(
                f"Failed to delete existing type {structure_name}; "
                "the existing (unrefined) type was kept.",
                True,
            )
            return None

        if not forge_types.create_type(structure_name, cdecl):
            log_error(f"Failed to recreate type {structure_name}", True)
            return None

        self.created_type_name = structure_name
        log_debug(f"Created type {structure_name}")
        return self._apply_scanned_variable_types(structure_name, origin)

    @staticmethod
    def _delete_named_type(structure_name: str) -> bool:
        """Delete a named type, preferring the ordinal delete.

        ``ida_typeinf.del_named_type(idati, name, 0)`` is a silent no-op on
        IDA 9.4 (the type stays resolvable, so every subsequent overwrite
        "recreate" finds the old type and fails). Deleting by ordinal
        (``get_type_ordinal`` → ``del_numbered_type``) removes it — the same
        proven pattern the vtable overwrite path uses (``members.py``).
        Returns False only when the type is still resolvable after both
        attempts, so a failed delete is loud instead of silently keeping the
        stale type.
        """
        ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, structure_name)
        if ordinal:
            idaapi.del_numbered_type(idaapi.cvar.idati, ordinal)

        if not Structure._named_type_exists(structure_name):
            return True

        # Name-delete fallback: works on some IDA versions even when the
        # ordinal delete path was unavailable.
        if hasattr(ida_typeinf, "del_named_type"):
            ida_typeinf.del_named_type(ida_typeinf.get_idati(), structure_name, 0)

        return not Structure._named_type_exists(structure_name)

    @staticmethod
    def _named_type_exists(structure_name: str) -> bool:
        tinfo = ida_typeinf.tinfo_t()
        try:
            return bool(
                tinfo.get_named_type(
                    ida_typeinf.get_idati(), structure_name, ida_typeinf.NTF_TYPE
                )
            )
        except Exception:  # noqa: BLE001 — version tolerance: older builds drop ntf_flags
            tinfo = ida_typeinf.tinfo_t()
            return bool(tinfo.get_named_type(ida_typeinf.get_idati(), structure_name))
