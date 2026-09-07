from __future__ import annotations

from dataclasses import dataclass

import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_name
import ida_typeinf

from forge.api import hexrays as hexrays_api
from forge.api.hexrays import (
    ctype,
    decompile,
    find_expr_address,
    get_argument,
    get_argument_index,
    get_func_argument_info,
    get_funcs_calling_address,
    is_imported,
    print_expr_address,
    to_hex,
)
from forge.api.scan_object import (
    CallArgumentObject,
    ObjectType,
    ScanObject,
    VariableObject,
    _extract_offset_expression,
    _make_offset_scan_object,
)
from forge.api.types import types
from forge.util.logging import log_debug, log_info, log_trace, log_warning


@dataclass(frozen=True)
class RecursiveCallFrame:
    """One caller-argument scan position in the recursive call tree.

    ``base_offset`` is the byte offset within the ROOT scanned structure at
    which this callee's view of the object starts: it accumulates the argument
    offsets along the caller chain so member observations recorded during the
    callee scan can be placed absolutely by the hierarchy session.
    """

    frame_id: int
    parent_frame_id: int | None
    function_ea: int
    argument_index: int
    call_site_ea: int
    base_offset: int
    depth: int


class ObjectVisitor(ida_hexrays.ctree_parentee_t):
    def __init__(
        self, cfunc: ida_hexrays.cfunc_t, obj: ScanObject, data, skip_until_object: bool
    ):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self._cfunc = cfunc
        self._objects = [obj]
        self._init_obj = obj
        self._data = data
        self._start_ea = obj.ea
        self._skip = (
            skip_until_object if self._start_ea != ida_idaapi.BADADDR else False
        )
        self.crippled = False

    def process(self):
        self.apply_to(self._cfunc.body, None)

    def set_callbacks(self, manipulate=None):
        if manipulate:
            self.__manipulate = manipulate.__get__(self, DownwardsObjectVisitor)

    def _manipulate(self, cexpr, obj):
        """
        Method called for every object having assignment relationship with starter object. This method should be
        reimplemented in order to do something useful

        :param cexpr: idaapi_cexpr_t
        :param obj: The scan object
        :return: None
        """
        self.__manipulate(cexpr, obj)

    def __manipulate(self, cexpr, obj):
        log_debug(f"Expression {cexpr.opname} at {print_expr_address(cexpr, self.parents)} Id - {getattr(obj, 'id', None)}")

    def get_line(self) -> str:
        return hexrays_api.get_line(self, self._cfunc)


class DownwardsObjectVisitor(ObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object: bool = False,
    ):
        ObjectVisitor.__init__(self, cfunc, obj, data, skip_until_object)
        self.cv_flags |= getattr(ida_hexrays, "CV_POST", 0)
        self._rescan_current_function = False

    def _create_scan_object_from_expr(
        self, expr: ida_hexrays.cexpr_t | None
    ) -> ScanObject | None:
        if expr is None:
            return None

        base_expr, offset = _extract_offset_expression(expr)
        if base_expr is None:
            return None

        scan_object = ScanObject.create(self._cfunc, base_expr, promote_root=False)
        if scan_object is None:
            return None

        # R3.13: refuse to wrap a member-reference around a DIFFERENT
        # lvar than the scan root when its allocator size disagrees with
        # the root's.  Prevents ``v0->field = v2`` (where v0 is a
        # 0x38-byte calloc target and v2 is the 0x2C-byte scan root)
        # from depositing v0's members into the root's structure.
        if (
            isinstance(scan_object, VariableObject)
            and isinstance(self._init_obj, VariableObject)
            and scan_object is not self._init_obj
        ):
            if getattr(scan_object, "alloc_size", None) is None:
                scan_object.alloc_size = self._resolve_init_alloc_size(
                    getattr(scan_object, "index", -1)
                )
            if getattr(scan_object, "alloc_size", None) is not None and (
                getattr(self._init_obj, "alloc_size", None) is None
                or scan_object.alloc_size != self._init_obj.alloc_size
            ):
                log_debug(
                    f"refusing member-wrap for {scan_object.name} (alloc "
                    f"{scan_object.alloc_size:#x}); scan-root "
                    f"{self._init_obj.name} (alloc {self._init_obj.alloc_size})"
                )
                return None

        return _make_offset_scan_object(scan_object, offset)

    def _resolve_init_alloc_size(self, lvar_index: int) -> int | None:
        """Wrap the shared ``resolve_lvar_init_alloc_size`` helper (R3.13).
        Kept as a method so test mocks can monkeypatch it.
        """
        from forge.api.scan_object import resolve_lvar_init_alloc_size

        return resolve_lvar_init_alloc_size(self._cfunc, lvar_index)

    def _append_scan_object(
        self, new_obj: ScanObject | None, source_obj: ScanObject
    ) -> None:
        if new_obj is None or new_obj in self._objects:
            return

        if hasattr(new_obj, "inherit_scan_root_from"):
            new_obj.inherit_scan_root_from(source_obj)
        # R3.13: refuse to add a VariableObject whose known alloc size
        # conflicts with an already-tracked VariableObject (typically
        # ``self._init_obj``).  Prevents the ``v0->field = v2`` LHS walk
        # from pulling v0 in as a new scan root when the scan was
        # started on v2.  Same rule as the upwards-visitor's closure.
        if isinstance(new_obj, VariableObject):
            new_alloc = getattr(new_obj, "alloc_size", None)
            if new_alloc is None:
                # Resolve lazily so the mid-walk path doesn't pay a ctree
                # walk for objects that never conflict.
                try:
                    new_alloc = self._resolve_init_alloc_size(
                        getattr(new_obj, "index", -1)
                    )
                    if new_alloc is not None:
                        new_obj.alloc_size = new_alloc
                except Exception:  # noqa: BLE001 — best-effort
                    new_alloc = None
            if isinstance(new_alloc, int) and new_alloc > 0:
                # The scan root may have been REMOVED from self._objects
                # by its own calloc write ("Remove object v2 from
                # scanning" — _is_object_overwritten treats the allocator
                # assignment as an overwrite).  Compare against the
                # immutable _init_obj in addition to the live list.
                candidates = list(self._objects)
                init_obj = getattr(self, "_init_obj", None)
                if init_obj is not None and init_obj not in candidates:
                    candidates.append(init_obj)
                for existing in candidates:
                    if not isinstance(existing, VariableObject):
                        continue
                    ex_alloc = getattr(existing, "alloc_size", None)
                    if (
                        isinstance(ex_alloc, int)
                        and ex_alloc > 0
                        and ex_alloc != new_alloc
                    ):
                        log_debug(
                            f"refusing scan-root merge of {new_obj.name} "
                            f"(alloc {new_alloc:#x}) with "
                            f"{existing.name} (alloc {ex_alloc:#x})"
                        )
                        return
        self._objects.append(new_obj)
        if (
            getattr(new_obj, "func_ea", ida_idaapi.BADADDR)
            == getattr(self._cfunc, "entry_ea", ida_idaapi.BADADDR)
        ):
            self._rescan_current_function = True

    def _matches_object(self, obj: ScanObject, cexpr: ida_hexrays.cexpr_t) -> bool:
        target_matches = getattr(obj, "is_target", None)
        if callable(target_matches):
            return target_matches(cexpr)

        obj_ea = getattr(obj, "ea", ida_idaapi.BADADDR)
        if obj_ea == ida_idaapi.BADADDR:
            return False

        parents = getattr(self, "parents", [])
        return obj_ea == find_expr_address(cexpr, parents)


    def visit_expr(self, cexpr: ida_hexrays.cexpr_t):
        if self._skip:
            if self._is_initial_object(cexpr):
                self._skip = False
            else:
                return 0

        if cexpr.op != ctype.asg:
            return 0

        x_cexpr = cexpr.x
        if cexpr.y.op == ctype.cast:
            y_cexpr: ida_hexrays.cexpr_t = cexpr.y.x
        else:
            y_cexpr: ida_hexrays.cexpr_t = cexpr.y

        for obj in self._objects:
            if self._matches_object(obj, x_cexpr):
                if self._is_object_overwritten(y_cexpr):
                    log_info(
                        f"Remove object {obj} from scanning at {print_expr_address(x_cexpr, self.parents)}"
                    )
                    self._objects.remove(obj)
                else:
                    self._append_scan_object(
                        self._create_scan_object_from_expr(y_cexpr), obj
                    )
            elif self._matches_object(obj, y_cexpr):
                self._append_scan_object(
                    self._create_scan_object_from_expr(x_cexpr), obj
                )
                return 0

        return 0


    def leave_expr(self, cexpr: ida_hexrays.cexpr_t):
        if self._skip:
            return 0
        for obj in self._objects:
            if self._matches_object(obj, cexpr) and getattr(obj, 'id', None) != ObjectType.returned_object:
                self._manipulate(cexpr, obj)
                return 0
        return 0



    def _is_initial_object(self, cexpr: ida_hexrays.cexpr_t):
        if cexpr.op == ctype.asg:
            cexpr = cexpr.y
            if cexpr.op == ctype.cast:
                cexpr = cexpr.x

        return self._matches_object(self._init_obj, cexpr) and find_expr_address(
            cexpr, self.parents
        ) == self._start_ea



    def _is_object_overwritten(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        if len(self._objects) < 2:
            return False

        e = cexpr.x if cexpr.op == ctype.cast else cexpr

        if e.op != ctype.call or len(e.a) == 0:
            return True

        return all(not self._matches_object(obj, e.a[0]) for obj in self._objects)



class UpwardsObjectVisitor(ObjectVisitor):
    STAGE_PREPARE = 1
    STAGE_PARSING = 2

    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object=False,
    ):
        ObjectVisitor.__init__(self, cfunc, obj, data, skip_until_object)
        self._stage = self.STAGE_PREPARE
        self._tree = {}
        self._call_obj = obj if getattr(obj, 'id', None) == ObjectType.call_argument else None

    def visit_expr(self, cexpr: ida_hexrays.cexpr_t):
        if self._stage == self.STAGE_PARSING:
            return 0

        if self._call_obj and self._matches_object(self._call_obj, cexpr):
            obj = self._call_obj.create_scan_object(self._cfunc, cexpr)
            if obj:
                self._objects.append(obj)
            return 0

        if cexpr.op != ctype.asg:
            return 0

        x_cexpr = cexpr.x
        y_cexpr = cexpr.y.x if cexpr.y.op == ctype.cast else cexpr.y

        obj_left = ScanObject.create(self._cfunc, x_cexpr, promote_root=False)
        obj_right = ScanObject.create(self._cfunc, y_cexpr, promote_root=False)
        if obj_left is not None and obj_right is not None:
            # R3.12: capture the allocator size on the LHS lvar so a later
            # transitive closure (e.g. ``v4 = v0; v4 = v2`` via a phi at
            # an if/else join) doesn't fold distinct allocations.
            self._record_alloc_size(obj_left, y_cexpr)
            self._add_object_assignment(obj_left, obj_right)

        if self._skip and self._is_initial_object(cexpr):
            return 1
        return 0

    def leave_expr(self, cexpr: ida_hexrays.cexpr_t):
        if self._stage == self.STAGE_PREPARE:
            return 0

        if self._skip and self._is_initial_object(cexpr):
            self._manipulate(cexpr, self._init_obj)
            return 1

        for obj in self._objects:
            if self._matches_object(obj, cexpr):
                self._manipulate(cexpr, obj)
                return 0
        return 0


    def process(self):
        self._stage = self.STAGE_PREPARE
        self.cv_flags &= ~getattr(ida_hexrays, "CV_POST", 0)
        super().process()
        self._stage = self.STAGE_PARSING
        self.cv_flags |= getattr(ida_hexrays, "CV_POST", 0)
        self._prepare()
        super().process()

    def _is_initial_object(self, cexpr: ida_hexrays.cexpr_t):
        return self._matches_object(self._init_obj, cexpr) and find_expr_address(
            cexpr, self.parents
        ) == self._start_ea


    def _record_alloc_size(self, lhs_obj, rhs_cexpr) -> None:
        """R3.12: when ``lhs = calloc(...)`` (or any tracked allocator), tag
        the lhs ``VariableObject`` with ``alloc_size`` so a later phi-driven
        transitive closure doesn't fold it with an lvar of a different size.
        """
        if not isinstance(lhs_obj, VariableObject):
            return
        if getattr(lhs_obj, "alloc_size", None) is not None:
            # First record wins — re-initialising an already-sized lvar
        # is a separate bug surface and shouldn't override the original.
            return
        from forge.api.scan_object import MemoryAllocationObject

        alloc = MemoryAllocationObject.create(self._cfunc, rhs_cexpr)
        if alloc is None:
            return
        lhs_obj.alloc_size = alloc.size

    def _add_object_assignment(self, from_obj, to_obj):
        if from_obj in self._tree:
            self._tree[from_obj].add(to_obj)
        else:
            self._tree[from_obj] = {to_obj}

    @staticmethod
    def _alloc_size(obj) -> tuple:
        """Stable key for the lvar's alloc identity — (size_or_None,).
        Used to refuse transitive merges that would fold distinct
        allocations (R3.12).  Duck-types on ``alloc_size`` so test fakes
        and any object that carries the attribute are accepted.
        """
        if not isinstance(obj, ScanObject):
            return ()
        sz = getattr(obj, "alloc_size", None)
        if isinstance(sz, int) and sz > 0:
            return (sz,)
        return ()

    def _prepare(self):
        # R3.12: refuse to merge two VariableObjects through the
        # transitive closure when their alloc sizes disagree.  Known
        # sizes seen during the closure run are tracked in
        # ``seen_sizes``; a known size conflicting with an
        # already-seen known size is rejected, and a SECOND DISTINCT
        # known size is rejected too — it must never be folded into
        # the accepted set, or later known-size objects are skipped
        # asymmetrically and their subtrees orphaned.  Unknown sizes
        # stay permissive.
        accepted_objects: set = set()
        seen_sizes: set[tuple] = set()
        pending: set = set(self._objects)
        while pending:
            current_object = pending.pop()
            object_alloc_size = self._alloc_size(current_object)
            if object_alloc_size and any(
                sz != object_alloc_size for sz in seen_sizes
            ):
                # size mismatch with an already-seen allocation — skip
                # this object; do not propagate its assignments.
                continue
            accepted_objects.add(current_object)
            if object_alloc_size:
                seen_sizes.add(object_alloc_size)
            if (
                getattr(current_object, "id", None) == ObjectType.call_argument
                or current_object not in self._tree
            ):
                continue
            children = self._tree[current_object]
            known_child_sizes = {
                size
                for child in children
                if (size := self._alloc_size(child))
            }
            if not object_alloc_size and len(known_child_sizes) > 1:
                # R3.12: an UNKNOWN-size parent (e.g. a phi-merged lvar
                # ``void *p; if (c) p = a(0x2C); else p = b(0x38)``)
                # whose children carry two distinct known sizes would
                # batch-accept and fold two different allocations.
                # Reject the parent's propagation entirely: the parent
                # stays accepted, but its children are not pulled in.
                # Parents with a known size (or children with a single
                # consistent known size) keep the validated behavior.
                log_debug(
                    "refusing upwards closure through unknown-size "
                    "parent with conflicting child alloc sizes "
                    f"{sorted(sz[0] for sz in known_child_sizes)}"
                )
                continue
            # R3.12: when propagating, drop any child whose known alloc
            # size conflicts with a known size seen in this closure.
            eligible_children = {
                child
                for child in children
                if not self._alloc_size(child)
                or not any(
                    sz != self._alloc_size(child) for sz in seen_sizes
                )
            }
            pending |= eligible_children - accepted_objects
            accepted_objects |= eligible_children
        self._objects = list(accepted_objects)
        self._tree.clear()


class RecursiveObjectVisitor(ObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object=False,
        visited: set | None = None,
    ):
        ObjectVisitor.__init__(self, cfunc, obj, data, skip_until_object)
        self._visited: set = visited if visited is not None else set()
        self._new_for_visit: set[tuple[int, int]] = set()
        self.crippled: bool = False
        self._arg_index: int | None = -1
        self._debug_scan_tree: dict[tuple[str, int], set[tuple[str, int]]] = {}
        self._debug_scan_tree_root: str = ida_funcs.get_func_name(self._cfunc.entry_ea)
        self._debug_message: list[str] = []

    def visit_expr(self, cexpr: ida_hexrays.cexpr_t):
        return super().visit_expr(cexpr)

    # noinspection PyAttributeOutsideInit
    def set_callbacks(
        self,
        manipulate=None,
        start=None,
        start_iteration=None,
        finish=None,
        finish_iteration=None,
    ):
        super().set_callbacks(manipulate)
        if start:
            self._start = start.__get__(self, RecursiveDownwardsObjectVisitor)
        if start_iteration:
            self._start_iteration = start_iteration.__get__(
                self, RecursiveDownwardsObjectVisitor
            )
        if finish:
            self._finish = finish.__get__(self, RecursiveDownwardsObjectVisitor)
        if finish_iteration:
            self._finish_iteration = finish_iteration.__get__(
                self, RecursiveDownwardsObjectVisitor
            )

    def prepare_new_scan(self, cfunc, arg_idx, obj, skip=False):
        self._cfunc: ida_hexrays.cfunc_t = cfunc
        self._arg_index = arg_idx
        self._objects = [obj]
        self._skip = skip
        self._init_obj = obj
        self.crippled = self._is_func_crippled()
        log_trace(
            f"Preparing scan of {getattr(cfunc, 'entry_ea', ida_idaapi.BADADDR)} "
            f"arg_idx={arg_idx} obj={getattr(obj, 'name', None)} skip={skip}"
        )

    def process(self):
        """Run the visitor lifecycle and render its scan tree.

        ``_finish`` always runs after recursive processing starts. If either
        body or finish callback raises, normal Python exception precedence
        applies; scan-tree rendering is skipped on failure.
        """
        self._start()
        try:
            self._recursive_process()
        finally:
            self._finish()
        self.dump_scan_tree()

    def dump_scan_tree(self):
        """Reset, render, and log the current scan tree.

        Rendering and logging errors intentionally propagate to the caller;
        diagnostics must not silently hide a failed render.
        """
        self._debug_message.clear()
        self._prepare_scan_tree()
        newline = "\n"
        log_info(f"{newline.join(self._debug_message)}\n---------------")

    def _prepare_scan_tree(
        self,
        key=None,
        level=1,
        _path: set[tuple[str, int]] | None = None,
    ):
        """Render scan-tree paths without Python recursion limits.

        ``_path`` is path-local, not global, so shared descendants remain
        visible for each distinct parent path while recursive cycles terminate.
        An explicit stack keeps deep call graphs renderable without changing
        ordering, indentation, or caller-supplied path ownership.
        """
        if _path is None:
            _path = set()
        if key is None:
            key = (self._debug_scan_tree_root, -1)
            self._debug_message.append(
                f"\n--- Scan Tree ---\n{self._debug_scan_tree_root}"
            )
        stack = [(key, level, False, True)]
        try:
            while stack:
                current_key, current_level, exiting, is_root = stack.pop()
                if exiting:
                    _path.remove(current_key)
                    continue
                if not is_root:
                    func_name, arg_idx = current_key
                    prefix = " | " * (current_level - 2) + " |_ "
                    self._debug_message.append(
                        f"{prefix}{func_name}(idx: {arg_idx})"
                    )
                if current_key in _path:
                    continue
                _path.add(current_key)
                stack.append((current_key, current_level, True, is_root))
                children = sorted(self._debug_scan_tree.get(current_key, ()))
                # LIFO stack: push ascending siblings reversed so each
                # sibling's own line and subtree render in ascending order.
                for child in reversed(children):
                    stack.append((child, current_level + 1, False, False))
        finally:
            while stack:
                current_key, _current_level, exiting, _is_root = stack.pop()
                if exiting and current_key in _path:
                    _path.remove(current_key)
    def _recursive_process(self):
        """Run one recursive pass and always finish its iteration callback."""
        self._start_iteration()
        try:
            super().process()
        finally:
            self._finish_iteration()

    def _check_call(self, cexpr: ida_hexrays.cexpr_t):
        raise NotImplementedError

    def _add_visit(self, func_ea, arg_idx):
        if (func_ea, arg_idx) not in self._visited:
            log_debug(f"Add visit {to_hex(func_ea)} {arg_idx}\n\n")
            self._visited.add((func_ea, arg_idx))
            self._new_for_visit.add((func_ea, arg_idx))
            return True
        return False

    def _add_scan_tree_info(self, func_ea, arg_idx):
        head_node = (ida_funcs.get_func_name(self._cfunc.entry_ea), self._arg_index)
        tail_node = (ida_funcs.get_func_name(func_ea), arg_idx)
        if head_node in self._debug_scan_tree:
            self._debug_scan_tree[head_node].add(tail_node)
        else:
            self._debug_scan_tree[head_node] = {tail_node}

    def _start(self):
        """Called at the beginning of visiting"""

    def _start_iteration(self):
        """Called every time new function visiting started"""

    def _finish(self):
        """Called after all visiting happened"""

    def _finish_iteration(self):
        """Called every time new function visiting finished"""

    def _is_func_crippled(self):
        # Check if function is just call to another function
        b = self._cfunc.body.cblock
        if b.size() == 1:
            e = b.at(0)
            return e.op == ida_hexrays.cit_return or (
                e.op == ida_hexrays.cit_expr and e.cexpr.op == ctype.call
            )
        return False


class RecursiveDownwardsObjectVisitor(RecursiveObjectVisitor, DownwardsObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object=False,
        visited=None,
        recurse_calls: bool = False,
        max_depth: int | None = None,
    ):
        RecursiveObjectVisitor.__init__(self, cfunc, obj, data, skip_until_object, visited)
        self.cv_flags |= getattr(ida_hexrays, "CV_POST", 0)
        self._rescan_current_function = False
        self._recurse_calls = recurse_calls
        self._max_depth = max_depth
        self._visit_base_offsets: dict[tuple[int, int], int] = {}
        root_frame = RecursiveCallFrame(
            frame_id=0,
            parent_frame_id=None,
            function_ea=cfunc.entry_ea,
            argument_index=-1,
            call_site_ea=ida_idaapi.BADADDR,
            base_offset=0,
            depth=0,
        )
        self._call_frames: dict[int, RecursiveCallFrame] = {0: root_frame}
        self._frame_children: dict[int, list[int]] = {0: []}
        self._frame_aliases: dict[int, int] = {}
        self._visited_frames: dict[tuple[int, int], int] = {}
        self._evidence_cache: dict[tuple[int, int, int], int] = {}
        self._current_frame = root_frame
        self._next_frame_id = 1
        # Deep scans queue whole RecursiveCallFrame visits (shallow/upwards
        # visitors keep the base tuple set) so every nested scan knows which
        # caller position it is observing and can report it to a member sink.
        self._new_for_visit: list[RecursiveCallFrame] = []

    @property
    def current_frame(self) -> RecursiveCallFrame:
        return self._current_frame

    @property
    def call_frames(self) -> tuple[RecursiveCallFrame, ...]:
        return tuple(self._call_frames[frame_id] for frame_id in sorted(self._call_frames))

    @property
    def frame_aliases(self) -> dict[int, int]:
        return dict(self._frame_aliases)

    def canonical_frame_id(self, frame_id: int) -> int:
        while frame_id in self._frame_aliases:
            frame_id = self._frame_aliases[frame_id]
        return frame_id

    def _has_active_ancestor(self, function_ea: int, argument_index: int) -> bool:
        frame: RecursiveCallFrame | None = self._current_frame
        while frame is not None:
            if (
                frame.function_ea == function_ea
                and frame.argument_index == argument_index
            ):
                return True
            if frame.parent_frame_id is None:
                break
            frame = self._call_frames[frame.parent_frame_id]
        return False

    def _add_visit(
        self,
        func_ea: int,
        arg_idx: int,
        call_site_ea: int = ida_idaapi.BADADDR,
        relative_offset: int = 0,
    ) -> bool:
        parent_frame = self._current_frame
        depth = parent_frame.depth + 1
        if self._max_depth is not None and depth > self._max_depth:
            return False
        if self._has_active_ancestor(func_ea, arg_idx):
            return False

        frame = RecursiveCallFrame(
            frame_id=self._next_frame_id,
            parent_frame_id=parent_frame.frame_id,
            function_ea=func_ea,
            argument_index=arg_idx,
            call_site_ea=call_site_ea,
            base_offset=parent_frame.base_offset + relative_offset,
            depth=depth,
        )
        self._next_frame_id += 1
        self._call_frames[frame.frame_id] = frame
        self._frame_children.setdefault(frame.parent_frame_id, []).append(frame.frame_id)
        self._frame_children[frame.frame_id] = []

        cache_key = (func_ea, arg_idx, frame.base_offset)
        canonical_frame_id = self._evidence_cache.get(cache_key)
        if (func_ea, arg_idx) in self._visited or canonical_frame_id is not None:
            # Already covered by an earlier scan position: keep the frame in
            # the tree for evidence bookkeeping but alias it to the canonical
            # (actually scanned) frame instead of rescanning.  A revisit at a
            # DIFFERENT base_offset has no evidence-cache entry (the cache is
            # keyed by offset); alias it to the earlier (func_ea, arg_idx)
            # frame anyway — offsets differ, but the earlier frame is the one
            # that actually scanned this callee, so canonical_frame_id keeps
            # finding a covering scan.
            if canonical_frame_id is not None:
                self._frame_aliases[frame.frame_id] = canonical_frame_id
            else:
                earlier_frame_id = self._visited_frames.get((func_ea, arg_idx))
                if earlier_frame_id is not None:
                    self._frame_aliases[frame.frame_id] = earlier_frame_id
            return False
        self._visited.add((func_ea, arg_idx))
        self._visited_frames[(func_ea, arg_idx)] = frame.frame_id
        self._evidence_cache[cache_key] = frame.frame_id
        log_debug(
            f"Add visit {to_hex(func_ea)} {arg_idx} at {to_hex(frame.base_offset)}\n\n"
        )
        self._new_for_visit.append(frame)
        return True


    def _referenced_object(self, cexpr):
        """The first scan object the expression subtree references, or None."""
        work: list[tuple[object, bool]] = [(cexpr, False)]
        while work:
            expr, addr_ctx = work.pop()
            if expr is None:
                continue
            if not addr_ctx:
                for obj in self._objects:
                    try:
                        if self._matches_object(obj, expr):
                            return obj
                    except Exception as exc:  # noqa: BLE001 — per-object matching is best-effort
                        log_debug(f"Ignoring object match failure for {getattr(obj, 'name', obj)!r}: {exc}")
            op = getattr(expr, "op", None)
            if op == ctype.cast:
                work.append((getattr(expr, "x", None), addr_ctx))
            elif op in (ctype.add, ctype.sub):
                work.append((getattr(expr, "x", None), addr_ctx))
                work.append((getattr(expr, "y", None), addr_ctx))
            elif op == ctype.ref:
                work.append((getattr(expr, "x", None), True))
            elif op == ctype.memptr:
                if addr_ctx:
                    work.append((getattr(expr, "x", None), False))
            elif op == ctype.memref and addr_ctx:
                work.append((getattr(expr, "x", None), True))
        return None

    def _expression_references_object(self, cexpr) -> bool:
        return self._referenced_object(cexpr) is not None

    _MEMORY_WRITER_CALLS = frozenset(
        {"strcpy", "strncpy", "strcat", "memcpy", "memmove", "memset"}
    )

    def _string_writer_tinfo(self, source_arg):
        """Member type for a memory-writer site: ``char[N+1]`` when the
        source is a string literal, plain ``char`` otherwise."""
        str_op = getattr(ctype, "str", None)
        if str_op is not None and getattr(source_arg, "op", None) == str_op:
            text = getattr(source_arg, "string", "") or ""
            array_data = ida_typeinf.array_type_data_t()
            array_data.base = 0
            array_data.elem_type = ida_typeinf.tinfo_t(types["char"].type)
            array_data.nelems = len(text) + 1  # NUL terminator
            array_tinfo = ida_typeinf.tinfo_t()
            array_tinfo.create_array(array_data)
            return array_tinfo
        return ida_typeinf.tinfo_t(types["char"].type)

    def _maybe_add_memory_writer_member(self, call_cexpr, dest_arg):
        """I.20: a write through a known memory helper into the scanned
        object's buffer is evidence of a named field.

        ``strcpy(root + 0x10, src)`` synthesizes a member at ``0x10``. Only
        the fixed six writers are allowlisted — that list is the guard
        against varargs-style functions (``printf``) framing unrelated
        strings as writes.
        """
        if not (hasattr(self, "_get_member") and hasattr(self, "_structure")):
            return
        writer_ea = getattr(getattr(call_cexpr, "x", None), "obj_ea", None)
        if writer_ea in (None, ida_idaapi.BADADDR):
            return
        canonical = (ida_name.get_name(writer_ea) or "").split("@")[0].lower()
        if canonical not in self._MEMORY_WRITER_CALLS:
            return
        if not self._expression_references_object(dest_arg):
            return
        _base, offset = _extract_offset_expression(dest_arg)
        if offset is None:
            return
        source_arg = None
        call_args = getattr(call_cexpr, "a", ()) or ()
        if len(call_args) >= 2:
            source_arg = call_args[1]
        obj = self._referenced_object(dest_arg)
        if obj is None:
            return
        try:
            member = self._get_member(
                offset, dest_arg, obj, self._string_writer_tinfo(source_arg)
            )
        except Exception:  # noqa: BLE001 — writer synthesis is best-effort
            return
        if member is not None:
            log_debug(f"[I.20] memory-writer member at 0x{offset:x} via {canonical}")
            emitter = getattr(self, "_emit_member", None)
            if callable(emitter):
                # NewDeepScanVisitor with a member sink routes every member
                # (including synthesized ones) through the frame-aware path.
                emitter(member)
            else:
                self._structure.add_member(member)

    def _is_unplaceable_call_argument(self, cexpr) -> bool:
        """True when the call argument's expression cannot be pinned to a
        fixed offset of the scanned object (indexed / pointer-member loads).
        """
        indexed_op = getattr(ctype, "idx", None)
        pointer_member_op = getattr(ctype, "memptr", None)
        work = [cexpr]
        while work:
            expr = work.pop()
            if expr is None:
                continue
            op = getattr(expr, "op", None)
            if op in (indexed_op, pointer_member_op):
                return True
            work.append(getattr(expr, "x", None))
            work.append(getattr(expr, "y", None))
        return False

    def _argument_is_tracked_root(self, cexpr) -> bool:
        """True when the call argument's value is itself a tracked scan object.

        Deep-scanning a pointer that lives in a member/indexed expression (for
        example ``this->u32_28`` typed as a scalar but used as a pointer) must
        follow that value into the callee to reconstruct what it points at.
        Such an argument otherwise looks ``unplaceable`` because it contains a
        ``memptr``/``idx`` node. Only the argument value itself qualifies here;
        a sub-field address like ``&a1->field`` does not, so embedded-hierarchy
        placement rules are unaffected.
        """
        expr = cexpr
        cast_op = getattr(ctype, "cast", None)
        while expr is not None and getattr(expr, "op", None) == cast_op:
            expr = getattr(expr, "x", None)
        if expr is None:
            return False
        return any(self._matches_object(obj, expr) for obj in self._objects)


    def _check_call(self, cexpr: ida_hexrays.cexpr_t):
        parent: ida_hexrays.cexpr_t | None = self.parent_expr()
        if parent is None:
            return
        grandparent: ida_hexrays.cexpr_t | None = None
        if self.parents.size() >= 2:
            grandparent = self.parents.at(self.parents.size() - 2)
        if parent.op == ctype.call:
            call_cexpr = parent
            arg_cexpr = cexpr
        elif parent.op == ctype.cast and grandparent is not None and grandparent.op == ctype.call:
            call_cexpr = grandparent.cexpr
            arg_cexpr = parent
        else:
            return

        if not self._expression_references_object(cexpr):
            return
        is_tracked_root = self._argument_is_tracked_root(cexpr)
        if not is_tracked_root and self._is_unplaceable_call_argument(cexpr):
            return
        _, arg_offset = _extract_offset_expression(cexpr)
        if arg_offset is None:
            arg_offset = 0
        idx, _ = get_func_argument_info(call_cexpr, arg_cexpr)
        if idx is None:
            return
        func_ea = call_cexpr.x.obj_ea
        if func_ea == ida_idaapi.BADADDR:
            return
        # I.20: the checked expression being the destination (arg 0) of a
        # memory helper is a write into the object's buffer — synthesize a
        # member for it before the ordinary argument-tracking path.
        if idx == 0:
            self._maybe_add_memory_writer_member(call_cexpr, arg_cexpr)
        # A tracked-root pointer passed by value opens a fresh pointee at
        # base 0; the parser's offset there is the member's slot inside its
        # own parent, which is irrelevant to what the pointer points at.
        relative_offset = 0 if is_tracked_root else arg_offset
        call_site_ea = getattr(call_cexpr, "ea", ida_idaapi.BADADDR)
        if self._add_visit(func_ea, idx, call_site_ea, relative_offset):
            self._visit_base_offsets[(func_ea, idx)] = arg_offset
            self._add_scan_tree_info(func_ea, idx)

    def leave_expr(self, cexpr):
        if getattr(self, "_recurse_calls", False):
            self._check_call(cexpr)
        return super().leave_expr(cexpr)

    def _refresh_decompilation_tree(self, cfunc: ida_hexrays.cfunc_t | None = None) -> ida_hexrays.cfunc_t | None:
        target_cfunc = cfunc or self._cfunc
        refreshed = refresh_function_tree(target_cfunc)
        if refreshed is not None:
            return refreshed
        return target_cfunc

    def _scan_single_function(self):
        self._cfunc = self._refresh_decompilation_tree(self._cfunc)
        MAX_RESCANS = 10
        for _ in range(MAX_RESCANS):
            self._rescan_current_function = False
            super()._recursive_process()
            if not self._rescan_current_function:
                break

    _VISIT_DEFERRED = object()

    def _execute_visit(self, frame: RecursiveCallFrame):
        """Scan one caller-argument frame and spool the frames it discovered.

        Nested visitor state is restored and the shared visit queue is cleared
        in all outcomes before returning or propagating an exception.

        Returns:
          - a list of child RecursiveCallFrame visits to queue,
          - ``_VISIT_DEFERRED`` when the callee cannot accept the argument yet
            (argidx unknown mid-analysis) and the visit must be retried,
          - ``None`` when the visit is dropped (decompilation failure or
            varargs callee).
        """
        cfunc = decompile(frame.function_ea)
        if cfunc is None:
            return None
        cfunc = self._refresh_decompilation_tree(cfunc)
        if cfunc is None:
            return None

        # O2: varargs callees (printf-style loggers, formatting helpers) can
        # never frame the scanned object as a member — their bodies treat
        # every argument list as format input and pollute the scan with
        # bogus members (the 2026-08-11 format-string pollution). Drop the
        # visit instead of scanning them.
        func_type = getattr(cfunc, "type", None)
        is_vararg_cc = getattr(func_type, "is_vararg_cc", None)
        if callable(is_vararg_cc) and is_vararg_cc():
            log_debug(
                f"Skipping varargs callee {to_hex(frame.function_ea)} - format-style body"
            )
            return None

        arg_idx = frame.argument_index
        argidx = getattr(cfunc, "argidx", ())
        if arg_idx is None or arg_idx < 0 or arg_idx >= len(argidx):
            return self._VISIT_DEFERRED

        arg, lvar_idx = get_argument(cfunc, arg_idx)
        obj = VariableObject(arg, lvar_idx)

        saved_cfunc: ida_hexrays.cfunc_t = self._cfunc
        saved_arg_index: int | None = getattr(self, "_arg_index", None)
        saved_objects: list[ScanObject] = list(getattr(self, "_objects", []))
        saved_skip: bool = getattr(self, "_skip", False)
        saved_init_obj: ScanObject | None = getattr(self, "_init_obj", None)
        saved_base_offset: int = self._callee_base_offset
        saved_frame: RecursiveCallFrame = self._current_frame

        try:
            self._callee_base_offset = frame.base_offset
            self._current_frame = frame
            self.prepare_new_scan(cfunc, lvar_idx, obj)
            self._scan_single_function()
            children: list[RecursiveCallFrame] = list(self._new_for_visit)
            self._new_for_visit.clear()
            return children
        finally:
            self._new_for_visit.clear()
            self._callee_base_offset = saved_base_offset
            self._cfunc = saved_cfunc
            self._arg_index = saved_arg_index
            self._objects = saved_objects
            self._skip = saved_skip
            self._init_obj = saved_init_obj
            self._current_frame = saved_frame

    def _recursive_process(self):
        """Run the root scan, then process caller-argument frames.

        Deferred frames (callee argidx not resolved yet) are retried after
        the queue drains; the loop stops as soon as a full pass makes no
        progress so mid-analysis callees cannot spin the scan forever.
        """
        try:
            self._scan_single_function()

            pending_visits: list[RecursiveCallFrame] = sorted(
                self._new_for_visit,
                key=lambda frame: (
                    frame.function_ea,
                    frame.argument_index,
                    frame.base_offset,
                ),
            )
            self._new_for_visit.clear()
            deferred_visits: list[RecursiveCallFrame] = []

            while pending_visits or deferred_visits:
                progressed = False
                while pending_visits:
                    frame = pending_visits.pop()

                    outcome = self._execute_visit(frame)
                    if outcome is self._VISIT_DEFERRED:
                        deferred_visits.append(frame)
                        continue
                    if outcome:
                        pending_visits.extend(outcome)
                        progressed = True

                if not deferred_visits or not progressed:
                    break
                pending_visits, deferred_visits = deferred_visits, []
        finally:
            self._new_for_visit.clear()

class RecursiveUpwardsObjectVisitor(RecursiveObjectVisitor, UpwardsObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object=False,
        visited=None,
    ):
        RecursiveObjectVisitor.__init__(self, cfunc, obj, data, skip_until_object, visited)
        self._stage = self.STAGE_PREPARE
        self._tree = {}
        self._call_obj = obj if getattr(obj, 'id', None) == ObjectType.call_argument else None

    def prepare_new_scan(self, cfunc, arg_idx, obj, skip=False):
        super().prepare_new_scan(cfunc, arg_idx, obj, skip)
        self._call_obj = obj if getattr(obj, 'id', None) == ObjectType.call_argument else None

    def _check_call(self, cexpr: ida_hexrays.cexpr_t):
        if cexpr.op != ctype.var:
            return
        if not any(self._matches_object(obj, cexpr) for obj in self._objects):
            return

        lvars = self._cfunc.get_lvars()
        if cexpr.v.idx < 0 or cexpr.v.idx >= len(lvars):
            return
        if not lvars[cexpr.v.idx].is_arg_var:
            return
        func_ea = self._cfunc.entry_ea
        arg_idx = get_argument_index(self._cfunc, cexpr.v.idx)
        if arg_idx is None:
            log_warning(
                f"Failed to resolve argument ordinal for {to_hex(func_ea)} lvar {cexpr.v.idx}",
                True,
            )
            return
        if self._add_visit(func_ea, arg_idx):
            for callee_ea in get_funcs_calling_address(func_ea):
                self._add_scan_tree_info(callee_ea, arg_idx)
    def leave_expr(self, cexpr):
        self._check_call(cexpr)
        return super().leave_expr(cexpr)

    def _recursive_process(self):
        super()._recursive_process()

        while self._new_for_visit:
            new_visit = list(self._new_for_visit)
            self._new_for_visit.clear()
            for func_ea, arg_idx in new_visit:
                funcs = get_funcs_calling_address(func_ea)
                cfunc = decompile(func_ea)
                if cfunc is None:
                    continue
                obj = CallArgumentObject.create(cfunc, arg_idx)
                if obj is None:
                    continue
                for callee_ea in funcs:
                    cfunc = decompile(callee_ea)
                    if cfunc:
                        self.prepare_new_scan(cfunc, arg_idx, obj, False)
                        super()._recursive_process()


class FunctionTouchVisitor(ida_hexrays.ctree_parentee_t):
    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self._functions = set()
        self._cfunc = cfunc
        self._visited = set()  # Keep track of visited functions

    def visit_expr(self, cexpr):
        if cexpr.op == ctype.call:
            self._functions.add(cexpr.x.obj_ea)
        return 0

    def process(self):
        if self._cfunc.entry_ea not in self._visited:
            self._visited.add(self._cfunc.entry_ea)
            # apply_to walks the whole tree and collects every `call` node
            # into self._functions. Do NOT reset between collection and use:
            # the old `self._functions = set()` here dropped the nested calls
            # and left process() touching nothing below the top level.
            self.apply_to(self._cfunc.body, None)
            self.touch_all_iterative()
            decompile(self._cfunc.entry_ea)
            return True
        return False

    def touch_all_iterative(self):
        stack = list(self._functions)
        while stack:
            address = stack.pop()
            if address in self._visited:
                continue
            self._visited.add(address)
            if is_imported(address):
                continue
            try:
                cfunc = decompile(address)
                if cfunc:
                    # Find all function calls in the current function
                    self._functions = set()
                    self.apply_to(cfunc.body, None)
                    self.visit_expr(cfunc.body)
                    stack.extend(self._functions)
            except ida_hexrays.DecompilationFailure:
                log_warning(f"Failed to decompile function {to_hex(address)}")


def _mark_cfunc_dirty(ea: int) -> None:
    dirty = getattr(hexrays_api, "mark_cfunc_dirty", None)
    if callable(dirty):
        dirty(ea, False)


def refresh_function_tree(
    cfunc: ida_hexrays.cfunc_t,
) -> ida_hexrays.cfunc_t | None:
    func_ea = cfunc.entry_ea
    if is_imported(func_ea):
        return cfunc

    _mark_cfunc_dirty(func_ea)
    return decompile(func_ea) or cfunc
