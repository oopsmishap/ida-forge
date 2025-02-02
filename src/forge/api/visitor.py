import ida_funcs
import ida_hexrays
import ida_idaapi

from forge.api.hexrays import *
from forge.api.scan_object import (
    ScanObject,
    ObjectType,
    VariableObject,
    CallArgumentObject,
)
from forge.util.logging import *


class ObjectVisitor(ida_hexrays.ctree_parentee_t):
    def __init__(
        self, cfunc: ida_hexrays.cfunc_t, obj: ScanObject, data, skip_until_object: bool
    ):
        super(ObjectVisitor, self).__init__()
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
        log_debug(
            f"Expression {cexpr.opname} at {print_expr_address(cexpr, self.parents)} Id - {obj.id}"
        )

    def get_line(self) -> int:
        for p in reversed(self.parents):
            if not p.is_expr():
                return idaapi.tag_remove(p.print1(self._cfunc.__ref__()))
        AssertionError("Parent instruction is not found")


class DownwardsObjectVisitor(ObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object: bool = False,
    ):
        super(DownwardsObjectVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self.cv_flags |= ida_hexrays.CV_POST

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
            if obj.is_target(x_cexpr):
                if self._is_object_overwritten(y_cexpr):
                    log_info(
                        f"Remove object {obj} from scanning at {print_expr_address(x_cexpr, self.parents)}"
                    )
                    self._objects.remove(obj)
                return 0
            elif obj.is_target(y_cexpr):
                new_obj = ScanObject.create(self._cfunc, x_cexpr)
                if new_obj:
                    self._objects.append(new_obj)
                return 0
        return 0

    def leave_expr(self, cexpr: ida_hexrays.cexpr_t):
        if self._skip:
            return 0
        for obj in self._objects:
            if obj.is_target(cexpr) and obj.id != ObjectType.returned_object:
                self._manipulate(cexpr, obj)
                return 0
        return 0

    def _is_initial_object(self, cexpr: ida_hexrays.cexpr_t):
        if cexpr.op == ctype.asg:
            cexpr = cexpr.y
            if cexpr.op == ctype.cast:
                cexpr = cexpr.x
        return (
            self._init_obj.is_target(cexpr)
            and find_expr_address(cexpr, self.parents) == self._start_ea
        )

    def _is_object_overwritten(self, cexpr: ida_hexrays.cexpr_t) -> bool:
        if len(self._objects) < 2:
            return False

        if cexpr.op == ctype.cast:
            e = cexpr.x
        else:
            e = cexpr

        if e.op != ctype.call or len(e.a) == 0:
            return True

        for obj in self._objects:
            if obj.is_target(e.a[0]):
                return False
        return True


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
        super(UpwardsObjectVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self._stage = self.STAGE_PREPARE
        self._tree = {}
        self._call_obj = obj if obj.id == ObjectType.call_argument else None

    def visit_expr(self, cexpr: ida_hexrays.cexpr_t):
        if self._stage == self.STAGE_PARSING:
            return 0

        if self._call_obj and self._call_obj.is_target(cexpr):
            obj = self._call_obj.create_scan_object(self._cfunc, cexpr)
            if obj:
                self._objects.append(obj)
            return 0

        if cexpr.op != ctype.asg:
            return 0

        x_cexpr = cexpr.x
        if cexpr.y.op == ctype.cast:
            y_cexpr = cexpr.y.x
        else:
            y_cexpr = cexpr.y

        obj_left = ScanObject.create(self._cfunc, x_cexpr)
        obj_right = ScanObject.create(self._cfunc, y_cexpr)
        if obj_left and obj_right:
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
            if obj.is_target(cexpr):
                self._manipulate(cexpr, obj)
                return 0
        return 0

    def process(self):
        self._stage = self.STAGE_PREPARE
        self.cv_flags &= ~ida_hexrays.CV_POST
        super(UpwardsObjectVisitor, self).process()
        self._stage = self.STAGE_PARSING
        self.cv_flags |= ida_hexrays.CV_POST
        self._prepare()
        super(UpwardsObjectVisitor, self).process()

    def _is_initial_object(self, cexpr: ida_hexrays.cexpr_t):
        return (
            self._init_obj.is_target(cexpr)
            and find_expr_address(cexpr, self.parents) == self._start_ea
        )

    def _add_object_assignment(self, from_obj, to_obj):
        if from_obj in self._tree:
            self._tree[from_obj].add(to_obj)
        else:
            self._tree[from_obj] = {to_obj}

    def _prepare(self):
        result = set()
        todo = set(self._objects)
        while todo:
            obj = todo.pop()
            result.add(obj)
            if obj.id == ObjectType.call_argument or obj not in self._tree:
                continue
            o = self._tree[obj]
            todo |= o - result
            result |= o
        self._objects = list(result)
        self._tree.clear()


class RecursiveObjectVisitor(ObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object=False,
        visited=None,
    ):
        super(RecursiveObjectVisitor, self).__init__(cfunc, obj, data, skip_until_object)
        self._visited = visited if visited else set()
        self._new_for_visit = set()
        self.crippled = False
        self._arg_index = -1
        self._debug_scan_tree = {}
        self._debug_scan_tree_root = ida_funcs.get_func_name(self._cfunc.entry_ea)
        self._debug_message = []

    def visit_expr(self, cexpr: ida_hexrays.cexpr_t):
        return super(RecursiveObjectVisitor, self).visit_expr(cexpr)

    # noinspection PyAttributeOutsideInit
    def set_callbacks(
        self,
        manipulate=None,
        start=None,
        start_iteration=None,
        finish=None,
        finish_iteration=None,
    ):
        super(RecursiveObjectVisitor, self).set_callbacks(manipulate)
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

    def process(self):
        self._start()
        self._recursive_process()
        self._finish()
        self.dump_scan_tree()

    def dump_scan_tree(self):
        self._prepare_scan_tree()
        newline = "\n"
        log_info(f"{newline.join(self._debug_message)}\n---------------")

    def _prepare_scan_tree(self, key=None, level=1):
        if key is None:
            key = (self._debug_scan_tree_root, -1)
            self._debug_message.append(
                f"\n--- Scan Tree ---\n{self._debug_scan_tree_root}"
            )
        if key in self._debug_scan_tree:
            for func_name, arg_idx in self._debug_scan_tree[key]:
                prefix = " | " * (level - 1) + " |_ "
                self._debug_message.append(f"{prefix}{func_name}(idx: {arg_idx})")
                self._prepare_scan_tree((func_name, arg_idx), level + 1)

    def _recursive_process(self):
        self._start_iteration()
        super(RecursiveObjectVisitor, self).process()
        self._finish_iteration()

    def _manipulate(self, cexpr, obj):
        self._check_call(cexpr)
        super(RecursiveObjectVisitor, self)._manipulate(cexpr, obj)

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
        pass

    def _start_iteration(self):
        """Called every time new function visiting started"""
        pass

    def _finish(self):
        """Called after all visiting happened"""
        pass

    def _finish_iteration(self):
        """Called every time new function visiting finished"""
        pass

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
    ):
        super(RecursiveDownwardsObjectVisitor, self).__init__(
            cfunc, obj, data, skip_until_object, visited
        )

    def _check_call(self, cexpr: ida_hexrays.cexpr_t):
        parent: ida_hexrays.cexpr_t = self.parent_expr()
        grandparent: ida_hexrays.cexpr_t = self.parents.at(self.parents.size() - 2)
        if parent.op == ctype.call:
            call_cexpr = parent
            arg_cexpr = cexpr
        elif parent.op == ctype.cast and grandparent.op == ctype.call:
            call_cexpr = grandparent.cexpr
            arg_cexpr = parent
        else:
            return

        idx, _ = get_func_argument_info(call_cexpr, arg_cexpr)
        func_ea = call_cexpr.x.obj_ea
        if func_ea == ida_idaapi.BADADDR:
            return
        if self._add_visit(func_ea, idx):
            self._add_scan_tree_info(func_ea, idx)

    def _recursive_process(self):
        super(RecursiveDownwardsObjectVisitor, self)._recursive_process()

        while self._new_for_visit:
            func_ea, arg_idx = self._new_for_visit.pop()
            # TODO: implement is_imported_ea
            # if is_imported_ea(func_ea):
            #     continue
            cfunc = decompile(func_ea)
            if cfunc:
                arg, lvar_idx = get_argument(cfunc, arg_idx)
                obj = VariableObject(arg, lvar_idx)
                self.prepare_new_scan(cfunc, lvar_idx, obj)
                self._recursive_process()


class RecursiveUpwardsObjectVisitor(RecursiveObjectVisitor, UpwardsObjectVisitor):
    def __init__(
        self,
        cfunc: ida_hexrays.cfunc_t,
        obj: ScanObject,
        data=None,
        skip_until_object=False,
        visited=None,
    ):
        super(RecursiveUpwardsObjectVisitor, self).__init__(cfunc, obj, data, skip_until_object, visited)

    def prepare_new_scan(self, cfunc, arg_idx, obj, skip=False):
        super(RecursiveUpwardsObjectVisitor, self).prepare_new_scan(cfunc, arg_idx, obj, skip)
        self._call_obj = obj if obj.id == ObjectType.call_argument else None

    def _check_call(self, cexpr: ida_hexrays.cexpr_t):
        if cexpr.op == ctype.var and self._cfunc.get_lvars()[cexpr.v.idx].is_arg_var:
            func_ea = self._cfunc.entry_ea
            arg_idx = cexpr.v.idx
            if self._add_visit(func_ea, arg_idx):
                for callee_ea in get_funcs_calling_address(func_ea):
                    self._add_scan_tree_info(callee_ea, arg_idx)

    def leave_expr(self, cexpr):
        self._check_call(cexpr)
        return super().leave_expr(cexpr)

    def _recursive_process(self):
        super(RecursiveUpwardsObjectVisitor, self)._recursive_process()

        while self._new_for_visit:
            new_visit = list(self._new_for_visit)
            self._new_for_visit.clear()
            for func_ea, arg_idx in new_visit:
                funcs = get_funcs_calling_address(func_ea)
                obj = CallArgumentObject.create(decompile(func_ea), arg_idx)
                for callee_ea in funcs:
                    cfunc = decompile(callee_ea)
                    if cfunc:
                        self.prepare_new_scan(cfunc, arg_idx, obj, False)
                        super()._recursive_process()


class FunctionTouchVisitor(ida_hexrays.ctree_parentee_t):
    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        super().__init__()
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
            self.apply_to(self._cfunc.body, None)
            self._functions = set()  # Reset the set of functions to visit
            self.visit_expr(self._cfunc.body)
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
