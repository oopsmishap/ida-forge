import idaapi

from forge.util.logging import *
from forge.api.hexrays import find_expr_address, to_function_offset_str, ctype
from forge.api.scan_object import ScanObject, ObjectType, MemoryAllocationObject
from forge.api.visitor import RecursiveUpwardsObjectVisitor
from forge.api.ui import Choose
from forge.api.ui_actions import HexRaysPopupAction, register_action


class StructureAllocationChoose(Choose):
    title = "Possible structure allocations"
    cols = [["Function", 30], ["Variable", 10], ["Line", 50], ["Type", 10]]

    def __init__(self, items):
        super().__init__(items)

    def OnSelectLine(self, n):
        idaapi.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        func_ea, var, line, alloc_type = self.items[n]
        return [to_function_offset_str(func_ea), var, line, alloc_type]


class GuessAllocationVisitor(RecursiveUpwardsObjectVisitor):
    def __init__(self, cfunc, obj: ScanObject):
        super().__init__(cfunc, obj, skip_until_object=True)
        self._data = []

    def _manipulate(self, cexpr, obj: ScanObject):
        if obj.id == ObjectType.local_variable:
            parent = self.parent_expr()
            if parent.op == ctype.asg:
                alloc_obj = MemoryAllocationObject.create(
                    self._cfunc, self.parent_expr().y
                )
                if alloc_obj:
                    self._data.append([alloc_obj.ea, obj.name, self.get_line(), "HEAP"])
            elif self.parent_expr().op == ctype.ref:
                self._data.append(
                    [
                        find_expr_address(cexpr, self.parents),
                        obj.name,
                        self.get_line(),
                        "STACK",
                    ]
                )
        elif obj.id == ObjectType.global_object:
            self._data.append(
                [
                    find_expr_address(cexpr, self.parents),
                    obj.name,
                    self.get_line(),
                    "GLOBAL",
                ]
            )

    def _finish(self):
        chooser = StructureAllocationChoose(self._data)
        chooser.Show(True)


@register_action
class GuessAllocation(HexRaysPopupAction):
    name = "GuessAllocation"
    description = "Guess allocation"
    hotkey = ""

    def __init__(self):
        super().__init__()

    def check(self, hx_view):
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        return ScanObject.create(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        obj = ScanObject.create(hx_view.cfunc, hx_view.item)
        if obj:
            visitor = GuessAllocationVisitor(hx_view.cfunc, obj)
            visitor.process()
