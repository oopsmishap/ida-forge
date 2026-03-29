from __future__ import annotations

import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
UTIL = ROOT / "util"

for path in (str(SRC), str(UTIL)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _stub_module(name: str, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


class _DummyChoose:
    CH_MODAL = 0
    NOTHING_CHANGED = 0

    def __init__(self, *args, **kwargs):
        pass


class _DummyPluginForm:
    def Show(self, *args, **kwargs):
        return True

    def FormToPyQtWidget(self, form):
        return form


class _DummyActionHandler:
    def __init__(self, *args, **kwargs):
        pass


class _DummyHexraysHooks:
    def hook(self):
        return True

    def unhook(self):
        return True


class _DummyTInfo:
    def __init__(self, *args, **kwargs):
        self._name = ""

    def equals_to(self, other):
        return self is other

    def deserialize(self, *args, **kwargs):
        return True

    def create_ptr(self, *args, **kwargs):
        return True

    def create_array(self, *args, **kwargs):
        return True

    def get_named_type(self, *args, **kwargs):
        return False

    def dstr(self):
        return self._name


class _DummyArrayTypeData:
    def __init__(self):
        self.base = 0
        self.elem_type = None
        self.nelems = 0


class _DummyUDTMember:
    def __init__(self):
        self.offset = 0
        self.name = ""


_user_ida_dir = Path(tempfile.gettempdir()) / "ida-forge-tests"
_user_ida_dir.mkdir(parents=True, exist_ok=True)

_stub_module(
    "ida_kernwin",
    msg=lambda *args, **kwargs: None,
    warning=lambda *args, **kwargs: None,
    ask_str=lambda default, *_args, **_kwargs: default,
    get_kernel_version=lambda: "9.3",
    register_action=lambda *args, **kwargs: True,
    unregister_action=lambda *args, **kwargs: True,
    create_menu=lambda *args, **kwargs: True,
    delete_menu=lambda *args, **kwargs: True,
    detach_action_from_menu=lambda *args, **kwargs: True,
    attach_action_to_menu=lambda *args, **kwargs: True,
    attach_action_to_popup=lambda *args, **kwargs: True,
    execute_ui_requests=lambda *args, **kwargs: True,
    action_desc_t=lambda *args, **kwargs: (args, kwargs),
    action_handler_t=_DummyActionHandler,

    HIST_TYPE=0,
    AST_ENABLE_FOR_IDB=1,
    AST_ENABLE_FOR_WIDGET=2,
    AST_DISABLE_FOR_WIDGET=3,
    BWN_PSEUDOCODE=10,
    BWN_STRUCTS=11,
    Choose=_DummyChoose,
    PluginForm=_DummyPluginForm,
    is_idaq=lambda: True,
)
_stub_module("ida_diskio", get_user_idadir=lambda: str(_user_ida_dir))
_stub_module(
    "ida_typeinf",
    tinfo_t=_DummyTInfo,
    array_type_data_t=_DummyArrayTypeData,
    udt_member_t=_DummyUDTMember,
    get_idati=lambda: object(),
    parse_decl=lambda *args, **kwargs: False,
    PT_TYP=0,
    PT_SIL=0,
    BADSIZE=-1,
    STRMEM_OFFSET=0,
    cvar=types.SimpleNamespace(idati=object()),
)
_stub_module(
    "idaapi",
    BADADDR=-1,
    PT_TYP=0,
    PLUGIN_KEEP=0,
    PLUGIN_SKIP=1,
    idc_parse_decl=lambda *args, **kwargs: None,
    register_timer=lambda *_args, **_kwargs: object(),
    unregister_timer=lambda *_args, **_kwargs: None,
    get_import_module_qty=lambda: 0,
    get_import_module_name=lambda _i: "",
    enum_import_names=lambda _i, _cb: True,
)
_stub_module("ida_idp", IDP_INTERFACE_VERSION=0)
_stub_module(
    "ida_hexrays",
    create_typedef=lambda *args, **kwargs: None,
    init_hexrays_plugin=lambda: True,
    open_pseudocode=lambda *args, **kwargs: None,
    cfunc_type=lambda *args, **kwargs: object(),
    Hexrays_Hooks=_DummyHexraysHooks,
    ctree_item_t=type("ctree_item_t", (), {}),
    cfunc_t=type("cfunc_t", (), {}),
    cexpr_t=type("cexpr_t", (), {}),
    lvar_t=type("lvar_t", (), {}),
    vdui_t=object,
    VDI_EXPR=1,
    OPF_REUSE=0,
    DecompilationFailure=Exception,
)
_stub_module(
    "idc",
    BADADDR=-1,
    FUNCATTR_START=0,
    import_type=lambda *args, **kwargs: 0,
    get_segm_name=lambda *_args: "",
    get_func_attr=lambda ea, _attr: ea,
    get_name=lambda ea: f"sub_{ea:x}",
)

for name in [
    "ida_auto",
    "ida_bytes",
    "ida_funcs",
    "ida_segment",
    "ida_xref",
    "ida_ida",
    "ida_lines",
]:
    _stub_module(name)

_stub_module("ida_name", get_short_name=lambda ea: f"name_{ea:x}")
_stub_module("ida_nalt", get_imagebase=lambda: 0)
_stub_module("ida_netnode", BADNODE=-1, netnode=lambda *args, **kwargs: None)

class _DummyQtClass:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return self

    def __getattr__(self, _name):
        return self


class _DummyQtNamespace:
    def __getattr__(self, name):
        if name == "Qt":
            return types.SimpleNamespace(
                AlignCenter=0,
                CustomContextMenu=0,
                Key_Return=0,
                Key_Enter=0,
                UserRole=0,
                TextFormat=types.SimpleNamespace(RichText=0),
            )
        return _DummyQtClass


_stub_module(
    "forge.util.qt",
    QtCore=_DummyQtNamespace(),
    QtGui=_DummyQtNamespace(),
    QtWidgets=_DummyQtNamespace(),
    Signal=lambda *args, **kwargs: None,
    qt_exec=lambda widget, *args, **kwargs: widget.exec(*args, **kwargs)
    if hasattr(widget, "exec")
    else widget.exec_(*args, **kwargs),
)
_stub_module(
    "forge.api.hexrays",
    ctype=types.SimpleNamespace(
        var=1,
        memptr=2,
        memref=3,
        obj=4,
        call=5,
        cast=6,
        ref=7,
        add=8,
        sub=9,
        idx=10,
        num=11,
    ),
    get_member_name=lambda *_args, **_kwargs: "member_name",
    get_ptr=lambda *args, **kwargs: 0,
    is_code=lambda *args, **kwargs: False,
    is_imported=lambda *args, **kwargs: False,
    decompile=lambda *args, **kwargs: None,
    create_udt_padding_member=lambda *args, **kwargs: None,
    to_function_offset_str=lambda ea: f"sub_{ea:x}+0x0",
)
_stub_module("forge.api.types", types=types.SimpleNamespace(width=8), import_type=lambda *args, **kwargs: 0)
_stub_module("forge.api.scanner", NewDeepScanVisitor=type("NewDeepScanVisitor", (), {}))
_stub_module("forge.api.visitor", FunctionTouchVisitor=type("FunctionTouchVisitor", (), {}))
