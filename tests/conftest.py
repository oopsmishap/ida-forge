from __future__ import annotations

import contextlib
import shutil
import sys
import tempfile
import types
from pathlib import Path

import pytest

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

    def create_udt(self, *args, **kwargs):
        return True

    def get_named_type(self, *args, **kwargs):
        return True

    def get_numbered_type(self, *args, **kwargs):
        return False

    def is_udt(self):
        return False

    def get_udt_details(self, *args, **kwargs):
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


class _DummyUDTTypeData(list):
    def push_back(self, value):
        self.append(value)

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
    UI_Hooks=_DummyHexraysHooks,
    AST_ENABLE_FOR_IDB=1,
    AST_ENABLE_FOR_WIDGET=2,
    AST_DISABLE_FOR_WIDGET=3,
    BWN_PSEUDOCODE=10,
    BWN_STRUCTS=11,
    Choose=_DummyChoose,
    PluginForm=_DummyPluginForm,
    is_idaq=lambda: True,
    jumpto=lambda *_args, **_kwargs: True,
)
_stub_module("ida_diskio", get_user_idadir=lambda: str(_user_ida_dir))
_stub_module(
    "ida_typeinf",
    tinfo_t=_DummyTInfo,
    array_type_data_t=_DummyArrayTypeData,
    udt_member_t=_DummyUDTMember,
    udt_type_data_t=_DummyUDTTypeData,
    BTF_STRUCT=0,
    BTF_UINT16=0,
    BTF_UINT32=0,
    BTF_UINT64=0,
    get_idati=lambda: object(),
    get_ordinal_count=lambda idati: 0,
    get_numbered_type_name=lambda idati, ordinal: "",
    get_type_ordinal=lambda idati, name: -1,
    apply_tinfo=lambda *args, **kwargs: True,
    TINFO_DEFINITE=0,
    print_tinfo=lambda *args, **kwargs: 0,
    PRTYPE_MULTI=0,
    PRTYPE_TYPE=0,
    PRTYPE_SEMI=0,
    parse_decl=lambda *args, **kwargs: False,
    import_type=lambda *args, **kwargs: 0,
    PT_TYP=0,
    PT_SIL=0,
    BADSIZE=-1,
    NTF_TYPE=0,
    STRMEM_OFFSET=0,
    cvar=types.SimpleNamespace(idati=object()),
)
_stub_module(
    "ida_idaapi",
    plugmod_t=type("plugmod_t", (), {}),
    plugin_t=type("plugin_t", (), {}),
    PLUGIN_OK=0,
    PLUGIN_SKIP=1,
    PLUGIN_KEEP=2,
    PLUGIN_MULTI=0x100,
    BADADDR=-1,
    BADORD=0,
)
_stub_module(
    "ida_expr",
    add_idc_func=lambda *args, **kwargs: True,
    del_idc_func=lambda *args, **kwargs: True,
    VT_LONG=0,
    VT_STR=1,
)
_stub_module(
    "idaapi",
    BADADDR=-1,
    PT_TYP=0,
    PLUGIN_KEEP=2,
    PLUGIN_SKIP=1,
    PRTYPE_MULTI=0,
    PRTYPE_TYPE=0,
    PRTYPE_SEMI=0,
    idc_parse_decl=lambda *args, **kwargs: None,
    register_timer=lambda *_args, **_kwargs: object(),
    unregister_timer=lambda *_args, **_kwargs: None,
    get_import_module_qty=lambda: 0,
    get_import_module_name=lambda _i: "",
    enum_import_names=lambda _i, _cb: True,
    print_tinfo=lambda *_args, **_kwargs: "typedef;",
    get_type_ordinal=lambda *_args, **_kwargs: 0,
    idc_set_local_type=lambda *_args, **_kwargs: 1,
    del_numbered_type=lambda *_args, **_kwargs: True,
    create_typedef=lambda name: name,
    cvar=types.SimpleNamespace(idati=object()),
)
_stub_module("ida_idp", IDP_INTERFACE_VERSION=0)
_stub_module(
    "ida_hexrays",
    create_typedef=lambda *args, **kwargs: None,
    init_hexrays_plugin=lambda: True,
    open_pseudocode=lambda *args, **kwargs: None,
    mark_cfunc_dirty=lambda *args, **kwargs: None,
    modify_user_lvar_info=lambda *args, **kwargs: True,
    lvar_saved_info_t=lambda *args, **kwargs: types.SimpleNamespace(ll=None, type=None),
    lvar_locator_t=lambda location, defea: types.SimpleNamespace(location=location, defea=defea),
    MLI_TYPE=0x08,
    OPF_NEW_WINDOW=2,
    cfunc_type=lambda *args, **kwargs: object(),
    Hexrays_Hooks=_DummyHexraysHooks,
    ctree_item_t=type("ctree_item_t", (), {}),
    ctree_parentee_t=type("ctree_parentee_t", (), {}),
    ctree_visitor_t=type(
        "ctree_visitor_t",
        (),
        {"__init__": lambda self, *a, **k: None, "apply_to": lambda self, *a, **k: None},
    ),
    cfunc_t=type("cfunc_t", (), {}),
    cexpr_t=type("cexpr_t", (), {}),
    lvar_t=type("lvar_t", (), {}),
    vdui_t=object,
    VDI_EXPR=1,
    cot_memptr=70,
    cot_memref=71,
    cot_idx=80,
    cot_num=12,
    OPF_REUSE=0,
    DecompilationFailure=Exception,
)
_stub_module(
    "idc",
    BADADDR=-1,
    BADORD=0,
    FUNCATTR_START=0,
    import_type=lambda *args, **kwargs: 0,
    get_segm_name=lambda *_args: "",
    get_func_attr=lambda ea, _attr: ea,
    get_name=lambda ea: f"sub_{ea:x}",
    get_inf_attr=lambda *_args, **_kwargs: 0,
    INF_SHORT_DN=0,
    # E1: parse_declaration / parse_user_tinfo fall back to idc.parse_decl
    # (ida_idaapi.idc_parse_decl does not exist on IDA 9.4); None means
    # "could not parse", matching the real module's failure mode.
    parse_decl=lambda *args, **kwargs: None,
)

_stub_module("ida_auto")
_stub_module(
    "ida_bytes",
    get_64bit=lambda *_args, **_kwargs: 0,
    get_32bit=lambda *_args, **_kwargs: 0,
    get_wide_dword=lambda *_args, **_kwargs: 0,
    get_byte=lambda *_args, **_kwargs: 0,
    get_wide_byte=lambda *_args, **_kwargs: 0,
)
_stub_module(
    "ida_funcs",
    get_func=lambda *_args, **_kwargs: None,
    get_func_name=lambda ea: f"sub_{ea:x}",
    FUNCATTR_START=0,
)
_stub_module("ida_segment", get_segm_name=lambda *_args, **_kwargs: "", getseg=lambda *_args, **_kwargs: None, SEGPERM_EXEC=1)
_stub_module(
    "ida_nalt",
    get_imagebase=lambda: 0,
    get_import_module_qty=lambda: 0,
    get_import_module_name=lambda _i: "",
    enum_import_names=lambda _i, _cb: True,
)
_stub_module("ida_xref", get_first_dref_to=lambda *_args, **_kwargs: -1)
_stub_module("ida_ida", idainfo=types.SimpleNamespace(procname="metapc"))
_stub_module("ida_lines")

_stub_module(
    "ida_name",
    get_short_name=lambda ea: f"name_{ea:x}",
    get_name=lambda _ea: "",
    get_name_ea=lambda *_args, **_kwargs: -1,
    set_name=lambda *_args, **_kwargs: True,
    is_valid_typename=lambda name: bool(name) and name.replace("_", "").isalnum(),
    demangle_name=lambda *_args, **_kwargs: None,
)
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
                ItemIsSelectable=1,
                ItemIsEnabled=2,
                ItemIsEditable=4,
                ItemFlags=lambda value=0: value,
                Key_Return=0,
                Key_Enter=0,
                UserRole=0,
                TextFormat=types.SimpleNamespace(RichText=0),
            )
        return _DummyQtClass


def _qt_item_flags(*flags):
    combined = 0
    for flag in flags:
        if flag is None:
            continue
        value = getattr(flag, "value", flag)
        try:
            combined |= int(value)
        except (TypeError, ValueError):
            continue
    return combined


def _qt_flag_value(flag):
    if flag is None:
        return 0
    return int(getattr(flag, "value", flag))


def _qt_combined_flags(*flags, flags_type=None):
    combined = 0
    for flag in flags:
        if flag is None:
            continue
        value = getattr(flag, "value", flag)
        try:
            combined |= int(value)
        except (TypeError, ValueError):
            continue
    if callable(flags_type):
        try:
            return flags_type(combined)
        except (TypeError, ValueError):
            pass
    return combined


_stub_module(
    "forge.util.qt",
    QtCore=_DummyQtNamespace(),
    QtGui=_DummyQtNamespace(),
    QtWidgets=_DummyQtNamespace(),
    Signal=lambda *args, **kwargs: None,
    qt_exec=lambda widget, *args, **kwargs: widget.exec(*args, **kwargs)
    if hasattr(widget, "exec")
    else widget.exec_(*args, **kwargs),
    qt_item_flags=_qt_item_flags,
    qt_flag_value=_qt_flag_value,
    qt_combined_flags=_qt_combined_flags,
)
def _collect_ctree_items_near_ea(cfunc, ea: int, *, exhaustive: bool = False):
    """Faithful behavioral double of hexrays.collect_ctree_items_near_ea.

    The structure-builder tests exercise the child-scan inference engine with
    fake cfuncs (SimpleNamespace treeitems/eamap/body), so the stub must run
    the same chain — a lambda returning [] would silently drop candidates.
    """
    candidates = []
    if cfunc is None or ea == -1:
        return []

    for item in getattr(cfunc, "treeitems", []) or []:
        if getattr(item, "ea", -1) == ea:
            candidates.append(item)

    eamap = getattr(cfunc, "eamap", None)
    if (exhaustive or not candidates) and eamap is not None:
        with contextlib.suppress(Exception):
            candidates.extend(list(eamap.get(ea, [])))

    body = getattr(cfunc, "body", None)
    if (
        (exhaustive or not candidates)
        and body is not None
        and hasattr(body, "find_closest_addr")
    ):
        try:
            closest_item = body.find_closest_addr(ea)
        except Exception:  # noqa: BLE001 — stub doubles may raise anything
            closest_item = None
        if closest_item is not None:
            candidates.append(closest_item)

    if exhaustive:
        seen = set()
        deduped = []
        for item in candidates:
            if item is None:
                continue
            marker = id(item)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped
    return candidates


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
        ptr=10,
        idx=11,
        num=12,
    ),
    get_member_name=lambda *_args, **_kwargs: "member_name",
    read_pointer=lambda *args, **kwargs: 0,
    is_code=lambda *args, **kwargs: False,
    is_imported=lambda *args, **kwargs: False,
    is_legal_type=lambda *args, **kwargs: True,
    decompile=lambda *args, **kwargs: None,
    get_line=lambda *args, **kwargs: "",
    find_expr_address=lambda *args, **kwargs: 0,
    print_expr_address=lambda *args, **kwargs: "0x0",
    get_func_argument_info=lambda *args, **kwargs: (0, None),
    get_argument=lambda *args, **kwargs: (None, 0),
    get_argument_index=lambda *args, **kwargs: 0,
    get_funcs_calling_address=lambda *args, **kwargs: set(),
    get_funcs_referencing_address=lambda *args, **kwargs: set(),
    to_hex=lambda value: hex(value),
    create_udt_padding_member=lambda *args, **kwargs: None,
    collect_ctree_items_near_ea=_collect_ctree_items_near_ea,
    to_function_offset_str=lambda ea: f"sub_{ea:x}+0x0",
    iter_returned_exprs=lambda *args, **kwargs: iter(()),
)
_stub_module("forge.api.types", types=types.SimpleNamespace(width=8), import_type=lambda *args, **kwargs: 0)
_stub_module("forge.api.scanner", NewDeepScanVisitor=type("NewDeepScanVisitor", (), {}))
_stub_module("forge.api.visitor", FunctionTouchVisitor=type("FunctionTouchVisitor", (), {}))


@pytest.fixture(autouse=True)
def _purge_user_config_dir():
    """Start every test with a clean ``ida_diskio.get_user_idadir`` directory.

    The ``ForgeConfig`` loader reads and writes a TOML file under
    ``get_user_idadir() / cfg / forge.toml``. If a previous test (or a
    prior local run) saved a file with an old schema, the singleton
    ``StructureBuilderConfig()`` instance created at import time would
    read those stale values and short-circuit the deep-merge that
    normally fills in missing keys. Purging the directory per test
    guarantees the latest ``default_config`` is used.
    """
    if _user_ida_dir.exists():
        shutil.rmtree(_user_ida_dir)
    _user_ida_dir.mkdir(parents=True, exist_ok=True)
    yield
