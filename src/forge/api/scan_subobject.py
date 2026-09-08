"""Subobject-rooted deep scan: explicit root descriptor and rebasing.

Recovery-eval round 3 (2026-08-31): a member at offset 0x1B60 that is
really a nested subobject must be scanned into the CHILD structure in
child coordinates. A scan rooted at the parent base variable records
offsets relative to the parent, so a field at subobject + 0x08 lands at
0x1B68 — wrong for the child type by exactly the subobject's own offset.

This module supplies the missing piece as a facade-level root descriptor
(:class:`SubobjectRoot`) and a scan-object wrapper
(:class:`SubobjectScanObject`) that matches the subobject expression
itself — ``parent->m(0x1B60)`` / ``(child_t *)(parent + 0x1B60)`` — so the
shared deep-scan visitor computes member offsets ABOVE the matched node,
i.e. already relative to the subobject: ``parent base + 0x1B60 + 0x08``
produces child offset 0x08, never 0x1B68.

The helper :func:`rebase_to_subobject` is the deterministic conversion for
evidence rows already recorded in parent coordinates (``0x1B68 - 0x1B60 ->
0x08``) — call it when merging a prior parent-rooted scan's rows into child
coordinates. The subobject scan itself never post-hoc rebases: matching the
subobject expression makes the visitor's offsets child-relative by
construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from forge.api.scan_object import (
    ObjectType,
    ScanObject,
    _extract_offset_expression,
    _type_name_matches,
    _unwrap_struct_type,
)

__all__ = ["SubobjectRoot", "SubobjectScanObject", "rebase_to_subobject"]

_ROOT_FIELDS = frozenset(
    {"base_offset", "var_name", "var_index", "item_ea", "parent_type"}
)


@dataclass(frozen=True)
class SubobjectRoot:
    """Explicit root descriptor for a subobject-rooted deep scan.

    ``base_offset`` is the subobject's byte offset inside the parent
    object. The parent base variable is addressed with the same criteria
    as ``deep_scan`` — ``var_name``, ``var_index`` or ``item_ea`` (at most
    one; none of them means the default first argument). ``parent_type``
    optionally names the parent structure type; when given, only
    subobject expressions whose base type matches are accepted.
    """

    base_offset: int
    var_name: str | None = None
    var_index: int | None = None
    item_ea: int | None = None
    parent_type: str | None = None

    def __post_init__(self):
        if (
            isinstance(self.base_offset, bool)
            or not isinstance(self.base_offset, int)
            or self.base_offset < 0
        ):
            raise ValueError("base_offset must be a non-negative int")
        criteria = sum(
            1
            for value in (self.var_name, self.var_index, self.item_ea)
            if value is not None
        )
        if criteria > 1:
            raise ValueError("use at most one of var_name, var_index, item_ea")

    @classmethod
    def from_dict(cls, raw) -> SubobjectRoot:
        """Build the descriptor from a JSON-shaped ``subobject=`` dict."""
        if not isinstance(raw, dict):
            raise ValueError("subobject root descriptor must be a dict")
        unknown = sorted(set(raw) - _ROOT_FIELDS)
        if unknown:
            raise ValueError(f"unknown subobject root fields: {unknown}")
        return cls(
            base_offset=raw.get("base_offset", 0),
            var_name=raw.get("var_name"),
            var_index=raw.get("var_index"),
            item_ea=raw.get("item_ea"),
            parent_type=raw.get("parent_type"),
        )


def rebase_to_subobject(offset: int, base_offset: int) -> int:
    """Rebase a parent-relative evidence offset into child coordinates.

    ``parent base + 0x1B60 + 0x08`` is observed at ``0x1B68`` relative to
    the parent base; against a subobject living at ``0x1B60`` the child
    offset is ``0x08`` — never ``0x1B68``. Negative results mean the
    offset lies before the subobject and cannot belong to it.
    """
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an int")
    return int(offset) - int(base_offset)


class SubobjectScanObject(ScanObject):
    """Scan root that matches the subobject expression itself.

    Wraps the resolved parent scan object (lvar identity, evidence and
    retype helpers delegate to it) and accepts exactly the expressions
    that denote the subobject base: a member access carrying the
    descriptor's offset (``parent->m`` / ``parent.m``) or pointer
    arithmetic landing on it (``(child_t *)(parent + base)``). Offsets the
    shared visitor computes above a matched node are therefore already
    child-relative — no post-hoc subtraction, no ``0x1B68`` rows.

    ``tinfo`` deliberately stays ``None``: falling back to the parent's
    type would mis-type unknown member reads as the parent structure.
    """

    def __init__(self, parent: ScanObject, root: SubobjectRoot):
        super().__init__()
        self._parent = parent
        self.root = root
        self.base_offset = root.base_offset
        self.name = parent.name
        self.id = getattr(parent, "id", ObjectType.unknown)
        self.ea = parent.ea
        self.func_ea = parent.func_ea
        self.lvar = getattr(parent, "lvar", None)
        self.index = getattr(parent, "index", None)
        self.inherit_scan_root_from(parent)

    def is_target(self, cexpr) -> bool:
        """True when ``cexpr`` denotes the subobject base expression."""
        base_expr, offset = _extract_offset_expression(cexpr)
        if base_expr is None:
            return False
        if offset != self.base_offset:
            return False
        if self.root.parent_type is not None:
            pointed = _unwrap_struct_type(getattr(base_expr, "type", None))
            if not _type_name_matches(pointed, self.root.parent_type):
                return False
        return self._base_matches(base_expr)

    def _base_matches(self, base_expr) -> bool:
        """True when the base expression is the descriptor's parent variable."""
        matcher = getattr(self._parent, "is_target", None)
        if callable(matcher):
            try:
                return bool(matcher(base_expr))
            except Exception:  # noqa: BLE001 — live ctree objects can throw
                return False
        return False
