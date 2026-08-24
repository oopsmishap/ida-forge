"""Shared structure catalog with optional netnode persistence (I.28).

The catalog is the single source of truth for the structure store. It is
dict-like over structure names so every existing caller keeps working,
adds ``unique_name``/``current`` helpers, and persists a portable
description (never live tinfo handles — the T1.1 rule) to
``Storage("Structures")`` after every mutation, reloading lazily on first
access. Persistence failures only degrade to a warning — they never break
facade operations.
"""

from __future__ import annotations

import dataclasses

from forge.api.storage import Storage
from forge.util.logging import log_warning

_STORAGE_KEY = "Structures"


def _live_scan_site_rows(structure) -> list:
    """Site rows derived from the members' live scan objects (R3.6).

    Plain JSON rows only (the T1.1 rule: never live tinfo handles) —
    ``{"func_ea", "var", "ea", "type", "member_offset"}`` per recorded
    scan-object site, deduplicated like the apply step does.
    """
    from forge.api.structure import Structure

    rows: list = []
    seen: set = set()
    for member in structure.members:
        for scan_object in getattr(member, "scanned_variables", None) or ():
            identity_key = getattr(scan_object, "identity_key", None)
            key = (
                identity_key()
                if callable(identity_key)
                else (
                    getattr(scan_object, "func_ea", None),
                    getattr(scan_object, "ea", None),
                    getattr(scan_object, "id", None),
                    getattr(scan_object, "name", None),
                )
            )
            if key in seen or key == (None, None):
                continue
            seen.add(key)
            try:
                row = Structure._scan_site_row(scan_object)
            except Exception as exc:  # noqa: BLE001 — one degenerate object degrades
                from forge.util.logging import log_debug

                log_debug(f"scan-site row failed for {scan_object!r}: {exc}")
                continue
            row["member_offset"] = getattr(member, "offset", 0)
            rows.append(row)
    return rows


def _scan_sites_payload(structure) -> list:
    """The persisted scan-site rows for a structure.

    Live member scan objects win (a fresh scan updates the model); with
    no live objects — e.g. right after a catalog reload — the previously
    persisted rows are kept so a re-snapshot never erases them.
    """
    rows = _live_scan_site_rows(structure)
    if rows:
        return rows
    return list(getattr(structure, "scan_sites_rows", None) or [])


class StructureCatalog:
    """Dict-like store of :class:`Structure` with write-through persistence."""

    def __init__(self):
        self._structures: dict = {}
        self._current: str | None = None
        self._loaded = False
        self.events: list = []

    # -- persistence -------------------------------------------------------

    @staticmethod
    def _storage() -> Storage:
        return Storage(_STORAGE_KEY)

    def _ensure_loaded(self) -> None:
        """Lazy one-time load from the persisted catalog description."""
        if self._loaded:
            return
        self._loaded = True
        try:
            stored = self._storage().get("data", None)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            log_warning(f"could not read persisted structure catalog: {exc}")
            return
        if not stored:
            return
        for raw in stored.get("structures", []) or []:
            try:
                structure = self._deserialize(raw)
            except Exception as exc:  # noqa: BLE001 — skip corrupt entries
                log_warning(
                    f"skipping corrupt catalog entry {raw.get('name', '?')!r}: {exc}"
                )
                continue
            self._structures[structure.name] = structure
        if stored.get("current") in self._structures:
            self._current = stored["current"]

    def _snapshot(self) -> None:
        """Write-through persistence; never raises."""
        try:
            self._storage()["data"] = {
                "structures": [self._serialize(s) for s in self._structures.values()],
                "current": self._current,
            }
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            log_warning(f"could not persist structure catalog: {exc}")

    def _serialize(self, structure) -> dict:
        from forge.api.members import VirtualTable

        provenance = structure.provenance
        if not isinstance(provenance, dict):
            provenance = dataclasses.asdict(provenance) or {}
        members = []
        for member in structure.members:
            tinfo = getattr(member, "tinfo", None)
            type_str = ""
            dstr = getattr(tinfo, "dstr", None)
            if callable(dstr):
                try:
                    type_str = dstr()
                except Exception:  # noqa: BLE001 — stub tinfos may break
                    type_str = ""
            entry = {
                "offset": member.offset,
                "name": getattr(member, "name", ""),
                "type": type_str,
                # The authored declaration string (E4): re-parsed fresh at
                # pack time so stale tinfo ordinals can never serialize as
                # ``#NN *``. Persisted so members keep it across reloads.
                "decl_src": getattr(member, "decl_src", None),
                "comment": getattr(member, "comment", ""),
                "enabled": getattr(member, "enabled", True),
                "is_array": getattr(member, "is_array", False),
                "origin": getattr(member, "origin", 0),
                "kind": "vtable" if isinstance(member, VirtualTable) else "member",
            }
            if entry["kind"] == "vtable":
                entry["vtable_address"] = getattr(member, "address", 0)
            members.append(entry)
        return {
            "name": structure.name,
            "main_offset": structure.main_offset,
            "created_type_name": structure.created_type_name,
            "is_auto_named": structure.is_auto_named,
            "pack": structure.pack,
            # R3.6: scan-evidence sites ride the catalog's netnode payload —
            # plain rows only (the T1.1 rule: never live tinfo handles), so
            # scan_sites() answers from the DB after any reopen/rebuild.
            "scan_sites": _scan_sites_payload(structure),
            "last_applied": list(getattr(structure, "last_apply_sites", [])),
            "provenance": provenance,
            "members": members,
            "child_relationships": [
                {
                    "parent_structure_name": rel.parent_structure_name,
                    "child_structure_name": rel.child_structure_name,
                    "parent_member_offset": rel.parent_member_offset,
                    "parent_member_name": rel.parent_member_name,
                    "relation_kind": rel.relation_kind,
                }
                for rel in structure.child_relationships
            ],
        }

    def _deserialize(self, raw: dict):
        from forge.api.members import Member, VirtualTable, parse_user_tinfo
        from forge.api.structure import Structure, StructureProvenance

        structure = Structure(raw["name"])
        structure.main_offset = raw.get("main_offset", 0)
        structure.created_type_name = raw.get("created_type_name")
        structure.is_auto_named = raw.get("is_auto_named", False)
        # R3.2: existing persisted catalogs default to packed (no migration).
        structure.pack = raw.get("pack", 1)
        structure.scan_sites_rows = list(raw.get("scan_sites") or [])
        structure.last_apply_sites = list(raw.get("last_applied") or [])
        prov = raw.get("provenance") or {}
        known = set(StructureProvenance.__dataclass_fields__)
        structure.provenance = StructureProvenance(
            **{key: value for key, value in prov.items() if key in known}
        )
        for member_raw in raw.get("members", []) or []:
            try:
                if member_raw.get("kind") == "vtable":
                    member = VirtualTable(
                        member_raw.get("offset", 0),
                        member_raw.get("vtable_address", 0),
                        None,
                        member_raw.get("origin", 0),
                    )
                else:
                    tinfo = parse_user_tinfo(member_raw.get("type") or "u64")
                    if tinfo is None:
                        log_warning(
                            f"catalog member type {member_raw.get('type')!r} did not "
                            "parse; using u64"
                        )
                        tinfo = parse_user_tinfo("u64")
                    member = Member(
                        member_raw.get("offset", 0),
                        tinfo,
                        None,
                        member_raw.get("origin", 0),
                    )
                    member.name = member_raw.get("name") or member.name
                    member.decl_src = member_raw.get("decl_src")
            except Exception as exc:  # noqa: BLE001 — skip broken members
                log_warning(f"skipping corrupt catalog member: {exc}")
                continue
            member.enabled = member_raw.get("enabled", True)
            member.comment = member_raw.get("comment", "")
            member.is_array = member_raw.get("is_array", False)
            structure.members.append(member)
        for rel in raw.get("child_relationships", []) or []:
            structure.add_child_relationship(
                child_structure_name=rel.get("child_structure_name", ""),
                parent_member_offset=rel.get("parent_member_offset", 0),
                parent_member_name=rel.get("parent_member_name", ""),
                relation_kind=rel.get("relation_kind", "pointer"),
            )
        structure.refresh_collisions()
        return structure

    # -- change notification ------------------------------------------------

    def notify_changed(self) -> None:
        for handler in list(self.events):
            try:
                handler()
            except Exception as exc:  # noqa: BLE001 — UI callbacks must not break the store
                log_warning(f"catalog change handler failed: {exc}")

    def _mark_dirty(self) -> None:
        self._ensure_loaded()
        self._snapshot()
        self.notify_changed()

    # -- dict-like API -------------------------------------------------------

    def __getitem__(self, name: str):
        self._ensure_loaded()
        return self._structures[name]

    def get(self, name: str, default=None):
        self._ensure_loaded()
        return self._structures.get(name, default)

    def __contains__(self, name: str) -> bool:
        self._ensure_loaded()
        return name in self._structures

    def __iter__(self):
        self._ensure_loaded()
        return iter(self._structures)

    def __len__(self) -> int:
        self._ensure_loaded()
        return len(self._structures)

    def __setitem__(self, name: str, structure) -> None:
        self._ensure_loaded()
        self._structures[name] = structure
        self._mark_dirty()

    def __delitem__(self, name: str) -> None:
        self._ensure_loaded()
        del self._structures[name]
        self._mark_dirty()

    def keys(self):
        self._ensure_loaded()
        return self._structures.keys()

    def values(self):
        self._ensure_loaded()
        return self._structures.values()

    def items(self):
        self._ensure_loaded()
        return self._structures.items()

    def clear(self) -> None:
        """Drop every structure and reset the current selection."""
        self._ensure_loaded()
        self._structures.clear()
        self._current = None
        self._mark_dirty()

    # -- helpers --------------------------------------------------------------

    @property
    def current(self) -> str | None:
        self._ensure_loaded()
        return self._current

    @current.setter
    def current(self, value: str | None) -> None:
        self._ensure_loaded()
        if self._current != value:
            self._current = value
            self._mark_dirty()

    def unique_name(self, base: str) -> str:
        """A name not yet taken: ``base``, or ``base Copy``, ``base Copy 2``..."""
        self._ensure_loaded()
        if base not in self._structures:
            return base
        copy_index = 2
        candidate = f"{base} Copy"
        while candidate in self._structures:
            candidate = f"{base} Copy {copy_index}"
            copy_index += 1
        return candidate


catalog = StructureCatalog()