from __future__ import annotations

from types import SimpleNamespace

from forge.api import cache


def test_collect_imported_ea_clears_existing_and_stores_absolute_eas(monkeypatch):
    """SDK path: import stub EAs arrive absolute and are stored absolute —
    the single coordinate system is_imported normalizes to (no RVA math)."""
    cache.imported_ea.update({999})
    imports = {
        0: [(0x140001010, "a", 0), (0x140001020, "b", 1)],
        1: [(0x140001030, "c", 2)],
    }

    monkeypatch.setattr(cache.ida_nalt, "get_import_module_qty", lambda: 3)
    monkeypatch.setattr(cache.ida_nalt, "get_import_module_name", lambda i: "mod" if i != 1 else "")

    def fake_enum_import_names(index, callback):
        for entry in imports.get(index, []):
            callback(*entry)
        return True

    monkeypatch.setattr(cache.ida_nalt, "enum_import_names", fake_enum_import_names)

    cache._collect_imported_ea()

    # module 1 exposes no name, so its entries are never enumerated
    assert cache.imported_ea == {0x140001010, 0x140001020}


def test_collect_imported_ea_domain_path_stores_absolute_eas(monkeypatch):
    """Domain path: entry addresses arrive absolute and are stored absolute —
    subtracting the image base produced RVAs that never matched is_imported's
    normalized (absolute) membership test."""
    class Imports:
        def get_all_imports(self):
            return iter(
                [SimpleNamespace(address=0x140001010), SimpleNamespace(address=0x140001030)]
            )

    monkeypatch.setattr(
        cache,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(imports=Imports(), base_address=0x140000000),
    )
    cache.imported_ea.clear()
    cache._collect_imported_ea()
    assert cache.imported_ea == {0x140001010, 0x140001030}


def test_collect_imported_ea_domain_failure_records_fallback(monkeypatch):
    from forge.api import domain

    class Imports:
        def get_all_imports(self):
            raise RuntimeError("unsupported")

    monkeypatch.setattr(
        cache,
        "_current_domain_database",
        lambda required=False: SimpleNamespace(imports=Imports(), base_address=0x1000),
    )

    monkeypatch.setattr(cache.ida_nalt, "get_import_module_qty", lambda: 0)
    domain.clear_fallback_records()
    cache.imported_ea.clear()
    cache._collect_imported_ea()
    assert any(item.capability == "imports.imported_ea" for item in domain.fallback_records())



def test_initialize_cache_delegates(monkeypatch):
    called = []
    monkeypatch.setattr(cache, "_collect_imported_ea", lambda: called.append(True))

    cache.initialize_cache()

    assert called == [True]
