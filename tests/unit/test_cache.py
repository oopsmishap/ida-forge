from __future__ import annotations

from forge.api import cache



def test_collect_imported_ea_clears_existing_and_subtracts_image_base(monkeypatch):
    cache.imported_ea.update({999})
    imports = {
        0: [(0x1010, "a", 0), (0x1020, "b", 1)],
        1: [(0x1030, "c", 2)],
    }

    monkeypatch.setattr(cache.ida_nalt, "get_imagebase", lambda: 0x1000)
    monkeypatch.setattr(cache.idaapi, "get_import_module_qty", lambda: 3)
    monkeypatch.setattr(cache.idaapi, "get_import_module_name", lambda i: "mod" if i != 1 else "")

    def fake_enum_import_names(index, callback):
        for entry in imports.get(index, []):
            callback(*entry)
        return True

    monkeypatch.setattr(cache.idaapi, "enum_import_names", fake_enum_import_names)

    cache._collect_imported_ea()

    assert cache.imported_ea == {0x10, 0x20}



def test_initialize_cache_delegates(monkeypatch):
    called = []
    monkeypatch.setattr(cache, "_collect_imported_ea", lambda: called.append(True))

    cache.initialize_cache()

    assert called == [True]
