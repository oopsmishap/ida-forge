from __future__ import annotations

import json
import zlib
from typing import Any

import pytest



from forge.api.storage import (
    BLOB_SIZE,
    INT_KEYS_TAG,
    INT_TO_INT_MAP_TAG,
    STR_KEYS_TAG,
    STR_TO_INT_MAP_TAG,
    NetnodeCorruptError,
    Storage,
    StorageError,
    StorageKey,
    StorageNameError,
    StorageUnavailableError,
    StorageValue,
) 


# Documentation helpers
def normalized_doc(value: str | None) -> str:
    """Collapse docstring whitespace and treat missing text as empty."""
    return " ".join((value or "").split())


def test_normalized_doc_helper_is_documented():
    assert "Collapse docstring whitespace" in normalized_doc(normalized_doc.__doc__)


@pytest.mark.parametrize(
    ("value", "expected"),
    ((None, ""), ("", ""), (" \t\n ", ""), ("a\n\t b", "a b")),
    ids=("missing", "empty", "whitespace-only", "mixed-whitespace"),
) 
def test_normalized_doc_handles_whitespace_edges(value, expected):
    assert normalized_doc(value) == expected


def storage_module_doc() -> str:
    """Return normalized documentation for the storage module."""
    from forge.api import storage as storage_module

    return normalized_doc(storage_module.__doc__)


def test_storage_module_doc_helper_has_string_contract():
    doc = storage_module_doc()
    assert isinstance(doc, str)
    assert doc
    assert "immutable ordered ``__all__`` tuple" in doc
    assert "normalized documentation" in normalized_doc(storage_module_doc.__doc__)
    assert "str" in storage_module_doc.__annotations__["return"]

# Export-surface helper
def wildcard_namespace() -> dict[str, object]:
    namespace: dict[str, object] = {}
    exec("from forge.api.storage import *", namespace)
    return namespace


def test_wildcard_namespace_returns_independent_mappings():
    first = wildcard_namespace()
    second = wildcard_namespace()
    first["temporary"] = object()
    assert "temporary" not in second
    assert first["Storage"] is second["Storage"]


def test_wildcard_namespace_helper_has_supported_runtime_shape():
    result = wildcard_namespace()
    assert isinstance(result, dict)
    assert "dict[str, object]" in (wildcard_namespace.__annotations__["return"])

def test_storage_exports_are_immutable():
    from forge.api import storage as storage_module

    assert isinstance(storage_module.__all__, tuple)
    assert storage_module.__all__[-1] == "Storage"


def test_storage_public_exports_are_complete_and_ordered():
    from forge.api import storage as storage_module

    # `__all__` ordering is public compatibility surface, not incidental layout.
    assert storage_module.__all__ == (
        "BLOB_SIZE",
        "INT_KEYS_TAG",
        "STR_KEYS_TAG",
        "STR_TO_INT_MAP_TAG",
        "INT_TO_INT_MAP_TAG",
        "StorageKey",
        "StorageValue",
        "StorageError",
        "NetnodeCorruptError",
        "StorageNameError",
        "StorageUnavailableError",
        "Storage",
    )
    assert len(storage_module.__all__) == len(set(storage_module.__all__))


def test_storage_public_export_order_groups_aliases_before_errors():
    from forge.api import storage as storage_module

    exports = storage_module.__all__
    assert exports.index("StorageKey") < exports.index("StorageError")
    assert exports.index("StorageValue") < exports.index("StorageError")
    assert exports[-1] == "Storage"


def test_storage_wildcard_exports_preserve_value_identity():
    from forge.api import storage as storage_module

    namespace = wildcard_namespace()
    for name in storage_module.__all__:
        assert namespace[name] is getattr(storage_module, name)
    assert "_CORRUPT_READ_ERRORS" not in namespace


def test_storage_wildcard_import_does_not_pollute_namespace():
    from forge.api import storage as storage_module

    namespace = wildcard_namespace()
    assert set(namespace) - {"__builtins__"} == set(storage_module.__all__)
    assert "_CORRUPT_READ_ERRORS" not in namespace
class FakeNetnode:
    def __init__(self, name, *_args):
        self.name = name
        self.sup = {}
        self.hash = {}
        self.blobs = {}
        self.killed = False

    def _sup_bucket(self, tag=None):
        return self.sup.setdefault(tag, {})

    def _hash_bucket(self, tag=None):
        return self.hash.setdefault(tag, {})

    def suplast(self, tag=None):
        keys = set(self._sup_bucket(tag).keys())
        keys.update(slot for blob_tag, slot in self.blobs if blob_tag == tag)
        return max(keys) if keys else None

    def supset(self, key, value, tag=None):
        self._sup_bucket(tag)[key] = value

    def supval(self, key, tag=None):
        return self._sup_bucket(tag).get(key)

    def supdel(self, key, tag=None):
        self._sup_bucket(tag).pop(key, None)

    def supfirst(self, tag=None):
        keys = sorted(self._sup_bucket(tag).keys())
        return keys[0] if keys else -1

    def supnext(self, key, tag=None):
        keys = sorted(self._sup_bucket(tag).keys())
        for candidate in keys:
            if candidate > key:
                return candidate
        return -1

    def hashset(self, key, value, tag=None):
        self._hash_bucket(tag)[key] = value

    def hashval(self, key, tag=None):
        return self._hash_bucket(tag).get(key)

    def hashdel(self, key, tag=None):
        self._hash_bucket(tag).pop(key, None)

    def hashfirst(self, tag=None):
        keys = sorted(self._hash_bucket(tag).keys())
        return keys[0] if keys else -1

    def hashnext(self, key, tag=None):
        keys = sorted(self._hash_bucket(tag).keys())
        for candidate in keys:
            if candidate > key:
                return candidate
        return -1

    def setblob(self, value, key, tag):
        self.blobs[(tag, key)] = value

    def getblob(self, key, tag):
        return self.blobs.get((tag, key))

    def delblob(self, key, tag):
        self.blobs.pop((tag, key), None)

    def kill(self):
        self.killed = True
        self.sup.clear()
        self.hash.clear()
        self.blobs.clear()


def test_storage_module_docs_describe_ordered_public_exports():
    doc = storage_module_doc()
    assert "immutable ordered ``__all__`` tuple" in doc
    assert "corruption helpers remain private" in doc


class FailingWriteNetnode(FakeNetnode):
    def supset(self, key, value, tag=None):
        raise OSError("simulated netnode write failure")

    def hashset(self, key, value, tag=None):
        raise OSError("simulated netnode write failure")


def test_storage_kill_propagates_reopen_failure(storage, monkeypatch):
    store, nodes = storage
    old_node = nodes[0]

    def fail_reopen(*_args):
        raise OSError("simulated reopen failure")

    monkeypatch.setattr("ida_netnode.netnode", fail_reopen)
    with pytest.raises(OSError, match="simulated reopen failure"):
        store.kill()
    assert old_node.killed


def test_storage_module_documents_public_contract():
    doc = storage_module_doc()
    assert "strict direct reads" in doc
    assert "tolerant ``get``" in doc
    assert "StorageError" in doc
    assert "blob slots" in doc


def test_setter_write_failure_occurs_after_existing_entry_deletion(storage, monkeypatch):
    store, nodes = storage
    store[1] = "old-int"
    store["key"] = "old-str"
    failing = FailingWriteNetnode(nodes[0].name)
    failing.sup = nodes[0].sup
    failing.hash = nodes[0].hash
    failing.blobs = nodes[0].blobs
    monkeypatch.setattr(store, "_n", failing)
    with pytest.raises(OSError, match="simulated"):
        store._int_set(1, b"new")
    with pytest.raises(KeyError):
        store[1]
    with pytest.raises(OSError, match="simulated"):
        store._str_set("key", b"new")
    with pytest.raises(KeyError):
        store["key"]



def test_public_write_propagates_netnode_failure_and_documents_contract(storage, monkeypatch):
    store, nodes = storage
    failing = FailingWriteNetnode(nodes[0].name)
    failing.sup = nodes[0].sup
    failing.hash = nodes[0].hash
    failing.blobs = nodes[0].blobs
    monkeypatch.setattr(store, "_n", failing)
    with pytest.raises(OSError, match="simulated"):
        store[1] = "value"
    assert "netnode errors propagate" in (Storage.__setitem__.__doc__ or "")

def make_large_payload():
    payload = [f"value_{i}_{i * 17}_{i * i}" for i in range(256)]
    while len(Storage._compress(Storage._encode(payload))) <= BLOB_SIZE:
        payload.extend(f"extra_{i}_{i * 31}" for i in range(len(payload), len(payload) + 256))
    return payload


def install_malformed_json(node, key=1):
    node.supset(key, zlib.compress(b"not-json"))


@pytest.fixture
def storage(monkeypatch):
    nodes = []

    def factory(name, *_args):
        node = FakeNetnode(name)
        nodes.append(node)
        return node

    monkeypatch.setattr("ida_netnode.netnode", factory)
    return Storage("unit"), nodes


def test_storage_fixture_creates_isolated_netnode(storage, monkeypatch):
    store, nodes = storage
    store[1] = "first"
    isolated_nodes = []

    def factory(name, *_args):
        node = FakeNetnode(name)
        isolated_nodes.append(node)
        return node

    monkeypatch.setattr("ida_netnode.netnode", factory)
    isolated = Storage("unit-isolated")
    assert isolated_nodes[0] is not nodes[0]
    with pytest.raises(KeyError):
        _ = isolated[1]


def test_storage_rejects_invalid_names():
    with pytest.raises(StorageNameError):
        Storage("")
    with pytest.raises(StorageNameError):
        Storage("bad:name")


def test_storage_rejects_non_string_names():
    with pytest.raises(TypeError, match="must be strings"):
        Storage(123)


def test_storage_reports_unavailable_netnode(monkeypatch):
    monkeypatch.setattr("forge.api.storage.ida_netnode", None)
    with pytest.raises(StorageUnavailableError, match="requires IDA netnode"):
        Storage("unit")




def test_storage_lifecycle_methods_are_compatibility_noops(storage):
    store, nodes = storage
    node = nodes[0]
    assert store.open() is None
    assert store.close() is None
    assert store._n is node
    assert "compatibility" in (Storage.open.__doc__ or "")
    assert "explicit destruction" in (Storage.close.__doc__ or "")


def test_storage_public_exports_include_availability_error():
    namespace = wildcard_namespace()
    assert namespace["StorageUnavailableError"] is StorageUnavailableError
    assert "_CORRUPT_READ_ERRORS" not in namespace


def test_storage_kill_reopens_a_clean_netnode(storage):
    store, nodes = storage
    store[1] = "value"
    old_node = nodes[0]
    store.kill()
    assert old_node.killed
    assert store._n is nodes[1]
    with pytest.raises(KeyError):
        _ = store[1]


def test_storage_kill_is_repeatable_and_reusable(storage):
    store, nodes = storage
    store[1] = "value"
    store.kill()
    store.kill()
    assert nodes[1].killed
    assert store.keys() == []
    store[1] = "after-kill"
    assert store[1] == "after-kill"


def test_storage_errors_preserve_runtime_error_compatibility():
    for error_type in (
        NetnodeCorruptError,
        StorageNameError,
        StorageUnavailableError,
    ):
        assert issubclass(error_type, StorageError)
        assert issubclass(error_type, RuntimeError)


def test_storage_kill_reopens_same_object_for_new_values(storage):
    store, _nodes = storage
    store["before"] = "old"
    store.kill()
    with pytest.raises(KeyError):
        _ = store["before"]
    store["after"] = "new"
    assert store["after"] == "new"
    assert "Destructively" in (Storage.kill.__doc__ or "")


def test_storage_errors_share_public_base():
    assert issubclass(NetnodeCorruptError, StorageError)
    assert issubclass(StorageNameError, StorageError)
    assert issubclass(StorageUnavailableError, StorageError)


def test_storage_public_aliases_are_type_aliases():
    assert StorageKey == str | int
    assert StorageValue is Any


def test_small_int_and_string_values_roundtrip(storage):
    store, _nodes = storage
    store[1] = {"a": 1}
    store["key"] = [1, 2, 3]

    assert store[1] == {"a": 1}
    assert store["key"] == [1, 2, 3]
    assert 1 in store
    assert "key" in store



def test_large_values_use_blob_storage(storage):
    store, nodes = storage
    payload = make_large_payload()

    assert len(Storage._compress(Storage._encode(payload))) > BLOB_SIZE

    store[1] = payload
    store["key"] = payload

    node = nodes[0]


    assert node.supval(1, INT_TO_INT_MAP_TAG) == b"0"
    assert node.hashval("key", STR_TO_INT_MAP_TAG) == b"0"
    assert node.getblob(0, INT_KEYS_TAG) is not None
    assert node.getblob(0, STR_KEYS_TAG) is not None
    assert store[1] == payload
    assert store["key"] == payload


def test_blob_threshold_is_strictly_greater_than_limit(storage):
    store, nodes = storage
    exact = b"e" * BLOB_SIZE
    large = b"l" * (BLOB_SIZE + 1)
    store._int_set(1, exact)
    store._str_set("exact", exact)
    assert nodes[0].supval(1, INT_TO_INT_MAP_TAG) is None
    assert nodes[0].hashval("exact", STR_TO_INT_MAP_TAG) is None
    assert store._int_get(1) == exact
    assert store._str_get("exact") == exact

    store._int_set(2, large)
    store._str_set("large", large)
    assert nodes[0].supval(2, INT_TO_INT_MAP_TAG) == b"0"
    assert nodes[0].hashval("large", STR_TO_INT_MAP_TAG) == b"0"
    assert store._int_get(2) == large
    assert store._str_get("large") == large


def test_blob_predicate_matches_threshold_contract(storage):
    assert Storage._uses_blob(b"x" * BLOB_SIZE) is False
    assert Storage._uses_blob(b"x" * (BLOB_SIZE + 1)) is True


def test_blob_predicate_rejects_non_bytes():
    with pytest.raises(AssertionError):
        Storage._uses_blob("not-bytes")
def test_storage_corrupt_utf8_is_treated_as_missing(storage):
    store, nodes = storage
    node = nodes[0]
    node.supset("bad", zlib.compress(b"\xff"))
    assert store.get("bad", "default") == "default"


def test_setters_reject_non_bytes_without_mutation(storage):
    store, _nodes = storage
    store[1] = "int-old"
    store["key"] = "str-old"
    with pytest.raises(AssertionError):
        store._int_set(1, "bad")
    with pytest.raises(AssertionError):
        store._str_set("key", "bad")
    assert store[1] == "int-old"
    assert store["key"] == "str-old"
    assert "bad" not in store


def test_low_level_setters_document_replacement_contract():
    assert "Replace" in (Storage._int_set.__doc__ or "")
    assert "Replace" in (Storage._str_set.__doc__ or "")



def test_overwriting_large_value_cleans_old_blob(storage):
    store, nodes = storage
    first = make_large_payload()
    second = [*make_large_payload(), "tail_marker"]

    assert len(Storage._compress(Storage._encode(first))) > BLOB_SIZE
    assert len(Storage._compress(Storage._encode(second))) > BLOB_SIZE

    store[1] = first
    old_blob = nodes[0].getblob(0, INT_KEYS_TAG)
    store[1] = second

    assert nodes[0].supval(1, INT_TO_INT_MAP_TAG) == b"0"
    assert nodes[0].getblob(0, INT_KEYS_TAG) != old_blob
    assert store[1] == second



def test_deleting_blob_entry_preserves_unrelated_slots(storage):
    store, nodes = storage
    first = make_large_payload()
    second = [*make_large_payload(), "second"]
    store[1] = first
    store[2] = second
    node = nodes[0]
    first_slot = int(node.supval(1, INT_TO_INT_MAP_TAG))
    second_slot = int(node.supval(2, INT_TO_INT_MAP_TAG))
    assert first_slot != second_slot

    del store[1]

    assert (INT_KEYS_TAG, first_slot) not in node.blobs
    assert (INT_KEYS_TAG, second_slot) in node.blobs
    assert node.supval(1, INT_TO_INT_MAP_TAG) is None
    assert store[2] == second



def test_blob_slots_are_monotonic_after_deletion(storage):
    store, nodes = storage
    first = make_large_payload()
    second = [*make_large_payload(), "second"]
    third = [*make_large_payload(), "third"]
    store[1] = first
    store[2] = second
    node = nodes[0]
    first_slot = int(node.supval(1, INT_TO_INT_MAP_TAG))
    second_slot = int(node.supval(2, INT_TO_INT_MAP_TAG))
    del store[1]
    store[3] = third
    third_slot = int(node.supval(3, INT_TO_INT_MAP_TAG))

    assert third_slot > second_slot > first_slot
    assert (INT_KEYS_TAG, first_slot) not in node.blobs
    assert store[2] == second
    assert store[3] == third

def test_delete_and_missing_key_paths(storage):
    store, _nodes = storage
    store[1] = {"a": 1}
    del store[1]

    with pytest.raises(KeyError):
        _ = store[1]
    with pytest.raises(KeyError):
        del store[1]


def test_delete_propagates_malformed_blob_mapping(storage):
    store, nodes = storage
    nodes[0].supset(1, b"not-an-integer", INT_TO_INT_MAP_TAG)
    with pytest.raises(ValueError):
        del store[1]


def test_delete_propagates_malformed_string_blob_mapping(storage):
    store, nodes = storage
    nodes[0].hashset("bad", b"not-an-integer", STR_TO_INT_MAP_TAG)
    with pytest.raises(ValueError):
        del store["bad"]


def test_tolerant_reads_treat_malformed_mappings_as_corrupt(storage):
    store, nodes = storage
    nodes[0].supset(1, b"bad", INT_TO_INT_MAP_TAG)
    nodes[0].hashset("bad", b"bad", STR_TO_INT_MAP_TAG)
    assert store.get(1, "default-int") == "default-int"
    assert store.get("bad", "default-str") == "default-str"
    assert 1 not in store
    assert "bad" not in store
    with pytest.raises(ValueError):
        _ = store[1]
    with pytest.raises(ValueError):
        _ = store["bad"]


def test_corrupt_read_error_tuple_is_narrow_and_documented():
    from forge.api import storage as storage_module

    errors = storage_module._CORRUPT_READ_ERRORS
    assert errors == (
        KeyError,
        NetnodeCorruptError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        zlib.error,
    )
    assert Exception not in errors
def test_storage_docs_distinguish_payload_and_mapping_corruption():
    doc = storage_module_doc()
    assert "corrupt payload bytes" in doc
    assert "malformed blob-slot metadata" in doc
    assert "strict reads propagate" in doc


def test_storage_class_docs_strict_metadata_propagation():
    doc = normalized_doc(Storage.__doc__)
    assert "malformed blob metadata propagates" in doc
    assert "membership tolerate corrupt entries" in doc


def test_storage_class_docs_deletion_metadata_contract():
    doc = normalized_doc(Storage.__doc__)
    assert "Deletion skips" in doc
    assert "decodes blob metadata" in doc
    assert "metadata propagates" in doc

def test_invalid_key_types_raise(storage):
    store, _nodes = storage

    with pytest.raises(TypeError):
        _ = store[object()]
    with pytest.raises(TypeError):
        store[object()] = 1
    with pytest.raises(TypeError):
        del store[object()]



def test_get_and_contains_handle_corruption_and_decode_errors(storage):
    store, nodes = storage
    node = nodes[0]
    node.supset(1, b"not-zlib")
    install_malformed_json(node, 2)
    node.supset(3, b"0", INT_TO_INT_MAP_TAG)

    assert store.get(1, "default") == "default"
    assert store.get(2, "default") == "default"
    assert store.get(3, "default") == "default"
    assert 1 not in store
    assert 2 not in store
    assert 3 not in store
    with pytest.raises(NetnodeCorruptError):
        _ = store[3]




def test_iterators_return_mixed_keys_values_and_items(storage):
    store, _nodes = storage
    store[2] = "two"
    store[1] = "one"

    store["b"] = 2
    store["a"] = 1
    assert list(store.iterkeys()) == [1, 2, "a", "b"]
    assert store.keys() == [1, 2, "a", "b"]
    assert list(store.itervalues()) == ["one", "two", 1, 2]
    assert store.items() == [(1, "one"), (2, "two"), ("a", 1), ("b", 2)]


def test_storage_read_contracts_are_documented(storage):
    assert "corrupt" in normalized_doc(Storage.__getitem__.__doc__)
    assert "default" in normalized_doc(Storage.get.__doc__)
    assert "decodable" in normalized_doc(Storage.__contains__.__doc__)




def test_storage_class_contract_is_documented(storage):
    doc = Storage.__doc__ or ""
    assert "small integer" in doc
    assert "large string" in doc
    assert "strict" in doc
    assert "tolerate corrupt" in doc


def test_corrupt_entries_can_be_deleted_and_overwritten(storage):
    store, nodes = storage
    nodes[0].supset(1, b"not-zlib")
    nodes[0].hashset("bad", b"not-zlib")
    del store[1]
    del store["bad"]
    with pytest.raises(KeyError):
        _ = store[1]
    with pytest.raises(KeyError):
        _ = store["bad"]

    nodes[0].supset(2, b"not-zlib")
    nodes[0].hashset("replace", b"not-zlib")
    store[2] = "recovered-int"
    store["replace"] = "recovered-str"
    assert store[2] == "recovered-int"
    assert store["replace"] == "recovered-str"


def test_storage_mutation_contract_is_documented(storage):
    assert "JSON-serializable" in normalized_doc(Storage.__setitem__.__doc__)
    assert "without decoding" in normalized_doc(Storage.__delitem__.__doc__)


def test_storage_documents_blob_lifecycle_contract(storage):
    doc = normalized_doc(Storage.__doc__)
    assert "larger than ``BLOB_SIZE``" in doc
    assert "removes its mapping and blob" in doc
    assert "advance monotonically" in doc


def test_storage_value_iterators_document_strict_reads(storage):
    assert "strict" in normalized_doc(Storage.itervalues.__doc__)
    assert "strict" in normalized_doc(Storage.values.__doc__)
    assert "strict" in normalized_doc(Storage.iteritems.__doc__)
    assert "strict" in normalized_doc(Storage.items.__doc__)
def test_corrupt_blob_entries_can_be_deleted_and_overwritten(storage):
    store, nodes = storage
    payload = make_large_payload()
    store[1] = payload
    old_int_blob = nodes[0].getblob(0, INT_KEYS_TAG)
    store["bad"] = payload
    old_str_blob = nodes[0].getblob(0, STR_KEYS_TAG)
    nodes[0].blobs[(INT_KEYS_TAG, 0)] = b"not-zlib"
    nodes[0].blobs[(STR_KEYS_TAG, 0)] = b"not-zlib"

    del store[1]
    del store["bad"]
    assert nodes[0].getblob(0, INT_KEYS_TAG) is None
    assert nodes[0].getblob(0, STR_KEYS_TAG) is None

    store[1] = payload
    store["bad"] = payload
    assert nodes[0].getblob(0, INT_KEYS_TAG) is not None
    assert nodes[0].getblob(0, STR_KEYS_TAG) is not None
    assert store[1] == payload
    assert store["bad"] == payload


def test_strict_value_iterators_raise_on_corrupt_entries(storage):
    store, nodes = storage
    install_malformed_json(nodes[0])
    with pytest.raises(json.JSONDecodeError):
        store.values()
    with pytest.raises(json.JSONDecodeError):
        store.items()




def test_iterkeys_sorts_each_namespace_lazily(storage):
    store, _nodes = storage
    events = []

    def first():
        events.append("first")
        yield 2
        yield 1

    def second():
        events.append("second")
        yield "b"
        yield "a"

    store._iter_int_keys_small = first
    store._iter_int_keys_large = lambda: iter(())
    store._iter_str_keys_small = second
    store._iter_str_keys_large = lambda: iter(())
    iterator = store.iterkeys()
    assert next(iterator) == 1
    assert events == ["first"]
    assert list(iterator) == [2, "a", "b"]
    assert events == ["first", "second"]


def test_kill_reinitializes_backing_netnode(storage):
    store, nodes = storage
    original = store._n
    store[1] = {"a": 1}

    store.kill()

    assert original.killed is True
    assert store._n is not original
    assert len(nodes) == 2
    assert store.keys() == []
