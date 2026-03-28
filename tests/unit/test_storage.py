from __future__ import annotations

import json
import zlib

import pytest

from forge.api.storage import (
    BLOB_SIZE,
    INT_KEYS_TAG,
    INT_TO_INT_MAP_TAG,
    STR_KEYS_TAG,
    STR_TO_INT_MAP_TAG,
    NetnodeCorruptError,
    Storage,
    StorageNameError,
)


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


def make_large_payload():
    payload = [f"value_{i}_{i * 17}_{i * i}" for i in range(256)]
    while len(Storage._compress(Storage._encode(payload))) <= BLOB_SIZE:
        payload.extend(f"extra_{i}_{i * 31}" for i in range(len(payload), len(payload) + 256))
    return payload


@pytest.fixture
def storage(monkeypatch):
    nodes = []

    def factory(name, *_args):
        node = FakeNetnode(name)
        nodes.append(node)
        return node

    monkeypatch.setattr("ida_netnode.netnode", factory)
    return Storage("unit"), nodes


def test_storage_rejects_invalid_names():
    with pytest.raises(StorageNameError):
        Storage("")
    with pytest.raises(StorageNameError):
        Storage("bad:name")


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



def test_overwriting_large_value_cleans_old_blob(storage):
    store, nodes = storage
    first = make_large_payload()
    second = make_large_payload() + ["tail_marker"]

    assert len(Storage._compress(Storage._encode(first))) > BLOB_SIZE
    assert len(Storage._compress(Storage._encode(second))) > BLOB_SIZE

    store[1] = first
    old_blob = nodes[0].getblob(0, INT_KEYS_TAG)
    store[1] = second

    assert nodes[0].supval(1, INT_TO_INT_MAP_TAG) == b"0"
    assert nodes[0].getblob(0, INT_KEYS_TAG) != old_blob
    assert store[1] == second



def test_delete_and_missing_key_paths(storage):
    store, _nodes = storage
    store[1] = {"a": 1}
    del store[1]

    with pytest.raises(KeyError):
        _ = store[1]
    with pytest.raises(KeyError):
        del store[1]



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
    node.supset(2, zlib.compress(b"not-json"))
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

    assert set(store.keys()) == {1, 2, "a", "b"}
    assert set(store.values()) == {"one", "two", 1, 2}
    assert set(store.items()) == {(1, "one"), (2, "two"), ("a", 1), ("b", 2)}



def test_kill_reinitializes_backing_netnode(storage):
    store, nodes = storage
    original = store._n
    store[1] = {"a": 1}

    store.kill()

    assert original.killed is True
    assert store._n is not original
    assert len(nodes) == 2
    assert store.keys() == []
