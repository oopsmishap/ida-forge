
"""Persistent JSON storage backed by IDA netnodes.

The public API supports strict direct reads and iterators, tolerant ``get`` and
membership reads, and explicit mutation of integer or string keys. Its immutable
ordered ``__all__`` tuple defines the public export surface; corruption helpers
remain private. Tolerant reads treat corrupt payload bytes and malformed
blob-slot metadata as missing; strict reads propagate the underlying corruption
exception. Storage errors share :class:`StorageError`; large compressed values
use blob slots that are removed with their mappings and allocated monotonically.
"""

from __future__ import annotations

import contextlib
import json
import zlib
from collections.abc import Iterable
from typing import Any, TypeAlias

try:
    import ida_netnode
except ImportError:  # pragma: no cover - headless import only
    ida_netnode = None

from forge.api.domain import sdk_fallback
from forge.plugin import PLUGIN_BASE_NETNODE_ID
from forge.util.logging import log_debug

__all__ = (
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

BLOB_SIZE = 1024
INT_KEYS_TAG = "M"
STR_KEYS_TAG = "N"
STR_TO_INT_MAP_TAG = "O"
INT_TO_INT_MAP_TAG = "P"

StorageKey: TypeAlias = str | int
StorageValue: TypeAlias = Any

class StorageError(RuntimeError):
    """Base class for storage-specific failures."""

class NetnodeCorruptError(StorageError):
    """Raised when the underlying netnode mapping points at missing blob data."""


_CORRUPT_READ_ERRORS = (
    # Missing entries, malformed blob metadata, and corrupt payload bytes.
    KeyError,
    NetnodeCorruptError,
    ValueError,
    UnicodeDecodeError,
    json.JSONDecodeError,
    zlib.error,
) 

class StorageNameError(StorageError):
    """Raised when a storage namespace cannot be represented safely."""


class StorageUnavailableError(StorageError):
    """Raised when IDA netnode persistence is unavailable."""
# https://github.com/williballenthin/ida-netnode
class Storage:
    """Store JSON-serializable data in IDA netnodes.

    Key iteration preserves the four namespaces in this order: small integer,
    large integer, small string, then large string. Direct indexing and value
    iteration are strict; malformed blob metadata propagates through strict
    reads, while ``get`` and membership tolerate corrupt entries.
    Deletion skips payload decoding but decodes blob metadata; malformed
    metadata propagates. Compressed values larger than ``BLOB_SIZE`` use blob
    slots, and deletion removes its mapping and blob; new blob slots advance
    monotonically.
    """

    def __init__(self, name: str):
        if not isinstance(name, str):
            raise TypeError("Storage names must be strings")
        if not name or ":" in name:
            raise StorageNameError(
                "Storage names must be non-empty and must not contain ':'."
            )
        if ida_netnode is None:
            sdk_fallback(
                "storage.netnode",
                "ida-domain exposes no persistent netnode namespace",
            )
            raise StorageUnavailableError(
                "forge storage requires IDA netnode persistence"
            )
        self.name = f"{PLUGIN_BASE_NETNODE_ID}:{name}"
        self._n = ida_netnode.netnode(self.name, 0, True)
        log_debug(f"loaded storage {self.name}")

    def open(self) -> None:
        """Keep the already-open netnode available; retained for compatibility."""
        pass

    def close(self) -> None:
        """Leave the netnode available; explicit destruction uses :meth:`kill`."""
        pass

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        return zlib.decompress(data)

    @staticmethod
    def _compress(data: bytes) -> bytes:
        return zlib.compress(data)

    @staticmethod
    def _encode(data: StorageValue) -> bytes:
        return json.dumps(data).encode("ascii")

    @staticmethod
    def _decode(data: bytes) -> StorageValue:
        return json.loads(data.decode("ascii"))

    @staticmethod
    def _uses_blob(value: bytes) -> bool:
        """Whether compressed bytes exceed the inline storage threshold."""
        assert isinstance(value, bytes)
        return len(value) > BLOB_SIZE

    def _get_next_slot(self, tag: str) -> int:
        slot = self._n.suplast(tag)
        if slot is None or slot == ida_netnode.BADNODE:
            return 0
        return slot + 1

    def _int_set(self, key: int, value: bytes) -> None:
        """Replace an integer value after validating compressed bytes."""
        assert isinstance(key, int)
        assert isinstance(value, bytes)

        with contextlib.suppress(KeyError):
            self._int_del(key)

        if self._uses_blob(value):
            store_key = self._get_next_slot(INT_KEYS_TAG)
            self._n.setblob(value, store_key, INT_KEYS_TAG)
            self._n.supset(key, str(store_key).encode("utf-8"), INT_TO_INT_MAP_TAG)
        else:
            self._n.supset(key, value)

    def _int_get(self, key: int) -> bytes:
        assert isinstance(key, int)

        store_key = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if store_key is not None:
            store_key = int(store_key.decode("utf-8"))
            v = self._n.getblob(store_key, INT_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.supval(key)
        if v is not None:
            return v

        raise KeyError(f"'{key}' not found")

    def _int_del(self, key: int) -> None:
        assert isinstance(key, int)

        did_del = False
        store_key = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if store_key is not None:
            store_key = int(store_key.decode("utf-8"))
            self._n.delblob(store_key, INT_KEYS_TAG)
            self._n.supdel(key, INT_TO_INT_MAP_TAG)
            did_del = True
        if self._n.supval(key) is not None:
            self._n.supdel(key)
            did_del = True

        if not did_del:
            raise KeyError(f"'{key}' not found")

    def _str_set(self, key: str, value: bytes) -> None:
        """Replace a string value after validating compressed bytes."""
        assert isinstance(key, str)
        assert isinstance(value, bytes)

        with contextlib.suppress(KeyError):
            self._str_del(key)

        if self._uses_blob(value):
            store_key = self._get_next_slot(STR_KEYS_TAG)
            self._n.setblob(value, store_key, STR_KEYS_TAG)
            self._n.hashset(key, str(store_key).encode("utf-8"), STR_TO_INT_MAP_TAG)
        else:
            self._n.hashset(key, value)

    def _str_get(self, key: str) -> bytes:
        assert isinstance(key, str)

        store_key = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if store_key is not None:
            store_key = int(store_key.decode("utf-8"))
            v = self._n.getblob(store_key, STR_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.hashval(key)
        if v is not None:
            return v

        raise KeyError(f"'{key}' not found")

    def _str_del(self, key: str) -> None:
        assert isinstance(key, str)

        did_del = False
        store_key = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if store_key is not None:
            store_key = int(store_key.decode("utf-8"))
            self._n.delblob(store_key, STR_KEYS_TAG)
            self._n.hashdel(key, STR_TO_INT_MAP_TAG)
            did_del = True
        if self._n.hashval(key) is not None:
            self._n.hashdel(key)
            did_del = True

        if not did_del:
            raise KeyError(f"'{key}' not found")

    def __getitem__(self, key: StorageKey) -> StorageValue:
        """Read a value, raising for missing or corrupt storage entries."""
        if isinstance(key, str):
            v = self._str_get(key)
        elif isinstance(key, int):
            v = self._int_get(key)
        else:
            raise TypeError(f"cannot use {type(key)} as k")

        data = self._decompress(v)
        return self._decode(data)

    def __setitem__(self, key: StorageKey, value: StorageValue) -> None:
        """Write JSON-serializable data; serialization precedes mutation and netnode errors propagate."""
        assert value is not None
        v = self._compress(self._encode(value))

        if isinstance(key, str):
            self._str_set(key, v)
        elif isinstance(key, int):
            self._int_set(key, v)
        else:
            raise TypeError(f"cannot use {type(key)} as k")

    def __delitem__(self, key: StorageKey) -> None:
        """Delete without decoding payloads; malformed mapping metadata raises."""
        if isinstance(key, str):
            self._str_del(key)
        elif isinstance(key, int):
            self._int_del(key)
        else:
            raise TypeError(f"cannot use {type(key)} as k")
    def get(self, key: StorageKey, default: StorageValue = None) -> StorageValue:
        """Return a value or ``default`` for missing/corrupt entries."""
        try:
            return self[key]
        except _CORRUPT_READ_ERRORS:
            return default

    def __contains__(self, key: StorageKey) -> bool:
        """Whether a valid, decodable value exists for ``key``."""
        try:
            self[key]
            return True
        except _CORRUPT_READ_ERRORS:
            return False

    def _iter_int_keys_small(self) -> Iterable[int]:
        i = self._n.supfirst()
        while i != ida_netnode.BADNODE:
            yield i
            i = self._n.supnext(i)

    def _iter_int_keys_large(self) -> Iterable[int]:
        i = self._n.supfirst(INT_TO_INT_MAP_TAG)
        while i != ida_netnode.BADNODE:
            yield i
            i = self._n.supnext(i, INT_TO_INT_MAP_TAG)

    def _iter_str_keys_small(self) -> Iterable[str]:
        i = self._n.hashfirst()
        while i != ida_netnode.BADNODE and i is not None:
            yield i
            i = self._n.hashnext(i)

    def _iter_str_keys_large(self) -> Iterable[str]:
        i = self._n.hashfirst(STR_TO_INT_MAP_TAG)
        while i != ida_netnode.BADNODE and i is not None:
            yield i
            i = self._n.hashnext(i, STR_TO_INT_MAP_TAG)

    def iterkeys(self) -> Iterable[StorageKey]:
        """Yield deterministic keys, sorting one namespace at a time.

        The four storage namespaces retain their established order; only the
        currently yielded namespace is materialized for sorting.
        """
        for iterator in (
            self._iter_int_keys_small,
            self._iter_int_keys_large,
            self._iter_str_keys_small,
            self._iter_str_keys_large,
        ):
            yield from sorted(iterator())

    def keys(self) -> list[StorageKey]:
        return list(self.iterkeys())

    def itervalues(self) -> Iterable[StorageValue]:
        """Yield values strictly; missing/corrupt entries raise."""
        for k in self.iterkeys():
            yield self[k]

    def values(self) -> list[StorageValue]:
        """Return strict values; missing/corrupt entries raise."""
        return list(self.itervalues())

    def iteritems(self) -> Iterable[tuple[StorageKey, StorageValue]]:
        """Yield strict key/value pairs; corrupt entries raise."""
        for k in self.iterkeys():
            yield k, self[k]

    def items(self) -> list[tuple[StorageKey, StorageValue]]:
        """Return strict key/value pairs; corrupt entries raise."""
        return list(self.iteritems())

    def kill(self) -> None:
        """Destructively clear this namespace and reopen it for reuse."""
        self._n.kill()
        self._n = ida_netnode.netnode(self.name, 0, True)
