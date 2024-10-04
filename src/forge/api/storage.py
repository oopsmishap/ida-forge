import json
import zlib
from typing import List, Union, Iterable, Tuple

import ida_netnode

from forge.plugin import PLUGIN_BASE_NETNODE_ID
from forge.util.logging import *

BLOB_SIZE = 1024
INT_KEYS_TAG = "M"
STR_KEYS_TAG = "N"
STR_TO_INT_MAP_TAG = "O"
INT_TO_INT_MAP_TAG = "P"


class NetnodeCorruptError(RuntimeError):
    pass


class StorageNameError(RuntimeError):
    pass


# https://github.com/williballenthin/ida-netnode
class Storage:
    """
    Storage class for storing data in IDA Pro netnodes.
    """

    def __init__(self, name: str):
        self.name = f"{PLUGIN_BASE_NETNODE_ID}:{name}"
        self._n = ida_netnode.netnode(self.name, 0, True)
        log_debug(f"loaded storage {self.name}")

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        return zlib.decompress(data)

    @staticmethod
    def _compress(data: bytes) -> bytes:
        return zlib.compress(data)

    @staticmethod
    def _encode(data) -> bytes:
        return json.dumps(data).encode("ascii")

    @staticmethod
    def _decode(data: bytes) -> dict:
        return json.loads(data.decode("ascii"))

    def _get_next_slot(self, tag: str) -> int:
        slot = self._n.suplast(tag)
        if slot is None or slot == ida_netnode.BADNODE:
            return 0
        else:
            return slot + 1

    def _int_set(self, key: int, value: bytes) -> None:
        assert isinstance(key, int)
        assert value is not None

        try:
            self._int_del(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
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
        assert isinstance(key, str)
        assert value is not None

        try:
            self._str_del(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            store_key = self._get_next_slot(STR_KEYS_TAG)
            self._n.setblob(value, store_key, STR_KEYS_TAG)
            self._n.hashset(key, str(store_key).encode("utf-8"), STR_TO_INT_MAP_TAG)
        else:
            self._n.hashset(key, bytes(value))

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
        if self._n.hashval(key):
            self._n.hashdel(key)
            did_del = True

        if not did_del:
            raise KeyError(f"'{key}' not found")

    def __getitem__(self, key: Union[str, int]) -> dict:
        if isinstance(key, str):
            v = self._str_get(key)
        elif isinstance(key, int):
            v = self._int_get(key)
        else:
            raise TypeError(f"cannot use {type(key)} as k")

        data = self._decompress(v)
        return self._decode(data)

    def __setitem__(self, key: Union[str, int], value) -> None:
        assert value is not None
        v = self._compress(self._encode(value))

        if isinstance(key, str):
            self._str_set(key, v)
        elif isinstance(key, int):
            self._int_set(key, v)
        else:
            raise TypeError(f"cannot use {type(key)} as k")

    def __delitem__(self, key: Union[str, int]) -> None:
        if isinstance(key, str):
            self._str_del(key)
        elif isinstance(key, int):
            self._int_del(key)
        else:
            raise TypeError(f"cannot use {type(key)} as k")

    def get(self, key: Union[str, int], default=None) -> dict:
        try:
            return self[key]
        except (KeyError, zlib.error):
            return default

    def __contains__(self, key: Union[str, int]) -> bool:
        try:
            if self[key] is not None:
                return True
            return False
        except (KeyError, zlib.error):
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

    def iterkeys(self) -> Iterable[Union[str, int]]:
        for k in self._iter_int_keys_small():
            yield k

        for k in self._iter_int_keys_large():
            yield k

        for k in self._iter_str_keys_small():
            yield k

        for k in self._iter_str_keys_large():
            yield k

    def keys(self) -> List[Union[str, int]]:
        return [k for k in list(self.iterkeys())]

    def itervalues(self) -> Iterable[dict]:
        for k in list(self.keys()):
            yield self[k]

    def values(self) -> List[dict]:
        return [v for v in list(self.itervalues())]

    def iteritems(self) -> Iterable[Tuple[Union[str, int], dict]]:
        for k in list(self.keys()):
            yield k, self[k]

    def items(self) -> List[Tuple[Union[str, int], dict]]:
        return [(k, v) for k, v in list(self.iteritems())]

    def kill(self) -> None:
        self._n.kill()
        self._n = ida_netnode.netnode(self.name, 0, True)
