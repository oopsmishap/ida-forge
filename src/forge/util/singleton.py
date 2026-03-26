import threading
from functools import wraps
from typing import Generic, TypeVar


T = TypeVar("T")


class Singleton(Generic[T]):
    """Simple thread-safe singleton decorator for no-argument classes."""

    def __init__(self, decorated):
        wraps(decorated)(self)
        self._decorated = decorated
        self._instance: T | None = None
        self._lock = threading.Lock()

    def get(self) -> T:
        """Return the singleton instance, creating it on first access."""
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = self._decorated()
        return self._instance

    def __call__(self):
        raise TypeError("Singletons must be accessed through `get()`.")

    def __instancecheck__(self, inst):
        return isinstance(inst, self._decorated)
