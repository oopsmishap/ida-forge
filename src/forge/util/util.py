from enum import IntEnum


class DocIntEnum(IntEnum):
    def __new__(cls, value, doc=None):
        self = int.__new__(cls, value)  # calling super().__new__(value) here would fail
        self._value_ = value
        if doc is not None:
            self.__doc__ = doc
        return self
