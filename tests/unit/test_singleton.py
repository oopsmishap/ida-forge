"""Behavior tests for forge.util.singleton."""

from __future__ import annotations

import pytest

from forge.util.singleton import Singleton


class _Counter:
    instances = 0

    def __init__(self):
        _Counter.instances += 1
        self.value = 42


@Singleton
class _Service:
    pass


def test_singleton_get_returns_same_instance():
    first = _Service.get()
    second = _Service.get()
    assert first is second


def test_singleton_creates_instance_once():
    _Counter.instances = 0

    @Singleton
    class Counter:
        def __init__(self):
            _Counter.instances += 1

    Counter.get()
    Counter.get()
    assert _Counter.instances == 1


def test_singleton_call_raises():
    with pytest.raises(TypeError):
        _Service()


def test_singleton_instancecheck():
    service = _Service.get()
    assert isinstance(service, _Service)
    assert isinstance(service, _Service._decorated)