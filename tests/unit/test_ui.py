from __future__ import annotations

from forge.api.ui import Choose, set_row_background_color, set_row_foreground_color


class FakeItem:
    def __init__(self):
        self.background = None
        self.foreground = None

    def setBackground(self, color):
        self.background = color

    def setForeground(self, color):
        self.foreground = color


class FakeTable:
    def __init__(self, items):
        self._items = items

    def columnCount(self):
        return len(self._items[0])

    def item(self, row, column):
        return self._items[row][column]



def test_choose_wrapper_exposes_items():
    chooser = Choose([["a"], ["b"]])

    assert chooser.OnGetSize() == 2
    assert chooser.OnGetLine(1) == ["b"]



def test_row_color_helpers_only_update_existing_items():
    items = [[FakeItem(), None, FakeItem()]]
    table = FakeTable(items)

    set_row_background_color(table, 0, "red")
    set_row_foreground_color(table, 0, "blue")

    assert items[0][0].background == "red"
    assert items[0][0].foreground == "blue"
    assert items[0][2].background == "red"
    assert items[0][2].foreground == "blue"
