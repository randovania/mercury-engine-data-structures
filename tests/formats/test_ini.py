from __future__ import annotations

from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.ini import Ini


def test_compare_100(dread_tree_100):
    parse_build_compare_editor(Ini, dread_tree_100, "config.ini")


def test_compare_210(dread_tree_210):
    parse_build_compare_editor(Ini, dread_tree_210, "config.ini")
