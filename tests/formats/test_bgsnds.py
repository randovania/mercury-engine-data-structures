from __future__ import annotations

from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bgsnds import Bgsnds


def test_bgsnds_100(dread_tree_100):
    parse_build_compare_editor(Bgsnds, dread_tree_100, "system/snd/guisoundevents.bgsnds")


def test_bgsnds_210(dread_tree_210):
    parse_build_compare_editor(Bgsnds, dread_tree_210, "system/snd/guisoundevents.bgsnds")
