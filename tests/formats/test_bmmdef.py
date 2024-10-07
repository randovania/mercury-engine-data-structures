from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmmdef import Bmmdef


def test_compare_bmmdef_dread(dread_tree_100):
    parse_build_compare_editor(Bmmdef, dread_tree_100, "system/minimap/minimap.bmmdef")
