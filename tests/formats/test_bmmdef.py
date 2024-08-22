from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmmdef import Bmmdef


def test_compare_bmmdef_dread(dread_file_tree):
    parse_build_compare_editor(Bmmdef, dread_file_tree, "system/minimap/minimap.bmmdef")
