from mercury_engine_data_structures.formats.bmscu import BMSCU
from test.test_lib import parse_build_compare_editor


def test_compare_dread(dread_file_tree):
    parse_build_compare_editor(
        BMSCU, dread_file_tree, "cutscenes/0037emmycaveappears/0037emmycaveappears.bmscu"
    )
