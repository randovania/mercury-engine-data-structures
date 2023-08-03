from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmscu import Bmscu


def test_compare_dread(dread_file_tree):
    parse_build_compare_editor(
        Bmscu.construct_class(dread_file_tree.target_game), dread_file_tree,
        "cutscenes/0037emmycaveappears/0037emmycaveappears.bmscu"
    )
