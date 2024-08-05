from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmsstoc import Bmsstoc


def test_bmsstoc(dread_file_tree):
    parse_build_compare_editor(Bmsstoc, dread_file_tree, "system/snd/sm_sounddefinitions_packed.bmsstoc")
