from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmsstoc import Bmsstoc

BMSSTOC_PATH = "system/snd/sm_sounddefinitions_packed.bmsstoc"


def test_bmsstoc_100(dread_tree_100):
    parse_build_compare_editor(Bmsstoc, dread_tree_100, BMSSTOC_PATH)


def test_bmsstoc_210(dread_tree_210):
    parse_build_compare_editor(Bmsstoc, dread_tree_210, BMSSTOC_PATH)
