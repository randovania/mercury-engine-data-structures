from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmdefs import Bmdefs


def test_bmdefs_dread(dread_tree_100):
    parse_build_compare_editor(Bmdefs, dread_tree_100, "system/snd/scenariomusicdefs.bmdefs")


def test_bmdefs_sr(samus_returns_tree):
    parse_build_compare_editor(Bmdefs, samus_returns_tree, "system/snd/scenariomusicdefs.bmdefs")
