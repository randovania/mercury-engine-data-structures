from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmsmd import Bmsmd


def test_bmsmd(samus_returns_tree):
    parse_build_compare_editor(
        Bmsmd, samus_returns_tree, r"gui/minimaps/c10_samus.bmsmd"
    )
