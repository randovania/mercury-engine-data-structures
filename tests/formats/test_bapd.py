import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bapd import Bapd

exclusive_210 = [
    "system/snd/presets/gui/timealarm_01.bapd",
    "system/snd/presets/hud/hud_maxfill2.bapd",
]


@pytest.mark.parametrize("bapd_path", dread_data.all_files_ending_with(".bapd", exclusive_210))
def test_bapd_100(dread_tree_100, bapd_path):
    parse_build_compare_editor(Bapd, dread_tree_100, bapd_path)


@pytest.mark.parametrize("bapd_path", exclusive_210)
def test_bapd_210(dread_tree_210, bapd_path):
    parse_build_compare_editor(Bapd, dread_tree_210, bapd_path)
