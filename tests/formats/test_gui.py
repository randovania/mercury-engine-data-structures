import contextlib

import construct
import pytest
from tests.test_lib import parse_build_compare_editor, parse_build_compare_editor_parsed

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.gui_files import Bmscp, Bmssh, Bmssk, Bmsss

dread_210_exclusive = [
    "gui/scripts/bossrushmain.bmscp",
    "gui/scripts/bossrushmain.bmssk",
    "gui/scripts/bossrushreport.bmscp",
    "gui/scripts/bossrushreport.bmssk",
    "gui/scripts/bossrushresults.bmscp",
    "gui/scripts/configmenubossrush.bmscp",
    "gui/scripts/configmenubossrush.bmssk",
    "gui/scripts/popupgeneric.bmscp",
    "gui/scripts/popupgeneric.bmssk",
    "gui/scripts/sprites_bossrush-bosses.bmsss",
    "gui/scripts/sprites_bossrush-result01.bmsss",
    "gui/scripts/sprites_bossrush-result02.bmsss",
    "gui/scripts/sprites_difmode_dread.bmsss",
    "gui/scripts/sprites_difmode_rookie.bmsss",
]

# these files are *updated* from base, so we run both versions through the test
dread_210_files = [
    *dread_210_exclusive,
    "gui/scripts/deathscreencomposition.bmssk",
    "gui/scripts/difficultycomposition.bmscp",
    "gui/scripts/extrasmenucomposition.bmscp",
    "gui/scripts/iconshudcomposition.bmscp",
    "gui/scripts/mainmenucomposition.bmscp",
    "gui/scripts/mainmenucomposition.bmssk",
    "gui/scripts/slotselectioncomposition.bmscp",
    "gui/scripts/slotselectioncomposition.bmssk",
]

dread_expected_failures = [
    "gui/scripts/bossrushreport.bmscp",
    "gui/scripts/popupgeneric.bmscp",
]


@pytest.mark.parametrize("bmscp_path", dread_data.all_files_ending_with(".bmscp", dread_210_exclusive))
def test_compare_bmscp_dread_100(dread_tree_100, bmscp_path):
    parse_build_compare_editor_parsed(Bmscp, dread_tree_100, bmscp_path)


@pytest.mark.parametrize("bmscp_path", [f for f in dread_210_files if f.endswith(".bmscp")])
def test_compare_bmscp_dread_210(dread_tree_210, bmscp_path):
    if bmscp_path in dread_expected_failures:
        expectation = pytest.raises(construct.ConstructError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor_parsed(Bmscp, dread_tree_210, bmscp_path)


@pytest.mark.parametrize("bmssh_path", dread_data.all_files_ending_with(".bmssh"))
def test_compare_bmssh_dread(dread_tree_100, bmssh_path):
    parse_build_compare_editor(Bmssh, dread_tree_100, bmssh_path)


@pytest.mark.parametrize("bmssk_path", dread_data.all_files_ending_with(".bmssk", dread_210_exclusive))
def test_compare_bmssk_dread_100(dread_tree_100, bmssk_path):
    parse_build_compare_editor(Bmssk, dread_tree_100, bmssk_path)


@pytest.mark.parametrize("bmssk_path", [f for f in dread_210_files if f.endswith(".bmssk")])
def test_compare_bmssk_dread_210(dread_tree_210, bmssk_path):
    parse_build_compare_editor_parsed(Bmssk, dread_tree_210, bmssk_path)


@pytest.mark.parametrize("bmsss_path", dread_data.all_files_ending_with(".bmsss", dread_210_exclusive))
def test_compare_bmsss_dread(dread_tree_100, bmsss_path):
    parse_build_compare_editor(Bmsss, dread_tree_100, bmsss_path)


@pytest.mark.parametrize("bmsss_path", [f for f in dread_210_files if f.endswith(".bmsss")])
def test_compare_bmsss_dread_210(dread_tree_210, bmsss_path):
    parse_build_compare_editor_parsed(Bmsss, dread_tree_210, bmsss_path)
