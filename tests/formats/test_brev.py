import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brev import Brev

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.brev",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.brev",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.brev",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.brev",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.brev",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.brev",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.brev",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.brev",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.brev",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.brev",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.brev",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.brev",
]


@pytest.mark.parametrize("brev_path", dread_data.all_files_ending_with(".brev", bossrush_assets))
def test_dread_brev_100(dread_tree_100, brev_path):
    parse_build_compare_editor(Brev, dread_tree_100, brev_path)


@pytest.mark.parametrize("brev_path", bossrush_assets)
def test_dread_brev_210(dread_tree_210, brev_path):
    parse_build_compare_editor(Brev, dread_tree_210, brev_path)
