import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmmap import Bmmap

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander",
]

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bmmap",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bmmap",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bmmap",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bmmap",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bmmap",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bmmap",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bmmap",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bmmap",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bmmap",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bmmap",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bmmap",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bmmap",
]


@pytest.mark.parametrize("bmmap_path", dread_data.all_files_ending_with(".bmmap", bossrush_assets))
def test_dread_bmmap_100(dread_tree_100, bmmap_path):
    parse_build_compare_editor(Bmmap, dread_tree_100, bmmap_path)


@pytest.mark.parametrize("bmmap_path", bossrush_assets)
def test_dread_bmmap_210(dread_tree_210, bmmap_path):
    parse_build_compare_editor(Bmmap, dread_tree_210, bmmap_path)
