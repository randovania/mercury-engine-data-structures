import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brem import Brem

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.brem",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.brem",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.brem",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.brem",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.brem",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.brem",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.brem",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.brem",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.brem",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.brem",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.brem",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.brem",
]


@pytest.mark.parametrize("brem_path", dread_data.all_files_ending_with(".brem", bossrush_assets))
def test_dread_brem_100(dread_tree_100, brem_path):
    parse_build_compare_editor(Brem, dread_tree_100, brem_path)


@pytest.mark.parametrize("brem_path", bossrush_assets)
def test_dread_brem_210(dread_tree_210, brem_path):
    parse_build_compare_editor(Brem, dread_tree_210, brem_path)
