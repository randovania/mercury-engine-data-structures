from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bres import Bres

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bres",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bres",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bres",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bres",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bres",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bres",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bres",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bres",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bres",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bres",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bres",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bres",
]


@pytest.mark.parametrize("bres_path", dread_data.all_files_ending_with(".bres", bossrush_assets))
def test_dread_bres_100(dread_tree_100, bres_path):
    parse_build_compare_editor(Bres, dread_tree_100, bres_path)


@pytest.mark.parametrize("bres_path", bossrush_assets)
def test_dread_bres_210(dread_tree_210, bres_path):
    parse_build_compare_editor(Bres, dread_tree_210, bres_path)
