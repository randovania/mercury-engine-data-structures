from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brsa import Brsa

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.brsa",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.brsa",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.brsa",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.brsa",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.brsa",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.brsa",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.brsa",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.brsa",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.brsa",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.brsa",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.brsa",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.brsa",
]


@pytest.mark.parametrize("brsa_path", dread_data.all_files_ending_with(".brsa", bossrush_assets))
def test_dread_brsa_100(dread_tree_100, brsa_path):
    parse_build_compare_editor(Brsa, dread_tree_100, brsa_path)


@pytest.mark.parametrize("brsa_path", bossrush_assets)
def test_dread_brsa_210(dread_tree_210, brsa_path):
    parse_build_compare_editor(Brsa, dread_tree_210, brsa_path)
