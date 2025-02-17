from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmsnav import Bmsnav

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bmsnav",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bmsnav",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bmsnav",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bmsnav",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bmsnav",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bmsnav",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bmsnav",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bmsnav",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bmsnav",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bmsnav",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bmsnav",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bmsnav",
]

sr_missing = [
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmsnav",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmsnav",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmsnav",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmsnav",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmsnav",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmsnav",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmsnav",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmsnav",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmsnav",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmsnav",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmsnav",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmsnav",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmsnav",
]


@pytest.mark.parametrize("bmsnav_path", dread_data.all_files_ending_with(".bmsnav", bossrush_assets))
def test_dread_bmsnav_100(dread_tree_100, bmsnav_path):
    parse_build_compare_editor(Bmsnav, dread_tree_100, bmsnav_path)


@pytest.mark.parametrize("bmsnav_path", bossrush_assets)
def test_dread_bmsnav_210(dread_tree_210, bmsnav_path):
    parse_build_compare_editor(Bmsnav, dread_tree_210, bmsnav_path)


@pytest.mark.parametrize("bmsnav_path", samus_returns_data.all_files_ending_with(".bmsnav", sr_missing))
def test_sr_bmsnav(samus_returns_tree, bmsnav_path):
    parse_build_compare_editor(Bmsnav, samus_returns_tree, bmsnav_path)
