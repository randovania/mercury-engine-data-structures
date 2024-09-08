import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmssd import Bmssd

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bmssd",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bmssd",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bmssd",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bmssd",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bmssd",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bmssd",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bmssd",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bmssd",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bmssd",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bmssd",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bmssd",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bmssd",
]

sr_missing = [
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmssd",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmssd",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmssd",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmssd",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmssd",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmssd",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmssd",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmssd",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmssd",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmssd",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmssd",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmssd",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmssd",
]


@pytest.mark.parametrize("bmssd_path", dread_data.all_files_ending_with(".bmssd", bossrush_assets))
def test_compare_dread_100(dread_tree_100, bmssd_path):
    parse_build_compare_editor(Bmssd, dread_tree_100, bmssd_path)


@pytest.mark.parametrize("bmssd_path", bossrush_assets)
def test_compare_dread_210(dread_tree_210, bmssd_path):
    parse_build_compare_editor(Bmssd, dread_tree_210, bmssd_path)


@pytest.mark.parametrize("bmssd_path", samus_returns_data.all_files_ending_with(".bmssd", sr_missing))
def test_compare_msr(samus_returns_tree, bmssd_path):
    parse_build_compare_editor(Bmssd, samus_returns_tree, bmssd_path)
