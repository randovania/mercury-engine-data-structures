import pytest
from tests.test_lib import parse_build_compare_editor_parsed

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmscc import Bmscc

sr_missing_cc = [
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmscc",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmscc",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmscc",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmscc",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmscc",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmscc",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmscc",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmscc",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmscc",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmscc",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmscc",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmscc",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmscc",
]

sr_missing_cd = [
    "actors/props/doorcreatureleft/collisions/doorcreatureleft.bmscd",
    "actors/props/grapplemovable4x1/collisions/grapplemovable4x1.bmscd",
    "actors/props/ridleyclouds/collisions/ridleyclouds.bmscd",
    "actors/props/spenergybestowalstatue/collisions/spenergybestowalstatue.bmscd",
    "actors/props/unlockarea/collisions/unlockarea.bmscd",
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmscd",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmscd",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmscd",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmscd",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmscd",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmscd",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmscd",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmscd",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmscd",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmscd",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmscd",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmscd",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmscd",
]


@pytest.mark.parametrize(
    "file_path", dread_data.all_files_ending_with(".bmscc") + dread_data.all_files_ending_with(".bmscd")
)
def test_compare_dread(dread_file_tree, file_path):
    parse_build_compare_editor_parsed(Bmscc, dread_file_tree, file_path)


@pytest.mark.parametrize(
    "file_path",
    samus_returns_data.all_files_ending_with(".bmscc", sr_missing_cc)
    + samus_returns_data.all_files_ending_with(".bmscd", sr_missing_cd),
)
def test_compare_msr(samus_returns_tree, file_path):
    parse_build_compare_editor_parsed(Bmscc, samus_returns_tree, file_path)
