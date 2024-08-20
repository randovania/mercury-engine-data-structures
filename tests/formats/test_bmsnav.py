import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmsnav import Bmsnav

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


@pytest.mark.parametrize("bmsnav_path", dread_data.all_files_ending_with(".bmsnav"))
def test_dread_bmsnav(dread_file_tree, bmsnav_path):
    parse_build_compare_editor(Bmsnav, dread_file_tree, bmsnav_path)


@pytest.mark.parametrize("bmsnav_path", samus_returns_data.all_files_ending_with(".bmsnav", sr_missing))
def test_sr_bmsnav(samus_returns_tree, bmsnav_path):
    parse_build_compare_editor(Bmsnav, samus_returns_tree, bmsnav_path)
