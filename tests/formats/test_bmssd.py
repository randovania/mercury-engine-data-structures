import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmssd import Bmssd

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

@pytest.mark.parametrize("bmssd_path", dread_data.all_files_ending_with(".bmssd"))
def test_compare_dread(dread_file_tree, bmssd_path):
    parse_build_compare_editor(Bmssd, dread_file_tree, bmssd_path)

@pytest.mark.parametrize("bmssd_path", samus_returns_data.all_files_ending_with(".bmssd", sr_missing))
def test_compare_msr(samus_returns_tree, bmssd_path):
    parse_build_compare_editor(Bmssd, samus_returns_tree, bmssd_path)
