import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsbk import Bmsbk

sr_missing = [
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmsbk",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmsbk",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmsbk",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmsbk",
]

@pytest.mark.parametrize("bmsbk_path", samus_returns_data.all_files_ending_with(".bmsbk", sr_missing))
def test_bmsbk(samus_returns_tree, bmsbk_path):
    parse_build_compare_editor(Bmsbk, samus_returns_tree, bmsbk_path)
