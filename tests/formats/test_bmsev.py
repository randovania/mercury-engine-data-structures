from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsev import Bmsev

sr_missing = [
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmsev",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmsev",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmsev",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmsev",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmsev",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmsev",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmsev",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmsev",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmsev",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmsev",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmsev",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmsev",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmsev",
]


@pytest.mark.parametrize("bmsev_path", samus_returns_data.all_files_ending_with(".bmsev", sr_missing))
def test_bmsev(samus_returns_tree, bmsev_path):
    parse_build_compare_editor(Bmsev, samus_returns_tree, bmsev_path)
