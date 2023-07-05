import pytest
from mercury_engine_data_structures.formats.bmsnav import BMSNAV
from test.test_lib import parse_build_compare_editor

all_bmsnav = [
    "maps/levels/c10_samus/s010_cave/s010_cave.bmsnav",
    "maps/levels/c10_samus/s020_magma/s020_magma.bmsnav",
    "maps/levels/c10_samus/s030_baselab/s030_baselab.bmsnav",
    "maps/levels/c10_samus/s040_aqua/s040_aqua.bmsnav",
    "maps/levels/c10_samus/s050_forest/s050_forest.bmsnav",
    "maps/levels/c10_samus/s060_quarantine/s060_quarantine.bmsnav",
    "maps/levels/c10_samus/s070_basesanc/s070_basesanc.bmsnav",
    "maps/levels/c10_samus/s080_shipyard/s080_shipyard.bmsnav",
    "maps/levels/c10_samus/s090_skybase/s090_skybase.bmsnav",
]


@pytest.mark.parametrize("bmsnav_path", all_bmsnav)
def test_bmsnav(dread_file_tree, bmsnav_path):
    parse_build_compare_editor(BMSNAV, dread_file_tree, bmsnav_path)