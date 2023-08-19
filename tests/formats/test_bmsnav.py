import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmsnav import Bmsnav

dread_bmsnav = [
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

sr_bmsnav = [
    "maps/levels/c10_samus/s000_surface/s000_surface.bmsnav",
    "maps/levels/c10_samus/s010_area1/s010_area1.bmsnav",
    "maps/levels/c10_samus/s020_area2/s020_area2.bmsnav",
    "maps/levels/c10_samus/s025_area2b/s025_area2b.bmsnav",
    "maps/levels/c10_samus/s028_area2c/s028_area2c.bmsnav",
    "maps/levels/c10_samus/s030_area3/s030_area3.bmsnav",
    "maps/levels/c10_samus/s033_area3b/s033_area3b.bmsnav",
    "maps/levels/c10_samus/s036_area3c/s036_area3c.bmsnav",
    "maps/levels/c10_samus/s040_area4/s040_area4.bmsnav",
    "maps/levels/c10_samus/s050_area5/s050_area5.bmsnav",
    "maps/levels/c10_samus/s060_area6/s060_area6.bmsnav",
    "maps/levels/c10_samus/s065_area6b/s065_area6b.bmsnav",
    "maps/levels/c10_samus/s067_area6c/s067_area6c.bmsnav",
    "maps/levels/c10_samus/s070_area7/s070_area7.bmsnav",
    "maps/levels/c10_samus/s090_area9/s090_area9.bmsnav",
    "maps/levels/c10_samus/s100_area10/s100_area10.bmsnav",
    "maps/levels/c10_samus/s110_surfaceb/s110_surfaceb.bmsnav",
]


@pytest.mark.parametrize("bmsnav_path", dread_bmsnav)
def test_dread_bmsnav(dread_file_tree, bmsnav_path):
    parse_build_compare_editor(Bmsnav, dread_file_tree, bmsnav_path)

@pytest.mark.parametrize("bmsnav_path", sr_bmsnav)
def test_sr_bmsnav(samus_returns_tree, bmsnav_path):
    parse_build_compare_editor(Bmsnav, samus_returns_tree, bmsnav_path)
