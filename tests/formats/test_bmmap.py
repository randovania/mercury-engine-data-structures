import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmmap import Bmmap

dread_bmmap = [
    "maps/levels/c10_samus/s010_cave/s010_cave.bmmap",
    "maps/levels/c10_samus/s020_magma/s020_magma.bmmap",
    "maps/levels/c10_samus/s030_baselab/s030_baselab.bmmap",
    "maps/levels/c10_samus/s040_aqua/s040_aqua.bmmap",
    "maps/levels/c10_samus/s050_forest/s050_forest.bmmap",
    "maps/levels/c10_samus/s060_quarantine/s060_quarantine.bmmap",
    "maps/levels/c10_samus/s070_basesanc/s070_basesanc.bmmap",
    "maps/levels/c10_samus/s080_shipyard/s080_shipyard.bmmap",
    "maps/levels/c10_samus/s090_skybase/s090_skybase.bmmap",
]


@pytest.mark.parametrize("bmmap_path", dread_bmmap)
def test_dread_bmmap(dread_file_tree, bmmap_path):
    parse_build_compare_editor(Bmmap, dread_file_tree, bmmap_path)

