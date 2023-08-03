import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.brfld import Brfld

all_brfld = [
    "maps/levels/c10_samus/s010_cave/s010_cave.brfld",
    "maps/levels/c10_samus/s020_magma/s020_magma.brfld",
    "maps/levels/c10_samus/s030_baselab/s030_baselab.brfld",
    "maps/levels/c10_samus/s040_aqua/s040_aqua.brfld",
    "maps/levels/c10_samus/s050_forest/s050_forest.brfld",
    "maps/levels/c10_samus/s060_quarantine/s060_quarantine.brfld",
    "maps/levels/c10_samus/s070_basesanc/s070_basesanc.brfld",
    "maps/levels/c10_samus/s080_shipyard/s080_shipyard.brfld",
    "maps/levels/c10_samus/s090_skybase/s090_skybase.brfld",

]


@pytest.mark.parametrize("brfld_path", all_brfld)
def test_brfld(dread_file_tree, brfld_path):
    parse_build_compare_editor(Brfld, dread_file_tree, brfld_path)
