import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmdefs import Bmdefs

all_sr_bmdefs = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmdefs")]


@pytest.mark.parametrize("bmdefs_path", all_sr_bmdefs)
def test_bmdefs(samus_returns_tree, bmdefs_path):
    parse_build_compare_editor(Bmdefs, samus_returns_tree, bmdefs_path, print_data=True)
