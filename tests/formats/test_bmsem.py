import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsem import Bmsem

all_sr_bmsmsd = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmsem")]

@pytest.mark.parametrize("bmsmsd_path", all_sr_bmsmsd)
def test_bmsem(samus_returns_tree, bmsmsd_path):
    parse_build_compare_editor(Bmsem, samus_returns_tree, bmsmsd_path, print_data=True)
