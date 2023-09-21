import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmtun import Bmtun

all_sr_bmtun = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmtun")]


@pytest.mark.parametrize("bmtun_path", all_sr_bmtun)
def test_bmtun(samus_returns_tree, bmtun_path):
    parse_build_compare_editor(Bmtun, samus_returns_tree, bmtun_path)
