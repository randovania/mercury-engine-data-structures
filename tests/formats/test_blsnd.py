import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.blsnd import Blsnd

all_sr_blsnd = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".blsnd")]


@pytest.mark.parametrize("blsnd_path", all_sr_blsnd)
def test_blsnd(samus_returns_tree, blsnd_path):
    parse_build_compare_editor(Blsnd, samus_returns_tree, blsnd_path)
