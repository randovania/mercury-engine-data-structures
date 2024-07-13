import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.blsnd import Blsnd

all_sr_blsnd = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".blsnd")]

all_dread_blsnd = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".blsnd")]

@pytest.mark.parametrize("blsnd_path", all_sr_blsnd)
def test_blsnd(samus_returns_tree, blsnd_path):
    parse_build_compare_editor(Blsnd, samus_returns_tree, blsnd_path)

@pytest.mark.parametrize("blsnd_path", all_dread_blsnd)
def test_blsnd_dread(dread_file_tree, blsnd_path):
    parse_build_compare_editor(Blsnd, dread_file_tree, blsnd_path)
