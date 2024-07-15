import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bapd import Bapd

all_dread_bapd = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bapd")]


@pytest.mark.parametrize("bapd_path", all_dread_bapd)
def test_bmtre(dread_file_tree, bapd_path):
    parse_build_compare_editor(Bapd, dread_file_tree, bapd_path)
