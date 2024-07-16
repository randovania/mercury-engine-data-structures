import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bcskla import Bcskla


all_dread_bcskla = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bcskla")]

@pytest.mark.parametrize("bcskla_path", all_dread_bcskla)
def test_bcskla(dread_file_tree, bcskla_path):
    parse_build_compare_editor(Bcskla, dread_file_tree, bcskla_path)
