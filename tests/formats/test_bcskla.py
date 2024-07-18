import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bcskla import Bcskla

all_dread_bcskla = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bcskla")]

all_sr_bcskla = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                 if name.endswith(".bcskla")]

@pytest.mark.parametrize("bcskla_path", all_dread_bcskla)
def test_bcskla_dread(dread_file_tree, bcskla_path):
    parse_build_compare_editor(Bcskla, dread_file_tree, bcskla_path)

@pytest.mark.parametrize("bcskla_path", all_sr_bcskla)
def test_bcskla_sr(samus_returns_tree, bcskla_path):
    try:
        parse_build_compare_editor(Bcskla, samus_returns_tree, bcskla_path)
    except FileNotFoundError:
        pytest.skip(f"File {bcskla_path} does not exist!")
