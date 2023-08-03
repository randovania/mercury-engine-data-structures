import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmsas import Bmsas

all_dread_bmsas = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmsas")]


@pytest.mark.parametrize("bmsas_path", all_dread_bmsas)
def test_bmsas(dread_file_tree, bmsas_path):
    parse_build_compare_editor(Bmsas, dread_file_tree, bmsas_path)
