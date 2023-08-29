import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmmap import Bmmap
from mercury_engine_data_structures.formats.bmmdef import Bmmdef

all_dread_bmmap = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmmap")]


@pytest.mark.parametrize("path", all_dread_bmmap)
def test_dread_bmsnav(dread_file_tree, path):
    parse_build_compare_editor(Bmmap, dread_file_tree, path)


def test_compare_bmmdef_dread(dread_file_tree):
    parse_build_compare_editor(
        Bmmdef, dread_file_tree, "system/minimap/minimap.bmmdef"
    )
