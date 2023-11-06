import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmses import Bmses

all_sr_bmses = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmses")]


@pytest.mark.parametrize("bmses_path", all_sr_bmses)
def test_bmses(samus_returns_tree, bmses_path):
    parse_build_compare_editor(Bmses, samus_returns_tree, bmses_path)
