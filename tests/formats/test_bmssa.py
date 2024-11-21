from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor_parsed

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmssa import Bmssa


@pytest.mark.parametrize("bmssa_path", samus_returns_data.all_files_ending_with(".bmssa"))
def test_compare_bmssa_msr(samus_returns_tree, bmssa_path):
    parse_build_compare_editor_parsed(Bmssa, samus_returns_tree, bmssa_path)
