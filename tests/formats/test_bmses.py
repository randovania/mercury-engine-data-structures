from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmses import Bmses


@pytest.mark.parametrize("bmses_path", samus_returns_data.all_files_ending_with(".bmses"))
def test_bmses(samus_returns_tree, bmses_path):
    parse_build_compare_editor(Bmses, samus_returns_tree, bmses_path)
