from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsmsd import Bmsmsd, TileType


@pytest.mark.parametrize("bmsmsd_path", samus_returns_data.all_files_ending_with(".bmsmsd"))
def test_bmsmsd(samus_returns_tree, bmsmsd_path):
    parse_build_compare_editor(Bmsmsd, samus_returns_tree, bmsmsd_path)


@pytest.fixture()
def surface_bmsmsd(samus_returns_tree) -> Bmsmsd:
    return samus_returns_tree.get_parsed_asset("gui/minimaps/c10_samus/s000_surface.bmsmsd", type_hint=Bmsmsd)


def test_get_tile(surface_bmsmsd: Bmsmsd):
    tile = surface_bmsmsd.get_tile(4)
    assert tile.tile_coordinates == [48, 5]

    tile = surface_bmsmsd.get_tile(12)
    assert len(tile.icons) == 2

    tile = surface_bmsmsd.get_tile(25)
    assert tile.tile_type == TileType.NORMAL
