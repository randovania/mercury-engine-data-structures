from __future__ import annotations

import copy

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.common_types import Vec2, Vec3
from mercury_engine_data_structures.formats.bmsmsd import Bmsmsd, IconPriority, TileBorders, TileType


@pytest.mark.parametrize("bmsmsd_path", samus_returns_data.all_files_ending_with(".bmsmsd"))
def test_bmsmsd(samus_returns_tree, bmsmsd_path):
    parse_build_compare_editor(Bmsmsd, samus_returns_tree, bmsmsd_path)


@pytest.fixture()
def surface_bmsmsd(samus_returns_tree) -> Bmsmsd:
    return samus_returns_tree.get_parsed_asset("gui/minimaps/c10_samus/s000_surface.bmsmsd", type_hint=Bmsmsd)


def test_get_tile(surface_bmsmsd: Bmsmsd):
    tile = surface_bmsmsd.get_tile(4)
    assert tile.tile_coordinates == [48, 5]

    tile = surface_bmsmsd.get_tile(0)
    assert tile.tile_dimensions == {"bottom_left": Vec2(6400.0, -10600.0), "top_right": Vec2(7000.0, -9800.0)}

    tile = surface_bmsmsd.get_tile(8)
    assert tile.tile_borders == {
        TileBorders.TOP: True,
        TileBorders.BOTTOM: True,
        TileBorders.LEFT: False,
        TileBorders.RIGHT: True,
        TileBorders.OPEN_TOP: False,
        TileBorders.OPEN_BOTTOM: False,
        TileBorders.OPEN_LEFT: False,
        TileBorders.OPEN_RIGHT: False,
    }

    tile = surface_bmsmsd.get_tile(25)
    assert tile.tile_type == TileType.NORMAL

    tile = surface_bmsmsd.get_tile(12)
    assert len(tile.icons) == 2


def test_set_tile_properties(surface_bmsmsd: Bmsmsd):
    tile = surface_bmsmsd.get_tile(0)
    original_tile = copy.deepcopy(tile)

    tile.tile_coordinates = [30, 20]
    tile.tile_dimensions = {"bottom_left": Vec2(10000.0, -1000.0), "top_right": Vec2(50000.0, -29000.0)}
    tile.update_tile_borders(TileBorders.OPEN_TOP, True)
    tile.tile_type = TileType.ACID_FALL

    assert original_tile != tile


def test_get_icon(surface_bmsmsd: Bmsmsd):
    icon = surface_bmsmsd.get_tile(4).get_icon()
    assert icon.actor_name == "LE_Item_001"
    assert icon.clear_condition == ""
    assert icon.icon == "item_missiletank"
    assert icon.icon_priority == IconPriority.ACTOR
    assert icon.coordinates == Vec3(-5500.0, -9700.0, 0.0)


def test_add_icon(surface_bmsmsd: Bmsmsd):
    tile = surface_bmsmsd.get_tile(10)
    assert tile is not None

    tile.add_icon("LE_Test_Icon", "CollectItem", "itemsphere", IconPriority.ACTOR, Vec3(100.0, 100.0, 0.0))

    new_icon = {
        "actor_name": "LE_Test_Icon",
        "clear_condition": "CollectItem",
        "icon": "itemsphere",
        "icon_priority": IconPriority.ACTOR,
        "coordinates": Vec3(100.0, 100.0, 0.0),
    }
    assert tile.get_icon(1) == new_icon
