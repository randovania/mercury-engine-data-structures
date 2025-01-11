from __future__ import annotations

import pytest
from construct import Container
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.common_types import Vec3
from mercury_engine_data_structures.formats.bmsmsd import Bmsmsd, IconPriority, TileType


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

    new_icon = Container({
        "actor_name": "LE_Test_Icon",
        "clear_condition": "CollectItem",
        "icon": "itemsphere",
        "icon_priority": IconPriority.ACTOR,
        "coordinates": Vec3(100.0, 100.0, 0.0)
    })
    assert tile.get_icon(1) == new_icon
