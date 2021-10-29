import functools
import json
from pathlib import Path
from typing import Dict, Optional

import construct
from construct import Hex, Int64ul
from construct.lib import HexDisplayedInteger


@functools.lru_cache()
def all_asset_id_to_name() -> Dict[int, str]:
    path = Path(__file__).parent.joinpath("resource_names.json")
    with path.open() as names_file:
        names: Dict[str, int] = json.load(names_file)

    return {
        asset_id: name
        for name, asset_id in names.items()
    }


def name_for_asset_id(asset_id: int) -> Optional[str]:
    return all_asset_id_to_name().get(asset_id)


@functools.lru_cache()
def all_name_to_property_id() -> Dict[str, int]:
    path = Path(__file__).parent.joinpath("property_names.json")
    with path.open() as names_file:
        return json.load(names_file)


@functools.lru_cache()
def all_property_id_to_name() -> Dict[int, str]:
    names = all_name_to_property_id()

    return {
        asset_id: name
        for name, asset_id in names.items()
    }


PropertyEnum = construct.Enum(Hex(Int64ul), **{
    name: HexDisplayedInteger.new(property_id, "0%sX" % (2 * 8))
    for property_id, name in all_property_id_to_name().items()
})
