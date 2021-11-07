import functools
import json
from pathlib import Path
from typing import Dict, Optional


@functools.lru_cache()
def get_raw_types() -> Dict[str, str]:
    path = Path(__file__).parent.joinpath("dread_types.json")
    with path.open() as f:
        return json.load(f)


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
