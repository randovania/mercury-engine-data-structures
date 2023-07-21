import functools
import json
import typing
from pathlib import Path
from typing import Dict, Optional

from mercury_engine_data_structures._dread_data_construct import KnownHashes

_root = Path(__file__).parent


@functools.lru_cache
def get_raw_types() -> Dict[str, typing.Any]:
    path = _root.joinpath("dread_types.json")
    with path.open() as f:
        return json.load(f)


@functools.lru_cache
def all_name_to_asset_id() -> Dict[str, int]:
    bin_path = _root.joinpath("dread_resource_names.bin")
    if bin_path.exists():
        return dict(KnownHashes.parse_file(bin_path))

    path = _root.joinpath("dread_resource_names.json")
    with path.open() as names_file:
        return json.load(names_file)


@functools.lru_cache
def all_asset_id_to_name() -> Dict[int, str]:
    return {
        asset_id: name
        for name, asset_id in all_name_to_asset_id().items()
    }


def name_for_asset_id(asset_id: int) -> Optional[str]:
    return all_asset_id_to_name().get(asset_id)


@functools.lru_cache
def all_name_to_property_id() -> Dict[str, int]:
    bin_path = _root.joinpath("dread_property_names.bin")
    if bin_path.exists():
        return dict(KnownHashes.parse_file(bin_path))

    path = _root.joinpath("dread_property_names.json")
    with path.open() as names_file:
        return json.load(names_file)


@functools.lru_cache
def all_property_id_to_name() -> Dict[int, str]:
    names = all_name_to_property_id()

    return {
        asset_id: name
        for name, asset_id in names.items()
    }
