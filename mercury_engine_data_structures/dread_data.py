import functools
import json
import typing
from pathlib import Path
from typing import Dict, Optional

from mercury_engine_data_structures.crc import crc64


@functools.lru_cache()
def get_raw_types() -> Dict[str, typing.Any]:
    path = Path(__file__).parent.joinpath("dread_types.json")
    with path.open() as f:
        return json.load(f)


@functools.lru_cache()
def all_name_to_asset_id() -> Dict[str, int]:
    path = Path(__file__).parent.joinpath("resource_names.json")
    with path.open() as names_file:
        return json.load(names_file)


@functools.lru_cache()
def all_asset_id_to_name() -> Dict[int, str]:
    return {
        asset_id: name
        for name, asset_id in all_name_to_asset_id().items()
    }


def name_for_asset_id(asset_id: int) -> Optional[str]:
    return all_asset_id_to_name().get(asset_id)


class CrcDict(dict):
    def __getitem__(self, __k):
        try:
            return super().__getitem__(__k)
        except:
            if isinstance(__k, int):
                return __k
            return crc64(__k)

@functools.lru_cache()
def all_name_to_property_id() -> Dict[str, int]:
    path = Path(__file__).parent.joinpath("property_names.json")
    names = CrcDict()
    with path.open() as names_file:
        names.update(json.load(names_file))
    return names


@functools.lru_cache()
def all_property_id_to_name() -> Dict[int, str]:
    names = all_name_to_property_id()

    return {
        asset_id: name
        for name, asset_id in names.items()
    }
