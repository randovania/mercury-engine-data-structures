from __future__ import annotations

import functools
import json
import typing
from pathlib import Path

from mercury_engine_data_structures._dread_data_construct import KnownHashes, VersionedHashes
from mercury_engine_data_structures.game_check import Game, GameVersion

_root = Path(__file__).parent
MSR_VERSIONS = GameVersion.versions_for_game(Game.SAMUS_RETURNS)
ALL_VERSIONS_BITMASK = sum([v.bitmask for v in MSR_VERSIONS.values()])


@functools.lru_cache
def get_raw_types() -> dict[str, typing.Any]:
    path = Path(__file__).parent.joinpath("samus_returns_types.json")
    with path.open() as f:
        return json.load(f)


@functools.lru_cache
def all_name_to_asset_id_and_version() -> dict[str, dict[str, int]]:
    bin_path = _root.joinpath("sr_resource_names.bin")
    if bin_path.exists():
        return dict(VersionedHashes.parse_file(bin_path))

    path = Path(__file__).parent.joinpath("sr_resource_names.json")
    with path.open() as names_file:
        data: dict[str, dict] = json.load(names_file)

    for a in data.values():
        vers = a.get("versions")
        if vers is not None:
            a["versions"] = sum([MSR_VERSIONS[v].bitmask for v in vers])
        else:
            a["versions"] = ALL_VERSIONS_BITMASK

    return data


@functools.lru_cache
def all_name_to_asset_id(ver: GameVersion | None = None) -> dict[str, int]:
    bitmask = ver.bitmask if ver else ALL_VERSIONS_BITMASK
    return {k: v["crc"] for k, v in all_name_to_asset_id_and_version().items() if v["versions"] & bitmask != 0}


@functools.lru_cache
def all_asset_id_to_name(ver: GameVersion | None = None) -> dict[int, str]:
    return {asset_id: name for name, asset_id in all_name_to_asset_id(ver).items()}


def name_for_asset_id(asset_id: int, ver: GameVersion | None = None) -> str | None:
    return all_asset_id_to_name(ver).get(asset_id)


@functools.lru_cache
def all_name_to_property_id() -> dict[str, int]:
    bin_path = _root.joinpath("sr_property_names.bin")
    if bin_path.exists():
        return dict(KnownHashes.parse_file(bin_path))

    path = Path(__file__).parent.joinpath("sr_property_names.json")
    with path.open() as names_file:
        return json.load(names_file)


@functools.lru_cache
def all_property_id_to_name() -> dict[int, str]:
    names = all_name_to_property_id()

    return {asset_id: name for name, asset_id in names.items()}


def all_files_ending_with(ext: str, exclusions: list[str] | None = None) -> list[str]:
    if not ext.startswith("."):
        ext = "." + ext

    if exclusions is None:
        exclusions = []

    return [name for name in all_name_to_asset_id().keys() if name.endswith(ext) and name not in exclusions]
