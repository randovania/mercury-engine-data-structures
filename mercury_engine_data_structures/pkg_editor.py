import os.path
import os.path
import typing
from pathlib import Path
from typing import Dict, Optional, Iterator, Set

import construct

from mercury_engine_data_structures import formats, dread_data
from mercury_engine_data_structures.formats.base_resource import AssetId, BaseResource, NameOrAssetId, resolve_asset_id
from mercury_engine_data_structures.formats.pkg import PKGHeader, Pkg
from mercury_engine_data_structures.game_check import Game


def _find_entry_for_asset_id(asset_id: AssetId, pkg_header):
    for entry in pkg_header.file_entries:
        if entry.asset_id == asset_id:
            return entry


def _read_file_with_entry(path: Path, entry):
    with path.open("rb") as f:
        f.seek(entry.start_offset)
        return f.read(entry.end_offset - entry.start_offset)


class PkgEditor:
    """
    Manages efficiently reading all PKGs in the game and writing out modifications to a new path.

    _files_for_asset_id: mapping of asset id to all pkgs it can be found at
    _ensured_asset_ids: mapping of pkg name to assets we'll copy into it when saving
    _modified_resources: mapping of asset id to bytes. When saving, these asset ids are replaced
    """
    files: Dict[str, Path]
    headers: Dict[str, construct.Container]
    _files_for_asset_id: Dict[AssetId, Set[str]]
    _ensured_asset_ids: Dict[str, Set[AssetId]]
    _modified_resources: Dict[AssetId, Optional[bytes]]
    _in_memory_pkgs: Dict[str, Pkg]

    def __init__(self, root: Path, target_game: Game = Game.DREAD):
        all_pkgs = root.rglob("*.pkg")

        self.root = root
        self.target_game = target_game
        self._modified_resources = {}
        self._in_memory_pkgs = {}

        self.files = {
            pkg_path.relative_to(root).as_posix(): pkg_path
            for pkg_path in all_pkgs
        }
        self._update_headers()

    def _update_headers(self):
        self.headers = {}
        self._ensured_asset_ids = {}
        self._files_for_asset_id = {}

        for name, pkg_path in self.files.items():
            with pkg_path.open("rb") as f:
                self.headers[name] = PKGHeader.parse_stream(f, target_game=self.target_game)

            self._ensured_asset_ids[name] = set()
            for entry in self.headers[name].file_entries:
                self._files_for_asset_id[entry.asset_id] = self._files_for_asset_id.get(entry.asset_id, set())
                self._files_for_asset_id[entry.asset_id].add(name)

    def all_asset_ids(self) -> Iterator[AssetId]:
        """
        Returns an iterator of all asset ids in the available pkgs.
        """
        yield from self._files_for_asset_id.keys()

    def all_asset_names(self) -> Iterator[str]:
        """
        Returns an iterator of all known names of the present asset ids.
        """
        for asset_id in self.all_asset_ids():
            name = dread_data.name_for_asset_id(asset_id)
            if name is not None:
                yield name

    def find_pkgs(self, asset_id: NameOrAssetId) -> Iterator[str]:
        yield from self._files_for_asset_id[resolve_asset_id(asset_id)]

    def does_asset_exists(self, asset_id: NameOrAssetId) -> bool:
        """
        Checks if a given asset id exists.
        """
        asset_id = resolve_asset_id(asset_id)

        if asset_id in self._modified_resources:
            return self._modified_resources[asset_id] is not None

        return asset_id in self._files_for_asset_id

    def get_raw_asset(self, asset_id: NameOrAssetId, *, in_pkg: Optional[str] = None) -> bytes:
        """
        Gets the bytes data for the given asset name/id, optionally restricting from which pkg.
        :raises ValueError if the asset doesn't exist.
        """
        asset_id = resolve_asset_id(asset_id)

        if asset_id in self._modified_resources:
            result = self._modified_resources[asset_id]
            if result is None:
                raise ValueError(f"Unknown asset_id: {asset_id:0x}")
            else:
                return result

        for name, pkg in self._in_memory_pkgs.items():
            result = pkg.get_resource(asset_id)
            if result is not None:
                return result

        for name, header in self.headers.items():
            if in_pkg is not None and name != in_pkg:
                continue

            entry = _find_entry_for_asset_id(asset_id, header)
            if entry is not None:
                return _read_file_with_entry(self.files[name], entry)

        raise ValueError(f"Unknown asset_id: {asset_id:0x}")

    def get_parsed_asset(self, name: str, *, in_pkg: Optional[str] = None) -> BaseResource:
        """
        Gets the resource with the given name and decodes it based on the extension.
        """
        data = self.get_raw_asset(name, in_pkg=in_pkg)
        file_format = os.path.splitext(name)[1][1:]
        return formats.format_for(file_format).parse(data, target_game=self.target_game)

    def replace_asset(self, asset_id: NameOrAssetId, new_data: typing.Union[bytes, BaseResource]):
        if not isinstance(new_data, bytes):
            new_data = new_data.build()
        self._modified_resources[resolve_asset_id(asset_id)] = new_data

    def delete_asset(self, asset_id: NameOrAssetId):
        # Test if the asset exists
        if not self.does_asset_exists(asset_id):
            raise ValueError(f"Unknown asset: {asset_id}")

        asset_id = resolve_asset_id(asset_id)
        self._modified_resources[asset_id] = None

        # If this asset id was previously ensured, remove that
        for ensured_ids in self._ensured_asset_ids.values():
            if asset_id in ensured_ids:
                ensured_ids.remove(asset_id)

    def ensure_present(self, pkg_name: str, asset_id: NameOrAssetId):
        """
        Ensures the given pkg has the given assets, collecting from other pkgs if needed.
        """
        if pkg_name not in self._ensured_asset_ids:
            raise ValueError(f"Unknown pkg_name: {pkg_name}")

        # Test if the asset exists
        if not self.does_asset_exists(asset_id):
            raise ValueError(f"Unknown asset: {asset_id}")

        # If the pkg already has the given asset, do nothing
        asset_id = resolve_asset_id(asset_id)
        if pkg_name not in self._files_for_asset_id[asset_id]:
            self._ensured_asset_ids[pkg_name].add(asset_id)

    def save_modified_pkgs(self):
        modified_pkgs = set()
        for asset_id in self._modified_resources.keys():
            modified_pkgs.update(self._files_for_asset_id[asset_id])

        for pkg_name in modified_pkgs:
            with self.files[pkg_name].open("rb") as f:
                self._in_memory_pkgs[pkg_name] = Pkg.parse_stream(f, target_game=self.target_game)

        # Read all asset ids we need to copy somewhere else
        asset_ids_to_copy = {}
        for asset_ids in self._ensured_asset_ids.values():
            for asset_id in asset_ids:
                if asset_id not in asset_ids_to_copy:
                    asset_ids_to_copy[asset_id] = self.get_raw_asset(asset_id)

        for pkg_name in modified_pkgs:
            pkg = self._in_memory_pkgs.pop(pkg_name)

            for asset_id, data in self._modified_resources.items():
                if pkg_name in self._files_for_asset_id[asset_id]:
                    if data is None:
                        pkg.remove_asset(asset_id)
                    else:
                        pkg.replace_asset(asset_id, data)

            # Add the files that were ensured to be present in this pkg
            for asset_id in self._ensured_asset_ids[pkg_name]:
                pkg.add_asset(asset_id, asset_ids_to_copy[asset_id])

            # Write the data
            with self.files[pkg_name].open("wb") as f:
                pkg.build_stream(f)

        self._modified_resources = {}
        self._update_headers()
