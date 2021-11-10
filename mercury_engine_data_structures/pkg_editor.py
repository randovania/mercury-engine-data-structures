import collections
import contextlib
import os.path
import typing
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Generator, Iterator, Set

from mercury_engine_data_structures import formats, dread_data
from mercury_engine_data_structures.formats.base_resource import AssetId, BaseResource, NameOrAssetId, resolve_asset_id
from mercury_engine_data_structures.formats.pkg import PKGHeader, Pkg
from mercury_engine_data_structures.game_check import Game


class PkgEditor:
    """
    Manages efficiently reading all PKGs in the game and writing out modifications to a new path.

    _files_for_asset_id: mapping of asset id to all pkgs it can be found at
    _ensured_asset_ids: mapping of pkg name to assets we'll copy into it when saving
    _modified_resources: mapping of asset id to bytes. When saving, these asset ids are replaced
    """
    _files_for_asset_id: Dict[AssetId, Set[str]]
    _ensured_asset_ids: Dict[str, Set[AssetId]]
    _modified_resources: Dict[AssetId, bytes]

    def __init__(self, root: Path, target_game: Game = Game.DREAD):
        all_pkgs = root.rglob("*.pkg")

        self.files = {}
        self.root = root
        self.target_game = target_game
        self.headers = {}
        self._files_for_asset_id = collections.defaultdict(set)
        self._ensured_asset_ids = {}
        self._modified_resources = {}

        for pkg_path in all_pkgs:
            name = pkg_path.relative_to(root).as_posix()
            self.files[name] = pkg_path
            with pkg_path.open("rb") as f:
                self.headers[name] = PKGHeader.parse_stream(f, target_game=target_game)

            self._ensured_asset_ids[name] = set()
            for entry in self.headers[name].file_entries:
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

    def get_raw_asset(self, asset_id: NameOrAssetId, in_pkg: Optional[str] = None) -> bytes:
        asset_id = resolve_asset_id(asset_id)

        if asset_id in self._modified_resources:
            return self._modified_resources[asset_id]

        for name, header in self.headers.items():
            if in_pkg is not None and name != in_pkg:
                continue

            for entry in header.file_entries:
                if entry.asset_id == asset_id:
                    with self.files[name].open("rb") as f:
                        f.seek(entry.start_offset)
                        return f.read(entry.end_offset - entry.start_offset)

        raise ValueError(f"Unknown asset_id: {asset_id:0x}")

    def get_parsed_asset(self, name: str, in_pkg: Optional[str] = None) -> BaseResource:
        data = self.get_raw_asset(name, in_pkg)
        file_format = os.path.splitext(name)[1][1:]
        return formats.format_for(file_format).parse(data, target_game=self.target_game)

    def replace_asset(self, asset_id: NameOrAssetId, new_data: typing.Union[bytes, BaseResource]):
        if not isinstance(new_data, bytes):
            new_data = new_data.build()
        self._modified_resources[resolve_asset_id(asset_id)] = new_data

    def ensure_present(self, pkg_name: str, asset_id: NameOrAssetId):
        """
        Ensures the given pkg has the give assets, collecting from other pkgs if needed.
        """
        if pkg_name not in self._ensured_asset_ids:
            raise ValueError(f"Unknown pkg_name: {pkg_name}")
        asset_id = resolve_asset_id(asset_id)

        # If the pkg already has the given asset, do nothing
        if pkg_name not in self._files_for_asset_id[asset_id]:
            self._ensured_asset_ids[pkg_name].add(asset_id)

    def save_modified_pkgs(self):
        modified_pkgs = set()
        for asset_id in self._modified_resources.keys():
            modified_pkgs.update(self._files_for_asset_id[asset_id])

        # Read all asset ids we need to copy somewhere else
        asset_ids_to_copy = {}
        for asset_ids in self._ensured_asset_ids.values():
            for asset_id in asset_ids:
                if asset_id not in asset_ids_to_copy:
                    asset_ids_to_copy[asset_id] = self.get_raw_asset(asset_id)

        for pkg_name in modified_pkgs:
            with self.files[pkg_name].open("rb") as f:
                pkg = Pkg.parse_stream(f, target_game=self.target_game)

            for asset_id, data in self._modified_resources.items():
                if pkg_name in self._files_for_asset_id[asset_id]:
                    pkg.replace_asset(asset_id, data)

            for asset_id in self._ensured_asset_ids[pkg_name]:
                pkg.add_asset(asset_id, asset_ids_to_copy[asset_id])
                self._files_for_asset_id[asset_id].add(pkg_name)

            with self.files[pkg_name].open("wb") as f:
                pkg.build_stream(f)

            # Clear the ensured asset ids, since we've written these
            self._ensured_asset_ids[pkg_name] = set()

        self._modified_resources = {}
