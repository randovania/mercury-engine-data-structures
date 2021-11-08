import collections
import contextlib
import os.path
import typing
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Generator, Iterator, Set

from mercury_engine_data_structures import crc, formats, dread_data
from mercury_engine_data_structures.formats.base_resource import AssetId, BaseResource, NameOrAssetId, resolve_asset_id
from mercury_engine_data_structures.formats.pkg import PKGHeader, Pkg
from mercury_engine_data_structures.game_check import Game


class PkgEditor:
    """
    Manages efficiently reading all PKGs in the game and writing out modifications to a new path.
    """
    _files_for_asset_id: Dict[AssetId, Set[str]]
    _modified_resources: Dict[AssetId, bytes]

    def __init__(self, files: Dict[str, BinaryIO], target_game: Game = Game.DREAD):
        self.files = files
        self.target_game = target_game
        self.headers = {
            name: PKGHeader.parse_stream(file, target_game=target_game)
            for name, file in files.items()
        }
        self._files_for_asset_id = collections.defaultdict(set)
        for name, header in self.headers.items():
            for entry in header.file_entries:
                self._files_for_asset_id[entry.asset_id].add(name)
        self._modified_resources = {}

    @classmethod
    @contextlib.contextmanager
    def open_pkgs_at(cls, root: Path) -> Generator["PkgEditor", None, None]:
        all_pkgs = root.rglob("*.pkg")

        with ExitStack() as stack:
            files = {
                file.relative_to(root).as_posix(): stack.enter_context(file.open("rb"))
                for file in all_pkgs
            }
            yield PkgEditor(files)

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
                    self.files[name].seek(entry.start_offset)
                    return self.files[name].read(entry.end_offset - entry.start_offset)

        raise ValueError(f"Unknown asset_id: {asset_id:0x}")

    def get_parsed_asset(self, name: str, in_pkg: Optional[str] = None) -> BaseResource:
        asset_id = crc.crc64(name)
        data = self.get_raw_asset(asset_id, in_pkg)
        file_format = os.path.splitext(name)[1][1:]
        return formats.format_for(file_format).parse(data, target_game=self.target_game)

    def replace_asset(self, asset_id: NameOrAssetId, new_data: typing.Union[bytes, BaseResource]):
        if not isinstance(new_data, bytes):
            new_data = new_data.build()
        self._modified_resources[resolve_asset_id(asset_id)] = new_data

    def save_modified_pkgs(self, out: Path):
        modified_pkgs = set()
        for asset_id in self._modified_resources.keys():
            modified_pkgs.update(self._files_for_asset_id[asset_id])

        for pkg_name in modified_pkgs:
            self.files[pkg_name].seek(0)
            pkg = Pkg.parse_stream(self.files[pkg_name], target_game=self.target_game)

            for asset_id, data in self._modified_resources.items():
                if pkg_name in self._files_for_asset_id[asset_id]:
                    pkg.replace_asset(asset_id, data)

            pkg_out = out.joinpath(pkg_name)
            pkg_out.parent.mkdir(parents=True, exist_ok=True)
            with pkg_out.open("wb") as f:
                pkg.build_stream(f)
