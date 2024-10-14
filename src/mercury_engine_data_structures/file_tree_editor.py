from __future__ import annotations

import copy
import enum
import json
import logging
import os.path
import typing

from mercury_engine_data_structures import formats, version_validation
from mercury_engine_data_structures.base_resource import AssetId, BaseResource, NameOrAssetId, resolve_asset_id
from mercury_engine_data_structures.formats import Toc
from mercury_engine_data_structures.formats.pkg import Pkg
from mercury_engine_data_structures.game_check import Game, GameVersion
from mercury_engine_data_structures.romfs import RomFs

if typing.TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    import construct

    from mercury_engine_data_structures.romfs import RomFs

_T = typing.TypeVar("_T", bound=BaseResource)
logger = logging.getLogger(__name__)


class OutputFormat(enum.Enum):
    """
    How the modifications are saved to the output dir.

    PKG: as modified pkg files, able to be ran on an unmodified executable.
    ROMFS: just the modified assets directly. Requires a modified executable to prioritize romfs before pkg.
    """

    PKG = enum.auto()
    ROMFS = enum.auto()


def _write_to_path(output: Path, data: bytes):
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)


class FileTreeEditor:
    """
    Manages efficiently reading all PKGs in the game and writing out modifications to a new path.

    _files_for_asset_id: mapping of asset id to all pkgs it can be found at
    _ensured_asset_ids: mapping of pkg name to assets we'll copy into it when saving
    _modified_resources: mapping of asset id to bytes. When saving, these asset ids are replaced
    """

    version: GameVersion
    headers: dict[str, construct.Container]
    _files_for_asset_id: dict[AssetId, set[str | None]]
    _ensured_asset_ids: dict[str, set[AssetId]]
    _modified_resources: dict[AssetId, bytes | None]
    _in_memory_pkgs: dict[str, Pkg]
    _toc: Toc

    def __init__(self, romfs: RomFs, target_game: Game):
        self.romfs = romfs
        self.target_game = target_game
        self._modified_resources = {}
        self._in_memory_pkgs = {}

        self._update_headers()

    def _add_pkg_name_for_asset_id(self, asset_id: AssetId, pkg_name: str | None):
        self._files_for_asset_id[asset_id] = self._files_for_asset_id.get(asset_id, set())
        self._files_for_asset_id[asset_id].add(pkg_name)

    def _update_headers(self):
        self.all_pkgs = []
        self.headers = {}
        self._ensured_asset_ids = {}
        self._files_for_asset_id = {}
        self.version = version_validation.identify_version(self)
        self._name_for_asset_id = copy.copy(self.version.all_asset_id_for_version())

        self._toc = Toc.parse(self.romfs.get_file(Toc.system_files_name()), target_game=self.target_game)

        for name in self.romfs.all_files():
            asset_id = resolve_asset_id(name, self.target_game)
            self._name_for_asset_id[asset_id] = name

            if name.endswith(".pkg"):
                self.all_pkgs.append(name)

            elif self._toc.get_size_for(asset_id) is None:
                # Vanilla has a bunch of files inside `textures/` that are missing from the toc
                if not name.startswith("textures/"):
                    logger.debug("Skipping extracted file %s as it does not have a TOC entry", name)
            else:
                self._add_pkg_name_for_asset_id(asset_id, None)

        for name in self.all_pkgs:
            with self.romfs.get_pkg_stream(name) as f:
                self.headers[name] = Pkg.header_class(self.target_game).parse_stream(f, target_game=self.target_game)

            self._ensured_asset_ids[name] = set()

            self.headers[name].entries_by_id = {}
            for entry in self.headers[name].file_entries:
                if self._toc.get_size_for(entry.asset_id) is None:
                    logger.warning(
                        "File with asset id 0x%016x in pkg %s does not have an entry in the TOC", entry.asset_id, name
                    )
                self._add_pkg_name_for_asset_id(entry.asset_id, name)
                self.headers[name].entries_by_id[entry.asset_id] = entry

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
            yield self._name_for_asset_id[asset_id]

    def find_pkgs(self, asset_id: NameOrAssetId) -> Iterator[str]:
        for pkg_name in self._files_for_asset_id[resolve_asset_id(asset_id, self.target_game)]:
            if pkg_name is not None:
                yield pkg_name

    def does_asset_exists(self, asset_id: NameOrAssetId) -> bool:
        """
        Checks if a given asset id exists.
        """
        asset_id = resolve_asset_id(asset_id, self.target_game)

        if asset_id in self._modified_resources:
            return self._modified_resources[asset_id] is not None

        return asset_id in self._files_for_asset_id

    def get_raw_asset(self, asset_id: NameOrAssetId, *, in_pkg: str | None = None) -> bytes:
        """
        Gets the bytes data for the given asset name/id, optionally restricting from which pkg.
        :raises ValueError if the asset doesn't exist.
        """
        original_name = asset_id
        asset_id = resolve_asset_id(asset_id, self.target_game)

        if asset_id in self._modified_resources:
            result = self._modified_resources[asset_id]
            if result is None:
                raise ValueError(f"Deleted asset_id: {original_name}")
            else:
                return result

        for name, pkg in self._in_memory_pkgs.items():
            result = pkg.get_asset(asset_id)
            if result is not None:
                return result

        for name, header in self.headers.items():
            if in_pkg is not None and name != in_pkg:
                continue

            entry = header.entries_by_id.get(asset_id)
            if entry is not None:
                logger.info("Reading asset %s from pkg %s", str(original_name), name)
                return self.romfs.read_file_with_entry(name, entry)

        if in_pkg is None and asset_id in self._name_for_asset_id:
            name = self._name_for_asset_id[asset_id]
            return self.romfs.get_file(name)

        raise ValueError(f"Unknown asset_id: {original_name}")

    def get_parsed_asset(self, name: str, *, in_pkg: str | None = None, type_hint: type[_T] = BaseResource) -> _T:
        """
        Gets the resource with the given name and decodes it based on the extension.
        """
        data = self.get_raw_asset(name, in_pkg=in_pkg)

        format_class = type_hint
        if isinstance(name, str):
            file_format = os.path.splitext(name)[1][1:]
            type_from_name = formats.format_for(file_format)
            if type_hint is BaseResource:
                format_class = type_from_name
            elif type_hint != type_from_name:
                raise ValueError(f"type_hint was {type_hint}, expected {type_from_name} from name")

        return format_class.parse(data, target_game=self.target_game, editor=self)

    def get_file(self, path: str, type_hint: type[_T] = BaseResource) -> _T:
        """
        Wrapper for `get_parsed_asset`. Override in children for additional functionality.
        """
        return self.get_parsed_asset(path, type_hint=type_hint)

    def add_new_asset(self, name: str, new_data: bytes | BaseResource, in_pkgs: typing.Iterable[str]):
        """
        Adds an asset that doesn't already exist.
        """
        asset_id = resolve_asset_id(name, self.target_game)
        if self.does_asset_exists(asset_id):
            if asset_id in self._modified_resources:
                raise ValueError(f"{name} was already modified")
            else:
                raise ValueError(
                    "Asset already exists in:\n"
                    + "\n".join(
                        pkg if pkg is not None else "In the RomFS" for pkg in self._files_for_asset_id[asset_id]
                    )
                )

        in_pkgs = list(in_pkgs)
        files_set = set()
        if not in_pkgs:
            files_set.add(None)

        self._name_for_asset_id[asset_id] = name
        self._files_for_asset_id[asset_id] = files_set
        self.replace_asset(name, new_data)
        for pkg_name in in_pkgs:
            self.ensure_present(pkg_name, asset_id)

    def replace_asset(self, asset_id: NameOrAssetId, new_data: bytes | BaseResource):
        """
        Replaces an existing asset.
        See `add_new_asset` for new assets.
        """

        # Test if the asset exists
        if not self.does_asset_exists(asset_id):
            raise ValueError(f"Unknown asset: {asset_id}")

        if not isinstance(new_data, bytes):
            logger.debug("Encoding %s", str(asset_id))
            new_data = new_data.build()

        self._modified_resources[resolve_asset_id(asset_id, self.target_game)] = new_data

    def delete_asset(self, asset_id: NameOrAssetId):
        # Test if the asset exists
        if not self.does_asset_exists(asset_id):
            raise ValueError(f"Unknown asset: {asset_id}")

        asset_id = resolve_asset_id(asset_id, self.target_game)

        if None in self._files_for_asset_id[asset_id]:
            raise ValueError("Not allowed to remove unpacked files")

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
        asset_id = resolve_asset_id(asset_id, self.target_game)
        if pkg_name not in self._files_for_asset_id[asset_id]:
            self._ensured_asset_ids[pkg_name].add(asset_id)

    def get_pkg(self, pkg_name: str) -> Pkg:
        if pkg_name not in self._ensured_asset_ids:
            raise ValueError(f"Unknown pkg_name: {pkg_name}")

        if pkg_name not in self._in_memory_pkgs:
            logger.info("Reading %s", pkg_name)
            with self.romfs.get_pkg_stream(pkg_name) as f:
                self._in_memory_pkgs[pkg_name] = Pkg.parse_stream(f, target_game=self.target_game)

        return self._in_memory_pkgs[pkg_name]

    def save_modifications(self, output_path: Path, output_format: OutputFormat, *, finalize_editor: bool = True):
        """Creates a mod file in the given output format with all the modifications requested.
        :param output_path: Where to write the mod files.
        :param output_format: If we should create PKG files or not.
        :param finalize_editor: If set, this editor will no longer be usable after this function, but is faster.
        """
        replacements = []
        modified_pkgs = set()
        asset_ids_to_copy = {}

        for asset_id in self._modified_resources.keys():
            modified_pkgs.update(self._files_for_asset_id[asset_id])

        # Ensure pkgs are written which only have new ensured assets without
        # completly new assets
        for key, asset_ids in self._ensured_asset_ids.items():
            if len(asset_ids) != 0:
                modified_pkgs.add(key)

        if None in modified_pkgs:
            modified_pkgs.remove(None)

        if output_format == OutputFormat.ROMFS:
            # Clear modified_pkgs, so we don't read/write any new pkg
            # We keep system.pkg because .bmmaps don't read properly with exlaunch and it's only 4MB
            # We keep MSR's "_discardables.pkg" as the files are not read from RomFS without the pkg
            modified_pkgs = list(
                filter(lambda pkg: pkg == "packs/system/system.pkg" or pkg.endswith("discardables.pkg"), modified_pkgs)
            )

        # Ensure all pkgs we'll modify is in memory already.
        # We'll need to read these files anyway to modify, so do it early to speedup
        # the get_raw_assets for _ensured_asset_ids.
        for pkg_name in modified_pkgs:
            self.get_pkg(pkg_name)

        # Read all asset ids we need to copy somewhere else
        for asset_ids in self._ensured_asset_ids.values():
            for asset_id in asset_ids:
                if asset_id not in asset_ids_to_copy:
                    asset_ids_to_copy[asset_id] = self.get_raw_asset(asset_id)

        # Update the toc for the modified (and new) files
        logger.debug("Writing modified files")
        for asset_id, data in self._modified_resources.items():
            if data is not None:
                self._toc.add_file(asset_id, len(data))
                if None in self._files_for_asset_id[asset_id] or output_format == OutputFormat.ROMFS:
                    path = self._name_for_asset_id[asset_id]
                    if path.endswith(".bmmap"):
                        if None in self._files_for_asset_id[asset_id]:
                            logger.warning("Requested that %s be written to romfs", path)
                        continue
                    logger.info("Writing to %s with %d bytes", path, len(data))
                    _write_to_path(output_path.joinpath(path), data)
                    if self._files_for_asset_id[asset_id] - {None}:
                        replacements.append(path)
                        if (
                            output_format == OutputFormat.ROMFS
                            and asset_id in asset_ids_to_copy
                            and self.target_game != Game.SAMUS_RETURNS
                        ):
                            del asset_ids_to_copy[asset_id]
            else:
                self._toc.remove_file(asset_id)

        # Update the Toc's own entry and then write
        logger.debug("Updating the system/files.toc")
        self._toc.add_file(Toc.system_files_name(), len(self._toc.build()))
        _write_to_path(output_path.joinpath(Toc.system_files_name()), self._toc.build())

        if output_format == OutputFormat.ROMFS:
            logger.debug("Copying to romfs the ensured files")
            for asset_id, data in asset_ids_to_copy.items():
                path = output_path.joinpath(self._name_for_asset_id[asset_id])
                logger.info("Writing to %s with %d bytes", path, len(data))
                _write_to_path(output_path.joinpath(path), data)

            # dread_depackager format
            replacement_json = json.dumps({"replacements": replacements}, indent=4)
            output_path.joinpath("replacements.json").write_text(replacement_json, "utf-8")

        # Update the PKGs
        for pkg_name in modified_pkgs:
            logger.info("Updating %s", pkg_name)
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
            out_pkg_path = output_path.joinpath(pkg_name)
            logger.info("Writing %s", out_pkg_path)
            out_pkg_path.parent.mkdir(parents=True, exist_ok=True)
            with out_pkg_path.open("wb") as f:
                pkg.build_stream(f)

        self._modified_resources = {}
        if finalize_editor:
            # _update_headers has significant runtime costs, so avoid it.
            # But lets delete these attributes so further use of this object fails explicitly
            del self.all_pkgs
            del self.headers
            del self._ensured_asset_ids
            del self._files_for_asset_id
            del self._name_for_asset_id
            del self._toc
        else:
            self._update_headers()
