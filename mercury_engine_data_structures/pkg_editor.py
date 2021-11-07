import contextlib
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Generator, Iterator

from mercury_engine_data_structures import crc
from mercury_engine_data_structures.formats.base_resource import AssetId
from mercury_engine_data_structures.formats.pkg import PKGHeader
from mercury_engine_data_structures.game_check import Game


class PkgEditor:
    """
    Manages efficiently reading all PKGs in the game and writing out modifications to a new path.
    """

    def __init__(self, files: Dict[str, BinaryIO]):
        self.files = files
        self.headers = {
            name: PKGHeader.parse_stream(file, target_game=Game.DREAD)
            for name, file in files.items()
        }

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

    def find_pkgs_for_asset_id(self, asset_id: AssetId) -> Iterator[str]:
        for name, header in self.headers.items():
            if any(entry.asset_id == asset_id for entry in header.file_entries):
                yield name

    def find_pkgs_for_name(self, name: str) -> Iterator[str]:
        yield from self.find_pkgs_for_asset_id(crc.crc64(name.encode("utf-8")))

    def get_asset_with_asset_id(self, asset_id: AssetId, in_pkg: Optional[str] = None) -> bytes:
        for name, header in self.headers.items():
            if in_pkg is not None and name != in_pkg:
                continue

            for entry in header.file_entries:
                if entry.asset_id == asset_id:
                    self.files[name].seek(entry.start_offset)
                    return self.files[name].read(entry.end_offset - entry.start_offset)
        raise ValueError(f"Unknown asset_id: {asset_id:0x}")

    def get_asset_with_name(self, name: str, in_pkg: Optional[str] = None) -> bytes:
        return self.get_asset_with_asset_id(crc.crc64(name.encode("utf-8")), in_pkg)

    def all_asset_ids(self):
        return {
            entry.asset_id
            for header in self.headers.values()
            for entry in header.file_entries
        }
