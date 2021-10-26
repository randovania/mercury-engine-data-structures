import contextlib
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Generator

from mercury_engine_data_structures import crc
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

    def find_asset_id(self, asset_id: int) -> Optional[str]:
        for name, header in self.headers.items():
            if any(entry.asset_id == asset_id for entry in header.file_entries):
                return name

    def find_name(self, name: str) -> Optional[str]:
        return self.find_asset_id(crc.crc64(name.encode("utf-8")))
