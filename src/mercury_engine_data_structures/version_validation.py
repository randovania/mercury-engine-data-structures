from __future__ import annotations

from hashlib import md5
from typing import TYPE_CHECKING

from mercury_engine_data_structures.formats.toc import Toc
from mercury_engine_data_structures.game_check import GameVersion

if TYPE_CHECKING:
    from mercury_engine_data_structures.romfs import RomFs


def _get_md5(data: bytes) -> bytes:
    return md5(data, usedforsecurity=False).digest()


def identify_version(romfs: RomFs) -> GameVersion:
    toc = romfs.get_file(Toc.system_files_name())
    toc_hash = _get_md5(toc)
    for ver in GameVersion:
        if ver.toc_hash == toc_hash:
            return ver

    raise ValueError("Not a valid version!")
