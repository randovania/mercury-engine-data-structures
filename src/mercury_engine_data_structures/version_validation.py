from __future__ import annotations

from hashlib import md5
from typing import TYPE_CHECKING

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.toc import Toc
from mercury_engine_data_structures.game_check import Game, GameVersion

if TYPE_CHECKING:
    from mercury_engine_data_structures.file_tree_editor import FileTreeEditor


def _get_md5(data: bytes) -> bytes:
    return md5(data, usedforsecurity=False).digest()


def all_asset_id_for_version(ver: GameVersion):
    if ver.game == Game.DREAD:
        return dread_data.all_asset_id_to_name(ver)
    elif ver.game == Game.SAMUS_RETURNS:
        return samus_returns_data.all_asset_id_to_name(ver)
    else:
        raise ValueError(f"Unsupported game {ver.game}")


def identify_version(editor: FileTreeEditor) -> GameVersion:
    romfs = editor.romfs
    print(romfs)
    toc = romfs.get_file(Toc.system_files_name())
    toc_hash = _get_md5(toc)
    for ver in GameVersion:
        if ver.toc_hash == toc_hash:
            return ver

    raise ValueError("Not a valid version!")


def verify_file_structure(editor: FileTreeEditor) -> GameVersion:
    ver = identify_version(editor)
    for assetid in all_asset_id_for_version(editor.version):
        if not editor.does_asset_exists(assetid):
            raise ValueError(f"Missing asset {assetid}")

    # TODO verify no extra files exist
    # for file in editor.root.rglob("*.*"):
    #     path = file.relative_to(editor.root).as_posix()
    #     if not editor.does_asset_exists(path):
    #         raise ValueError(f"Extra asset {path}")

    return ver


def verify_file_integrity(editor: FileTreeEditor) -> GameVersion:
    ver = identify_version(editor)
    all_hashes = b""
    for assetid in all_asset_id_for_version(editor.version):
        if not editor.does_asset_exists(assetid):
            raise ValueError(f"Missing asset {assetid}")
        all_hashes += _get_md5(editor.get_raw_asset(assetid))

    if _get_md5(all_hashes) == ver.all_files_hash:
        return ver
    else:
        raise ValueError(f"Invalid hash {_get_md5(all_hashes).hex()}!")
