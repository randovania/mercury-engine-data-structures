from hashlib import md5

from construct.core import BytesInteger, Int32ul, PrefixedArray, Struct

from mercury_engine_data_structures.file_tree_editor import FileTreeEditor, GameVersion
from mercury_engine_data_structures.formats.property_enum import FileNameEnum
from mercury_engine_data_structures.formats.toc import Toc

MANIFEST_CONSTRUCT = Struct(
    "toc_md5" / BytesInteger(16),
    "file_data" / PrefixedArray(Int32ul, Struct("assetid" / FileNameEnum, "md5" / BytesInteger(16))),
)


def get_md5(data: bytes) -> int:
    return int(md5(data, usedforsecurity=False).hexdigest(), 16)


def get_expected_assetids(editor: FileTreeEditor) -> dict[int, str]:
    manifest = MANIFEST_CONSTRUCT.parse_file(editor.version.manifest, target_game=editor.target_game)

    return {editor.target_game.hash_asset(file.assetid): file.assetid for file in manifest.file_data}


def check_version(editor: FileTreeEditor) -> tuple[bool, GameVersion]:
    toc_hash = get_md5(editor.root.joinpath(Toc.system_files_name()).read_bytes())
    for ver in GameVersion:
        if ver.toc_hash == toc_hash:
            print(f"VERSION {ver}")
            return True, ver

    return False, GameVersion.UNIDENTIFIED


def check_file_structure(editor: FileTreeEditor) -> tuple[bool, GameVersion]:
    valid, ver = check_version(editor)
    if not valid or ver == GameVersion.UNIDENTIFIED:
        return False, ver

    manifest = MANIFEST_CONSTRUCT.parse_file(ver.manifest, target_game=editor.target_game)
    for assetid in manifest.file_data:
        if not editor.does_asset_exists(assetid.assetid):
            return False, ver

    return True, ver


def check_file_integrity(editor: FileTreeEditor) -> tuple[bool, GameVersion]:
    valid, ver = check_version(editor)
    if not valid or ver == GameVersion.UNIDENTIFIED:
        return False, ver

    manifest = MANIFEST_CONSTRUCT.parse_file(ver.manifest, target_game=editor.target_game)
    for assetid in manifest.file_data:
        if (
            not editor.does_asset_exists(assetid.assetid)
            or get_md5(editor.get_raw_asset(assetid.assetid)) != assetid.md5
        ):
            print(assetid)
            return False, ver

    return True, ver
