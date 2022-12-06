from __future__ import annotations

import dataclasses
import typing
from typing import Optional

import construct
from construct import (
    Struct, PrefixedArray, Int64ul, Int32ul, Hex, Construct, IfThenElse, )

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.base_resource import BaseResource, NameOrAssetId, resolve_asset_id, AssetId
from mercury_engine_data_structures.game_check import Game, get_current_game

Construct_AssetId = Hex(IfThenElse(construct.this._params.target_game == Game.SAMUS_RETURNS.value, Int32ul, Int64ul))


def offset_for(con: Struct, name: str):
    result = 0
    for sc in con.subcons:
        sc = typing.cast(Construct, sc)
        if sc.name == name:
            return result
        result += sc.sizeof()
    raise construct.ConstructError(f"Unknown field: {name}")


def header_field(field_name: str):
    offset = offset_for(FileEntry, field_name)

    def result(ctx):
        parents = [ctx]
        while "_" in parents[-1]:
            parents.append(parents[-1]["_"])

        start_headers = None
        index = None

        for c in reversed(parents):
            if "_start_headers" in c:
                start_headers = c["_start_headers"]
                break

        for c in parents:
            if "_resource_index" in c:
                index = c["_resource_index"]
                break

        if index is None or start_headers is None:
            raise ValueError("Missing required context key")

        return start_headers + (index * FileEntry.sizeof()) + offset

    return result


FileEntry = Struct(
    asset_id=Construct_AssetId,
    start_offset=Int32ul,
    end_offset=Int32ul,
)

PKGHeader = Struct(
    header_size=Int32ul,
    data_section_size=Int32ul,
    file_entries=PrefixedArray(Int32ul, FileEntry),
).compile()


class PkgConstruct(construct.Construct):
    int_size: construct.FormatField
    file_headers_type: construct.Construct

    def __init__(self):
        super().__init__()
        self.int_size = typing.cast(construct.FormatField, Int32ul)
        self.file_headers_type = PrefixedArray(self.int_size, FileEntry).compile()

    def _parse(self, stream, context, path) -> construct.Container:
        # Skip over header size and data section size
        construct.stream_seek(stream, 2 * self.int_size.length, 1, path)

        # Get the file headers
        file_headers = self.file_headers_type._parsereport(stream, context, path)

        if get_current_game(context) == Game.DREAD:
            # Align to 128 bytes
            AlignTo(128)._parsereport(stream, context, path)

        files = construct.ListContainer()
        for i, header in enumerate(file_headers):
            file_path = f"{path} -> file {i}"
            construct.stream_seek(stream, header.start_offset, 0, file_path)
            files.append(construct.Container(
                asset_id=header.asset_id,
                data=construct.stream_read(stream, header.end_offset - header.start_offset, file_path)
            ))

        return construct.Container(files=files)

    def _build(self, obj: construct.Container, stream, context, path):
        file_entry_size = FileEntry.sizeof(target_game=get_current_game(context))

        header_start = construct.stream_tell(stream, path)

        # Skip over header size and data section size for now
        construct.stream_seek(stream, 2 * self.int_size.length, 1, path)

        # Skip over file headers
        construct.stream_seek(stream, len(obj.files) * file_entry_size, 1, path)

        if get_current_game(context) == Game.DREAD:
            # Align to 128 bytes
            AlignTo(128)._build(None, stream, context, path)

        header_end = construct.stream_tell(stream, path)

        file_headers = []
        for i, file in enumerate(obj.files):
            field_path = f"{path}.field_{i}"
            start_offset = construct.stream_tell(stream, path)
            construct.stream_write(stream, file.data, len(file.data), field_path)
            end_offset = construct.stream_tell(stream, path)
            file_headers.append(construct.Container(
                asset_id=file.asset_id,
                start_offset=start_offset,
                end_offset=end_offset,
            ))
            # Align to 8 bytes
            pad = -(end_offset - start_offset) % 8
            construct.stream_write(stream, b"\x00" * pad, pad, path)

        files_end = construct.stream_tell(stream, path)

        # Update Headers
        construct.stream_seek(stream, header_start, 0, path)

        # Header Size
        self.int_size._build(header_end - header_start - 4, stream, context, path)
        # Data Section Size
        self.int_size._build(files_end - header_end, stream, context, path)
        # File Entries
        self.file_headers_type._build(file_headers, stream, context, path)

        # Return to the end
        construct.stream_seek(stream, files_end, 0, path)


PKG = PkgConstruct()


@dataclasses.dataclass(frozen=True)
class PkgFile:
    game: Game
    asset_id: AssetId
    data: bytes

    @property
    def asset_name(self) -> Optional[str]:
        if self.game == Game.DREAD:
            return dread_data.name_for_asset_id(self.asset_id)
        elif self.game == Game.SAMUS_RETURNS:
            return samus_returns_data.name_for_asset_id(self.asset_id)
        else:
            return None


class Pkg(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return PKG

    @classmethod
    def parse_stream(cls, stream: typing.BinaryIO, target_game: Game) -> Pkg:
        return cls(cls.construct_class(target_game).parse_stream(stream, target_game=target_game),
                   target_game)

    def build_stream(self, stream: typing.BinaryIO) -> bytes:
        return self.construct_class(self.target_game).build_stream(self._raw, stream, target_game=self.target_game)

    @property
    def all_assets(self) -> typing.Iterator[PkgFile]:
        for file in self.raw.files:
            yield PkgFile(self.target_game, file.asset_id, file.data)

    def get_asset(self, asset_id: NameOrAssetId) -> Optional[bytes]:
        asset_id = resolve_asset_id(asset_id, self.target_game)
        for file in self.raw.files:
            if file.asset_id == asset_id:
                return file.data
        return None

    def replace_asset(self, asset_id: NameOrAssetId, new_file: bytes):
        asset_id = resolve_asset_id(asset_id, self.target_game)

        for file in self.raw.files:
            if file.asset_id == asset_id:
                file.data = new_file
                return

        raise ValueError(f"Unknown asset id: {asset_id}")

    def add_asset(self, asset_id: NameOrAssetId, new_file: bytes):
        asset_id = resolve_asset_id(asset_id, self.target_game)

        if self.get_asset(asset_id) is not None:
            raise ValueError(f"Asset id already exists: {asset_id}")

        self.raw.files.append(construct.Container(
            asset_id=asset_id,
            data=new_file,
        ))

    def remove_asset(self, asset_id: NameOrAssetId):
        asset_id = resolve_asset_id(asset_id, self.target_game)

        for file in self.raw.files:
            if file.asset_id == asset_id:
                self.raw.files.remove(file)
                return

        raise ValueError(f"Unknown asset id: {asset_id}")
