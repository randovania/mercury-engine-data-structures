import dataclasses
import typing
from typing import Optional

import construct
from construct import (
    Struct, PrefixedArray, Int64ul, Int32ul, Hex, Construct, Computed, Array, Tell,
    Aligned, FocusedSeq, Rebuild, Seek, Pointer, Prefixed, GreedyBytes,
)

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.construct_extensions.misc import Skip
from mercury_engine_data_structures.formats.base_resource import BaseResource, NameOrAssetId, resolve_asset_id, AssetId
from mercury_engine_data_structures.game_check import Game

Construct_AssetId = Hex(Int64ul)


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
)

PKG = Struct(
    _header_size=Skip(1, Int32ul),

    _data_section_size_address=Tell,
    _data_section_size=Skip(1, Int32ul),

    _num_files=Rebuild(Int32ul, construct.len_(construct.this.files)),
    _start_headers=Tell,
    _skip_headers=Seek(lambda ctx: ctx._num_files * FileEntry.sizeof(), 1),

    _align=AlignTo(128),
    _files_start=Tell,
    _update_header_size=Pointer(
        0x0,
        Rebuild(Int32ul, lambda ctx: ctx._files_start - Int32ul.sizeof()),
    ),
    files=Array(
        construct.this._num_files,
        Aligned(8, FocusedSeq(
            "item",
            _resource_index=Computed(lambda ctx: ctx["_index"]),

            actual_start_offset=Tell,
            start_offset=Pointer(header_field("start_offset"),
                                 Rebuild(Int32ul, lambda ctx: ctx.actual_start_offset)),
            end_offset=Pointer(header_field("end_offset"),
                               Rebuild(Int32ul, lambda ctx: ctx.start_offset + len(ctx.item.data))),
            item_size=Computed(lambda ctx: ctx.end_offset - ctx.start_offset),

            item=Struct(
                asset_id=Pointer(header_field("asset_id"), Construct_AssetId),
                asset_name=Computed(lambda ctx: dread_data.name_for_asset_id(ctx.asset_id)),
                data=Prefixed(
                    Rebuild(
                        Computed(lambda ctx: ctx._.item_size),
                        construct.len_(construct.this.data),
                    ),
                    GreedyBytes,
                ),
            ),
        )),
    ),
    _files_end=Tell,
    _update_data_section_size=Pointer(
        lambda ctx: ctx._data_section_size_address,
        Rebuild(Int32ul, lambda ctx: ctx._files_end - ctx._files_start),
    ),
)


@dataclasses.dataclass(frozen=True)
class PkgFile:
    asset_id: AssetId
    data: bytes

    @property
    def asset_name(self) -> Optional[str]:
        return dread_data.name_for_asset_id(self.asset_id)


class Pkg(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return PKG

    @classmethod
    def parse_stream(cls, stream: typing.BinaryIO, target_game: Game) -> "Pkg":
        return cls(cls.construct_class(target_game).parse_stream(stream, target_game=target_game),
                   target_game)

    def build_stream(self, stream: typing.BinaryIO) -> bytes:
        return self.construct_class(self.target_game).build_stream(self._raw, stream, target_game=self.target_game)

    @property
    def all_assets(self) -> typing.Iterator[PkgFile]:
        for file in self.raw.files:
            yield PkgFile(file.asset_id, file.data)

    def get_asset(self, asset_id: NameOrAssetId) -> Optional[bytes]:
        asset_id = resolve_asset_id(asset_id)
        for file in self.raw.files:
            if file.asset_id == asset_id:
                return file.data

    def replace_asset(self, asset_id: NameOrAssetId, new_file: bytes):
        asset_id = resolve_asset_id(asset_id)

        for file in self.raw.files:
            if file.asset_id == asset_id:
                file.data = new_file
                return

        raise ValueError(f"Unknown asset id: {asset_id}")

    def add_asset(self, asset_id: NameOrAssetId, new_file: bytes):
        asset_id = resolve_asset_id(asset_id)

        if self.get_asset(asset_id) is not None:
            raise ValueError(f"Asset id already exists: {asset_id}")

        self.raw.files.append(construct.Container(
            asset_id=asset_id,
            data=new_file,
        ))

    def remove_asset(self, asset_id: NameOrAssetId):
        asset_id = resolve_asset_id(asset_id)

        for file in self.raw.files:
            if file.asset_id == asset_id:
                self.raw.files.remove(file)
                return

        raise ValueError(f"Unknown asset id: {asset_id}")
