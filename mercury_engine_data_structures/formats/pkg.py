from typing import Optional

import construct
from construct import (
    Struct, PrefixedArray, Int64ul, Int32ul, Hex, Construct, Computed, Array, Tell,
    Aligned, FocusedSeq, Rebuild, Seek, Pointer, Prefixed, GreedyBytes, Check, Bytes,
)

from mercury_engine_data_structures import crc
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

AssetId = Hex(Int64ul)

FileEntry = Struct(
    asset_id=AssetId,
    start_offset=Int32ul,
    end_offset=Int32ul,
)

PKGHeader = Struct(
    header_size=Int32ul,
    data_section_size=Int32ul,
    file_entries=PrefixedArray(Int32ul, FileEntry),
)


PKG = Struct(
    header=PKGHeader,
    header_end=Tell,
    _skip_end_of_header=Seek(lambda ctx: ctx.header.header_size - ctx.header_end, 1),
    _align=AlignTo(8),
    files_start=Tell,
    files=Array(
        construct.len_(construct.this.header.file_entries),
        Aligned(8, FocusedSeq(
            "item",
            entry=Computed(lambda ctx: ctx._.header.file_entries[ctx._index]),
            start_offset=Tell,
            start_offset_check=Check(lambda ctx: ctx.start_offset == ctx.entry.start_offset),
            item=Struct(
                asset_id=Computed(lambda ctx: ctx._.entry.asset_id),
                data=Bytes(lambda ctx: ctx._.entry.end_offset - ctx._.entry.start_offset),
            ),
            end_offset=Tell,
            end_offset_check=Check(lambda ctx: ctx.end_offset == ctx.entry.end_offset),
        )),
    ),
    files_end=Tell,
)


class Pkg(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return PKG

    def get_resource_by_asset_id(self, asset_id: AssetId) -> Optional[bytes]:
        for entry, file in zip(self.raw.header.file_entries, self.raw.files):
            if entry.asset_id == asset_id:
                return file

    def get_resource_by_name(self, name: str) -> Optional[bytes]:
        return self.get_resource_by_asset_id(crc.crc64(name.encode("utf-8")))
