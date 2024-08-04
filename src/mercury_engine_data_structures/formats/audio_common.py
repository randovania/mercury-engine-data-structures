

import construct
from construct.core import (
    Adapter,
    Array,
    Byte,
    Const,
    Construct,
    Enum,
    FocusedSeq,
    Int16ul,
    Int32ul,
    Pointer,
    Rebuild,
    Struct,
    Tell,
)
from construct.expr import Path
from construct.lib.containers import Container, ListContainer

from mercury_engine_data_structures.common_types import VersionAdapter, make_dict
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo

# An int32 offset (or size) that can be rebuilt later in another struct using RebuildOffset().
# stores the offset without needing extra Tells or private offsets cluttering the struct.
RebuildableOffset = Struct(
    "_offset" / Tell,
    "value" / Int32ul,
)

def RebuildOffset(target_offset: Path, starting_from: int | Path = 0) -> Struct:
    """
    Returns a struct that will rebuild the targeted RebuildableOffset with the current stream's position.

    :param target_offset: a construct path to be rebuilt
    :param starting_from: an optional construct path or lambda to rebuild a relative offset or size a structure
    """
    return Struct(
        "cur_offset" / Tell,
        "updated" / Pointer(target_offset._offset, Rebuild(Int32ul, construct.this.cur_offset - starting_from)),
    )

def Header(magic: bytes, version: int | str | tuple[int, int, int], sections: dict[str, int]) -> Struct:
    """
    Returns an AAL header for the given magic, version number, and sections. Expects to be a little-endian file.

    :param magic: a bytestring containing the fourcc (FSTM, FSAR, etc)
    :param version: a string or tuple representing the version number for a VersionAdapter
    :param sections: a dictionary mapping data block fourcc's (STRG, INFO, FILE, etc) to their section flags
    """
    return Struct(
        "_magic" / Const(magic),
        Const(0xFEFF, Int16ul), # byte-order mark, always LE
        "_header_size_offset" / Tell,
        "_header_size" / Int16ul,
        Const(0, Byte),
        "version" / VersionAdapter(version, (Byte, Byte, Byte)),
        "size" / RebuildableOffset,
        "sections" / make_dict(
            value=Struct(
                "offset" / RebuildableOffset,
                "size" / RebuildableOffset,
            ),
            key = Enum(Int32ul, **sections)
        ),
        AlignTo(0x20),
        "_end_offset" / Tell,
        Pointer(
            construct.this._header_size_offset,
            Rebuild(Int16ul, construct.this._end_offset - construct.this._header_size_offset + 6)
        )
    )

def Block(name: str, subcon: Struct):
    """
    Uses the subcon to parse the data block, and updates the offset and size in the header.

    :param name: the section fourcc (used to find header context)
    :param subcon: the subcon to parse the data block with
    """
    return FocusedSeq(
        "blk",
        "_start" / Tell,
        RebuildOffset(construct.this._root.header.sections[name]["offset"]),
        "blk" / subcon,
        RebuildOffset(construct.this._root.header.sections[name]["size"], construct.this._._start),
    )

class ReferenceTableOfOffsets(Adapter):
    """
    Adapts a ReferenceTable where each table entry has an offset to a ReferencePointer,
    and each of those has an offset to the data_subcon.

    These are always constructed where all ReferencePointers follow the last table entry,
    and all data subcons follow the last ReferencePointer.

    Data decodes to a ListContainer of all data, and generates the table and offsets during encoding.
    """

    def __init__(self, table_flag: int, data_flag: int, data_subcon: Construct):
        self.table_flag = table_flag
        self.data_flag = data_flag
        self.data_subcon = data_subcon

        inner_subcon = Struct(
            "length" / Int32ul,
            "table" / Array(
                construct.this.length,
                Struct(
                    Const(self.table_flag, Int32ul),
                    "offset" / Int32ul,
                )
            ),
            "data_ptrs" / Array(
                construct.this.length,
                Struct(
                    Const(self.data_flag, Int32ul),
                    "offset" / Int32ul,
                )
            ),
            "data" / Array(construct.this.length, data_subcon),
        ).compile()

        super().__init__(inner_subcon)

    def _decode(self, obj, context, path):
        return obj.data

    def _encode(self, obj, context, path):
        count = len(obj)
        table_size = 4 + 8 * count

        return Container(
            length = count,
            # offsets can be calculated since this is constant
            table = ListContainer([
                Container(offset = table_size + 8 * i)
                for i in range(count)
            ]),
            # info offsets can also be calculated
            data_ptrs = ListContainer([
                Container(offset = self.data_subcon.sizeof() * i + 8 * (count - i))
                for i in range(count)
            ]),
            data = obj
        )
