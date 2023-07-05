import construct

from mercury_engine_data_structures.common_types import UInt, StrId

BlockType = construct.Enum(
    UInt,
    texture=2,
    data=3,
)

XTX_TextureBlock = construct.Struct(
    data_size=construct.Int64ul,
    alignment=UInt,
    width=UInt,
    height=UInt,
    depth=UInt,
    target=UInt,
    xtx_format=UInt,
    mip_count=UInt,
    slice_size=UInt,
    mip_offsets=UInt[17],
    texture_layout_1=UInt,
    texture_layout_2=UInt,
    boolean=UInt,
    _terminated=construct.Terminated,
)

XTX_Block = construct.Struct(
    _start=construct.Tell,
    _magic=construct.Const(b"HBvN"),
    block_size=UInt,
    data_size=construct.Int64ul,
    data_offset=construct.Int64sl,
    block_type=BlockType,
    global_block_index=UInt,
    inc_block_type_index=UInt,

    _data_seek=construct.Seek(construct.this._start + construct.this.data_offset),
    data=construct.FixedSized(
        construct.this.data_size,
        construct.Switch(
            construct.this.block_type,
            {
                BlockType.texture: XTX_TextureBlock,
            },
            construct.GreedyBytes,
        )
    )
)

XTX = construct.Struct(
    _magic=construct.Const(b"DFvN"),
    header_size=UInt,
    major_version=UInt,
    minor_version=UInt,
    _header_end=construct.Seek(construct.this.header_size),
    blocks=construct.GreedyRange(XTX_Block),
)

BCTEX = construct.Struct(
    _magic=construct.Const(b"MTXT"),
    flags=UInt,
    data=construct.Compressed(
        construct.Struct(
            unk_1=construct.Int64ul,
            width=UInt,
            height=UInt,
            mip_count=UInt,
            texture_flag=UInt,  # unk
            name_offset=UInt,
            name=construct.Peek(construct.FocusedSeq(
                "value",
                construct.Seek(construct.this._.name_offset - 8),
                value=StrId,
            )),
            unk_2=UInt,
            texture_offset=UInt,  # texture xtx offset
            unk_3=UInt,
            texture_size=UInt,  # texture xtx size

            _xtx_bytes_seek=construct.Seek(construct.this.texture_offset - 8),
            xtx=construct.FixedSized(construct.this.texture_size, XTX),
            rest=construct.GreedyBytes,
        ),
        "gzip",
        level=9,
    ),
)
