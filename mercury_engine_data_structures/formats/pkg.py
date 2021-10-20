from construct import Struct, Int64ub, Int32ub, PrefixedArray, Int64ul, Int32ul, Hex

AssetId = Hex(Int64ul)

FileEntry = Struct(
    asset_id=AssetId,
    start_offset=Int32ul,
    end_offset=Int32ul,
)

PKGHeader = Struct(
    header_size=Int32ul,
    data_section_size=Int32ul,
    file_entries=PrefixedArray(Int32ul, FileEntry)
)


PKG = Struct(
    header=PKGHeader,
)
