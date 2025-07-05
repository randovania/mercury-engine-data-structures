from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

from construct.core import (
    Bytes,
    Const,
    FlagsEnum,
    GreedyBytes,
    If,
    Int32ul,
    Struct,
    this,
)
from construct.lib.containers import Container

from mercury_engine_data_structures.formats.bctex import XTX_Tegra_Format

if TYPE_CHECKING:
    from pathlib import Path

    from mercury_engine_data_structures.exporters.raw_texture import Array, RawTexture


class DDPF_FLAGS(IntEnum):
    DDPF_ALPHAPIXELS = 0x1
    DDPF_ALPHA = 0x2
    DDPF_FOURCC = 0x4
    DDPF_RGB = 0x40
    DDPF_YUV = 0x200
    DDPF_LUMINANCE = 0x20000


DDS_PIXELFORMAT = Struct(
    "dwSize" / Const(32, Int32ul),
    "dwFlags" / FlagsEnum(Int32ul, DDPF_FLAGS),
    "dwFourCC" / Bytes(4),
    "dwRGBBitCount" / Int32ul,
    "dwRBitMask" / Int32ul,
    "dwGBitMask" / Int32ul,
    "dwBBitMask" / Int32ul,
    "dwABitMask" / Int32ul,
)


class DDS_FLAGS(IntEnum):
    DDSD_CAPS = 0x1
    DDSD_HEIGHT = 0x2
    DDSD_WIDTH = 0x4
    DDSD_PITCH = 0x8
    DDSD_PIXELFORMAT = 0x1000
    DDSD_MIPMAPCOUNT = 0x20000
    DDSD_LINEARSIZE = 0x80000
    DDSD_DEPTH = 0x800000


class CAPS_FLAGS(IntEnum):
    DDSCAPS_COMPLEX = 0x8
    DDSCAPS_TEXTURE = 0x1000
    DDSCAPS_MIPMAP = 0x400000


class CAPS2_FLAGS(IntEnum):
    DDSCAPS2_CUBEMAP = 0x200
    DDSCAPS2_CUBEMAP_POSITIVEX = 0x400
    DDSCAPS2_CUBEMAP_NEGATIVEX = 0x800
    DDSCAPS2_CUBEMAP_POSITIVEY = 0x1000
    DDSCAPS2_CUBEMAP_NEGATIVEY = 0x2000
    DDSCAPS2_CUBEMAP_POSITIVEZ = 0x4000
    DDSCAPS2_CUBEMAP_NEGATIVEZ = 0x8000
    DDSCAPS2_VOLUME = 0x200000


DDS_HEADER = Struct(
    "dwSize" / Const(124, Int32ul),
    "dwFlags" / FlagsEnum(Int32ul, DDS_FLAGS),
    "dwHeight" / Int32ul,
    "dwWidth" / Int32ul,
    "dwPitchOrLinearSize" / Int32ul,
    "dwDepth" / Int32ul,
    "dwMipMapCount" / Int32ul,
    "dwReserved1" / Int32ul[11],
    "ddspf" / DDS_PIXELFORMAT,
    "dwCaps" / FlagsEnum(Int32ul, CAPS_FLAGS),
    "dwCaps2" / FlagsEnum(Int32ul, CAPS2_FLAGS),
    "dwCaps3" / Int32ul,
    "dwCaps4" / Int32ul,
    "dwReserved2" / Int32ul,
)


class D3D10_RESOURCEs_DIMENSION(IntEnum):
    D3D10_RESOURCE_DIMENSION_UNKNOWN = 0
    D3D10_RESOURCE_DIMENSION_BUFFER = 1
    D3D10_RESOURCE_DIMENSION_TEXTURE1D = 2
    D3D10_RESOURCE_DIMENSION_TEXTURE2D = 3
    D3D10_RESOURCE_DIMENSION_TEXTURE3D = 4


DDS_HEADER_DX10 = Struct(
    "dxgiFormat" / Const(95, Int32ul),  # only cubemaps are exported as DX10
    "resourceDimension" / Const(3, Int32ul),
    "miscFlag" / Const(4, Int32ul),  # 0x4 = cubemap
    "arraySize" / Int32ul,
    "miscFlags2" / Const(0, Int32ul),
)

DDS = Struct(
    "_magic" / Const(b"DDS "),
    "header" / DDS_HEADER,
    "header10" / If(this.header.dwFlags.DDPF_FOURCC and this.header.ddspf.dwFourCC == b"DX10", DDS_HEADER_DX10),
    "data" / GreedyBytes,
)

_EMPTY_FOURCC = b"\x00" * 4
DXGI_FORMATS: dict[XTX_Tegra_Format, tuple[bool, bytes]] = {
    XTX_Tegra_Format.R8_UNORM: (False, _EMPTY_FOURCC),
    XTX_Tegra_Format.R8G8_UNORM: (False, _EMPTY_FOURCC),
    XTX_Tegra_Format.R8G8B8A8_UNORM: (False, _EMPTY_FOURCC),
    XTX_Tegra_Format.BC1_UNORM: (True, b"DXT1"),
    XTX_Tegra_Format.BC3_UNORM: (True, b"DXT5"),
    XTX_Tegra_Format.BC5_UNORM: (True, b"BC5U"),
    XTX_Tegra_Format.BC6H_UF16: (True, b"DX10"),
    XTX_Tegra_Format.B8G8R8A8_UNORM: (False, _EMPTY_FOURCC),
}


# caps, width, height, pixelformat, mipmapcount
STANDARD_DDSD_FLAGS = 0x21007

# caps without mips
_CAPS_NOMIP = CAPS_FLAGS.DDSCAPS_TEXTURE
_CAPS_MIP = CAPS_FLAGS.DDSCAPS_COMPLEX | CAPS_FLAGS.DDSCAPS_TEXTURE | CAPS_FLAGS.DDSCAPS_MIPMAP
# cubemap, all faces
_CAPS2_CUBEMAP = 0xFE00


class DdsExporter:
    raw: RawTexture
    dds_files: list[bytes]

    def __init__(self, raw: RawTexture) -> None:
        self.raw = raw
        self._build_all_dds()

    def _build_all_dds(self):
        """
        Generates a list of raw DDS files in `self.dds_files`.
        Should always be one texture per BCTEX, but haven't confirmed.
        """
        texture_count = len(self.raw.textures)
        if texture_count == 0:
            raise ValueError("Not enough textures!")

        res = []
        for arr in self.raw.textures:
            dds = self._build_dds(arr)
            res.append(dds)

        self.dds_files = res

    def _build_dds(self, array: Array) -> bytes:
        """
        Builds an array into a dds file

        See: https://learn.microsoft.com/en-us/windows/win32/direct3ddds/dx-graphics-dds-pguide
        """

        array_size = len(array.members)
        if array_size == 0:
            raise ValueError("No textures in arrays!")

        is_block_compressed, dxgi_fourcc = DXGI_FORMATS[array.format]

        # handle differences between BC and uncompressed formats
        pitch = array.width * array.height * array.format.bytes_per_pixel
        dds_flags = STANDARD_DDSD_FLAGS | DDS_FLAGS.DDSD_LINEARSIZE
        ddpf_flags = 0
        if is_block_compressed:
            pitch //= 16
            ddpf_flags = 4

        pixelformat = Container(
            dwSize=32,
            dwFlags=ddpf_flags,
            dwFourCC=dxgi_fourcc,
            dwRGBBitCount=0,
            dwRBitMask=0,
            dwGBitMask=0,
            dwBBitMask=0,
            dwABitMask=0,
        )

        if array.format == XTX_Tegra_Format.R8G8_UNORM:
            pixelformat.dwFlags = 0x41
            pixelformat.dwRGBBitCount = 0x18
            pixelformat.dwRBitMask = 0xFF << 16
            pixelformat.dwGBitMask = 0xFF << 8
            pixelformat.dwBBitMask = 0xFF
        elif array.format == XTX_Tegra_Format.R8G8B8A8_UNORM:
            pixelformat.dwFlags = 0x41
            pixelformat.dwRGBBitCount = 0x20
            pixelformat.dwRBitMask = 0xFF
            pixelformat.dwGBitMask = 0xFF << 8
            pixelformat.dwBBitMask = 0xFF << 16
            pixelformat.dwABitMask = 0xFF << 24

        header = Container(
            dwSize=124,
            dwFlags=dds_flags,
            dwHeight=array.height,
            dwWidth=array.width,
            dwPitchOrLinearSize=pitch,
            dwDepth=1,
            dwMipMapCount=len(array.members[0].mips),
            dwReserved1=[0] * 11,
            ddspf=pixelformat,
            dwCaps=_CAPS_MIP if len(array.members[0].mips) > 1 else _CAPS_NOMIP,
            dwCaps2=_CAPS2_CUBEMAP if array_size == 6 else 0,
            dwCaps3=0,
            dwCaps4=0,
            dwReserved2=0,
        )

        if dxgi_fourcc == b"DX10":
            header10 = Container(
                dxgiFormat=95,  # only cubemaps are exported as dx10
                resourceDimension=3,
                miscFlag=4,
                arraySize=array_size // 6,
                miscFlags2=0,
            )
        else:
            header10 = None

        data = b""
        for tex in array.members:
            for mip in tex.mips:
                data += mip.data

        dds = Container(_magic=b"DDS ", header=header, header10=header10, data=data)

        res = DDS.build(dds)
        return res

    def save_dds(self, folder: Path, name: str = None):
        """
        Exports a .dds file to the given folder.

        If there are multiple images contained in a single BCTEX (which there aren't in vanilla),
        an error is raised.

        :param folder: folder to write the dds file to
        :param name: name of the file. default is `{self.raw.name}.dds`
        """

        folder.mkdir(parents=True, exist_ok=True)
        if not name:
            name = self.raw.name + ".dds"

        if len(self.dds_files) == 1:
            folder.joinpath(name).write_bytes(self.dds_files[0])

        else:
            raise ValueError(f"Too many images contained in one BCTEX (expected 1, got {len(self.dds_files)}")
