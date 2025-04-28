from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from mercury_engine_data_structures.exporters.dds import DdsExporter
from mercury_engine_data_structures.exporters.raw_texture import RawTexture
from mercury_engine_data_structures.formats.bctex import Bctex

BCTEX_SINGLE_IMAGES = [
    (
        "textures/system/minimap/icons/icons.bctex",
        b"\x1f \xa0\xe8\x12\xa0\xfe\xe9\xb1s\xf2\xbds\xde\x03\xcf\xe2\xf29|\xe8\xcb\x1d \xf1\xda\xcdi~\xcd\x04\xd0",
    ),
    (
        "textures/actors/characters/autector/fx/textures/alarmring.bctex",
        b"\x96]P\x00\xd9\xc2\xeb\x97\xcf\xea\x9b\x14\x9a`\xf5)\x17\x04\xecx\xe2\xf2\xf6\x97\x1d\x7fw\xb1R\r\xfb\x17",
    ),
    (
        "textures/actors/characters/armadigger/models/textures/armadigger_bc.bctex",
        b"@M\xbb\xe1\xbbI\xab\x03\xda\xf1f\xd8U\xbc\xb9\xc2P\xc6\xbcsz\x16I\xab\x16\x94\xdcU\xfb(M%",
    ),
    (
        "textures/actors/props/doorshieldmissile/fx/textures/explosion01.bctex",
        b"-\x95Q8\xce\xeb\x18\xc4\x0e\xbbG\x1a\xae\\\xbet\xe1\x1a\xfd\x0cn\xfe\xed\xaf\x86\xbf\xb4b!&]\x0b",
    ),
    (
        "textures/actors/characters/chozowarrior/fx/textures/groundshaft.bctex",
        b"\xdb\xb3i5`K\x96\xdc\xec\x06\n?\x9c\xe0\x05\xaf*\xc0\xa6\xcc\xd7\xab\xe9\x85\xfd\x0b\x17\xda.\xd0\x8a\x91",
    ),
    (
        "textures/actors/characters/chozowarriorx/fx/textures/mudfluid04_nor.bctex",
        b"\xf4\x08\xc5$\xd5\x87p\xf1\x1d\xe1\xca;\x1f\x020\xdbBR4\x92\xcf_im\xec\x9d\xa24\xf8\x86\xda\x1c",
    ),
    (
        "textures/maps/cubemaps/airport_cubemapdiffusehdr.bctex",
        b"\xf0\xc8\xaeX\xd3\x93\x89(?\xc9g\xba\x9aG|7cJ!\xa1\x86\xac\xae\x84\xee\x99\x08\xed\x90w\x0b\xfa",
    ),
]


@pytest.mark.parametrize(["texture_name", "sha256_hash"], BCTEX_SINGLE_IMAGES)
def test_bctex_export(texture_name: str, sha256_hash: bytes, dread_tree_100, tmp_path):
    tex = dread_tree_100.get_parsed_asset(texture_name, type_hint=Bctex)
    exporter = DdsExporter(RawTexture(tex))

    assert len(exporter.dds_files) == 1
    assert sha256(exporter.dds_files[0]).digest() == sha256_hash

    exporter.save_dds(Path(tmp_path))
    expected_result = Path(tmp_path).joinpath(f"{tex.raw.data.name}.dds")

    assert expected_result.exists()
    assert sha256(expected_result.read_bytes()).digest() == sha256_hash
