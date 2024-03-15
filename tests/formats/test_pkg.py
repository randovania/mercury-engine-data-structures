import pytest
from construct import Container, ListContainer
from tests.test_lib import parse_and_build_compare

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.pkg import Pkg
from mercury_engine_data_structures.game_check import Game

_EMPTY_DREAD_PKG = (b'\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

all_dread_pkg = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".pkg")]

all_sr_pkg = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".pkg")]

wrong_build_sr = [
    # MSCU, no padding in vanilla
    "packs/cutscenes/elevator.pkg",
    # MSCU, no padding in vanilla
    "packs/cutscenes/teleporter.pkg",
    # MSAT, padding of three 0 bytes in vanilla
    "packs/maps/s020_area2/subareas/subarearp1_discardables.pkg",
    # MSAT, padding of one 0 byte in vanilla
    "packs/maps/s033_area3b/subareas/subarearp7_discardables.pkg",
    # MSAT, padding of one 0 byte in vanilla
    "packs/maps/s033_area3b/subareas/subarearp8_discardables.pkg",
    # MSAT, padding of one 0 byte in vanilla
    "packs/maps/s050_area5/subareas/subarearp4_discardables.pkg",
    # MSAT, padding of one 0 byte in vanilla
    "packs/maps/s060_area6/subareas/subarearp4_discardables.pkg",
    # MSAT, padding of one 0 byte in vanilla
    "packs/maps/s065_area6b/subareas/subarearp4_discardables.pkg",
    # MSAT, padding of one 0 byte in vanilla
    "packs/maps/s067_area6c/subareas/subarearp6_discardables.pkg",
    # MTXT, no padding in vanilla
    "packs/players/common.pkg",
    # MTXT, no padding in vanilla
    "packs/players/common_fusion.pkg",
]

@pytest.mark.parametrize("pkg_path", all_dread_pkg)
def test_compare_dread(dread_path, pkg_path):
    parse_and_build_compare(
        Pkg.construct_class(Game.DREAD), Game.DREAD, dread_path.joinpath(pkg_path)
    )

@pytest.mark.parametrize("pkg_path", all_sr_pkg)
def test_compare_sr(samus_returns_path, pkg_path):
    if pkg_path in wrong_build_sr:
        raw = samus_returns_path.joinpath(pkg_path).read_bytes()
        target_game = Game.SAMUS_RETURNS

        module = Pkg.construct_class(target_game)
        data = module.parse(raw, target_game=target_game)
        encoded = module.build(data, target_game=target_game)

        # compare up to the length field
        assert raw[0:4] == encoded[0:4]

        # compare after the length field until the end of bytes
        # only to proof that only the ending has a random padding
        min_len = min(len(raw), len(encoded))
        assert raw[5:min_len] == encoded[5:min_len]
        assert abs(len(raw) - len(encoded)) <= 3
    else:
        parse_and_build_compare(
            Pkg.construct_class(Game.SAMUS_RETURNS), Game.SAMUS_RETURNS, samus_returns_path.joinpath(pkg_path)
        )

def test_build_empty_pkg():
    pkg = Pkg(Container(files=ListContainer()), Game.DREAD)

    assert pkg.build() == _EMPTY_DREAD_PKG


def test_remove_pkg_element():
    single_element_pkg = (b'|\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\xd2\x04\x00\x00'
                          b'\x00\x00\x00\x00\x80\x00\x00\x00\x86\x00\x00\x00\x00\x00\x00\x00'
                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                          b'FOOBAR\x00\x00')

    pkg = Pkg.parse(single_element_pkg, Game.DREAD)
    assert pkg.build() == single_element_pkg

    pkg.remove_asset(1234)
    assert pkg.build() == _EMPTY_DREAD_PKG
