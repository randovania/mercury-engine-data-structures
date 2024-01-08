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

@pytest.mark.parametrize("pkg_path", all_dread_pkg)
def test_compare_dread(dread_path, pkg_path):
    parse_and_build_compare(
        Pkg.construct_class(Game.DREAD), Game.DREAD, dread_path.joinpath(pkg_path)
    )

@pytest.mark.skip("Rebuilding vanilla pkg files is currently not supported for SR")
@pytest.mark.parametrize("pkg_path", all_sr_pkg)
def test_compare_sr(samus_returns_path, pkg_path):
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
