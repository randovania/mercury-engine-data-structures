import contextlib

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bcmdl import Bcmdl

all_dread_bcmdl = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bcmdl")]

dread_bcmdl_expected_failure = [
    'actors/characters/morphball/models/labase.bcmdl',
    'actors/characters/morphball/models/ladamage.bcmdl',
    'actors/characters/samus/models/phasedisplacement_new.bcmdl',
    'actors/items/powerup_sonar/models/powerup_sonar.bcmdl',
    'actors/props/teleporter/models/samusaura.bcmdl',
    'actors/props/teleporter/models/teleporttunnel.bcmdl',
    'actors/weapons/grapplebeam/models/grapplelightning_1.bcmdl',
    'actors/weapons/weaponboost/models/weaponboost.bcmdl',
    'actors/weapons/weaponboost/models/weaponboostmorphball.bcmdl',
    'system/engine/models/immune.bcmdl',
    'system/engine/models/sedisolve.bcmdl',
    'system/engine/models/sedisolver.bcmdl',
    'system/engine/models/selected_hi.bcmdl',
    'system/engine/models/selected_lo.bcmdl',
]


@pytest.mark.parametrize("bcmdl_path", all_dread_bcmdl)
def test_compare_dread_all(dread_file_tree, bcmdl_path):
    if bcmdl_path in dread_bcmdl_expected_failure:
        expectation = pytest.raises(AssertionError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(
            Bcmdl, dread_file_tree, bcmdl_path
        )


def test_change_material(dread_file_tree):
    construct_class = Bcmdl.construct_class(dread_file_tree.target_game)
    model = dread_file_tree.get_parsed_asset("actors/props/doorshieldsupermissile/models/doorshieldsupermissile.bcmdl",
                                             type_hint=Bcmdl)

    # ensure replacing it with the exact length works
    replace = "actors/props/doorshieldsupermissile/models/imats/doorshieldsupermissile_mp_opaque_69.bsmat"
    model.change_material_path("mp_opaque_01", replace)
    encoded = construct_class.build(model.raw, target_game=dread_file_tree.target_game)

    assert encoded[0x5845:0x58A0] == (b"actors/props/doorshieldsupermissile/models/imats/"
                                      b"doorshieldsupermissile_mp_opaque_69.bsmat\0")

    # ensure replacing it with a shorter length works
    replace = "actors/props/doorshieldsupermiss/models/imats/doorshieldsupermiss_mp_opaque_01.bsmat"
    model.change_material_path("mp_opaque_01", replace)
    encoded2 = construct_class.build(model.raw, target_game=dread_file_tree.target_game)

    assert encoded2[0x5845:0x58A0] == (b"actors/props/doorshieldsupermiss/models/imats/"
                                       b"doorshieldsupermiss_mp_opaque_01.bsmat\0\0\0\0\0\0\0")

    long_path = "actors/props/doorshieldsupermissile/models/imats/doorshieldsupermissile_mp_opaque_420.bsmat"
    expectation = pytest.raises(ValueError)
    with expectation:
        model.change_material_path("mp_opaque_01", long_path)
