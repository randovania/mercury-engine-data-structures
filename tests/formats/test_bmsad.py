import contextlib

import construct
import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import dread_types
from mercury_engine_data_structures.formats.bmsad import ActorDefFunc, Bmsad

all_sr_bmsad = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                if name.endswith(".bmsad")]

all_dread_bmsad = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmsad")]

expected_dread_failures = {
    "actors/props/pf_mushr_fr/charclasses/pf_mushr_fr.bmsad",
}
expected_sr_failures = set()


@pytest.mark.parametrize("bmsad_path", all_dread_bmsad)
def test_compare_dread_all(dread_file_tree, bmsad_path):
    if bmsad_path in expected_dread_failures:
        expectation = pytest.raises(construct.ConstructError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(
            Bmsad, dread_file_tree, bmsad_path
        )


@pytest.mark.parametrize("bmsad_path", all_sr_bmsad)
def test_compare_sr_all(samus_returns_tree, bmsad_path):
    if not samus_returns_tree.does_asset_exists(bmsad_path):
        return pytest.skip()

    if bmsad_path in expected_sr_failures:
        expectation = pytest.raises(construct.core.ConstError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(
            Bmsad, samus_returns_tree, bmsad_path
        )


def test_api_dread_actordef(dread_file_tree: FileTreeEditor):
    bmsad = dread_file_tree.get_parsed_asset(
        "actors/logic/breakablehint/charclasses/breakablehint.bmsad",
        type_hint=Bmsad
    )

    fakename = "foo"

    assert bmsad.name == "breakablehint"
    bmsad.name = fakename
    assert bmsad.name == fakename

    with pytest.raises(AttributeError):
        bmsad.model_name = fakename
    with pytest.raises(AttributeError):
        assert bmsad.model_name == fakename

    assert bmsad.sub_actors == []
    bmsad.sub_actors = [fakename, fakename]
    assert bmsad.sub_actors == [fakename, fakename]

    assert bmsad.action_sets == []
    with pytest.raises(AttributeError):
        bmsad.action_sets = []

    assert bmsad.action_set_refs == []
    bmsad.action_set_refs = [fakename]
    assert bmsad.action_set_refs == [fakename]

    assert bmsad.sound_fx == []
    bmsad.sound_fx = [(fakename, 0)]
    assert bmsad.sound_fx == [(fakename, 0)]

    # make sure it builds
    bmsad.build()


def test_api_dread_charclass(dread_file_tree: FileTreeEditor):
    bmsad = dread_file_tree.get_parsed_asset(
        "actors/props/doorheat/charclasses/doorheat.bmsad",
        type_hint=Bmsad
    )

    fakename = "foo"

    assert bmsad.name == "doorheat"

    assert bmsad.model_name == "actors/props/doorheat/models/doorheat.bcmdl"
    bmsad.model_name = fakename
    assert bmsad.model_name == fakename

    assert len(bmsad.action_sets) == 1
    assert bmsad.action_set_refs == ["actors/props/doorheat/charclasses/doorheat.bmsas"]

    assert bmsad.sound_fx == [
        ("props/heatdoor/hdoor_close_02.wav", 1),
        ("props/heatdoor/hdoor_open_02.wav", 1),
        ("props/heatdoor/hdoor_close_01.wav", 1),
        ("props/heatdoor/hdoor_init.wav", 1),
        ("props/heatdoor/hdoor_open_01.wav", 1)
    ]

    navmesh = bmsad.components["NAVMESHITEM"]

    # type
    assert navmesh.type == "CNavMeshItemComponent"
    assert navmesh.get_component_type() == "CCharClassNavMeshItemComponent"
    navmesh.type = "CPowerBombBlockLifeComponent"
    assert navmesh.type == "CPowerBombBlockLifeComponent"
    assert navmesh.get_component_type() == "CCharClassLifeComponent"
    navmesh.type = "CNavMeshItemComponent"

    # extra_fields
    assert navmesh.fields.sInitialStage == "closed"
    navmesh.fields.sInitialStage = "opened"
    assert navmesh.fields.sInitialStage == "opened"

    # fields
    assert navmesh.fields.eType == dread_types.ENavMeshItemType.Dynamic

    with pytest.raises(TypeError):
        navmesh.fields.eType = fakename

    navmesh.fields.eType = None
    assert navmesh.raw.fields is None

    navmesh.fields.eType = dread_types.ENavMeshItemType.Destructible
    assert navmesh.raw.fields is not None
    assert navmesh.fields.eType == dread_types.ENavMeshItemType.Destructible

    with pytest.raises(AttributeError):
        navmesh.fields.oThisIsNotARealField = fakename

    # functions
    funcs = list(navmesh.functions)
    assert [func.name for func in funcs] == [
        "CreateStage",
        "AddStageCollider",
        "CreateStage"
    ]
    newfunc = ActorDefFunc.new("CreateStage")
    newfunc.set_param("Stage", "in-between")
    funcs.append(newfunc)
    navmesh.functions = funcs

    assert navmesh.functions[-1] == newfunc

    # dependencies
    assert navmesh.dependencies is None

    # make sure it builds
    bmsad.build()


def test_api_sr(samus_returns_tree: FileTreeEditor):
    bmsad = samus_returns_tree.get_parsed_asset(
        "actors/characters/alpha/charclasses/alpha.bmsad",
        type_hint=Bmsad,
    )

    fakename = "foo"

    assert bmsad.name == "alpha"
    bmsad.name = fakename
    assert bmsad.name == fakename

    assert bmsad.model_name == "actors/characters/alpha/models/alpha.bcmdl"
    bmsad.model_name = fakename
    assert bmsad.model_name == fakename

    assert bmsad.sub_actors == [
        "alphaelectricmine",
        "adn",
        "ice_casquery",
        "alphagiantelectricmine",
    ]
    bmsad.sub_actors = [fakename, fakename]
    assert bmsad.sub_actors == [fakename, fakename]

    assert len(bmsad.action_sets) == 1

    with pytest.raises(AttributeError):
        assert bmsad.action_set_refs == []
    with pytest.raises(AttributeError):
        bmsad.action_set_refs = []

    assert len(bmsad.sound_fx) == 39
    bmsad.sound_fx = []
    assert bmsad.raw.sound_fx is None
    bmsad.sound_fx = [(fakename, 0)]
    assert bmsad.sound_fx == [(fakename, 0)]

    # components
    modelupdater = bmsad.components["MODELUPDATER"]
    modelupdater.functions[1].set_param(1, "foo")

    assert modelupdater.fields.vInitPosWorldOffset == [0.0, 0.0, 0.0]
    modelupdater.fields.vInitPosWorldOffset = [1.0, 2.0, 3.0]
    assert modelupdater.fields.vInitPosWorldOffset == [1.0, 2.0, 3.0]
    with pytest.raises(TypeError):
        modelupdater.fields.vInitPosWorldOffset = [1, True, False]
    with pytest.raises(ValueError):
        modelupdater.fields.vInitPosWorldOffset = [0.0, 0.0]
    with pytest.raises(TypeError):
        modelupdater.fields.vInitPosWorldOffset = {"foo": "bar"}

    # make sure it builds
    bmsad.build()
