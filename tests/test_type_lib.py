import contextlib

import pytest

from mercury_engine_data_structures.formats import dread_types
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.type_lib import TypeLib, get_type_lib_for_game


@pytest.mark.parametrize("game", (Game.DREAD, Game.SAMUS_RETURNS))
def test_get_type_lib_for_game(game):
    type_lib = get_type_lib_for_game(game)
    assert type_lib.target_game == game


@pytest.fixture(name="dread_type_lib")
def _dread_type_lib():
    return get_type_lib_for_game(Game.DREAD)


@pytest.mark.parametrize(("type_name", "value", "expected"), (
    # primitive
    ("base::global::CStrId", "", None),
    ("bool", True, None),
    ("int", -1, None),
    ("unsigned_short", 2**16 - 1, None),
    ("unsigned_int", 2**32 - 1, None),
    ("unsigned_long", 2**64 - 1, None),
    ("float", 0.0, None),
    ("base::math::CVector2D", [0.0, 0.0], None),
    ("base::math::CVector3D", [0.0, 0.0, 0.0], None),
    ("base::math::CVector4D", [0.0, 0.0, 0.0, 0.0], None),
    ("base::global::CRntFile", b"\x24\x03", None),
    ("base::global::CName", "", None),
    ("base::global::CName", 2**64 - 1, None),

    ("base::global::CStrId", None, TypeError('Expected str; got NoneType')),
    ("bool", None, TypeError('Expected bool; got NoneType')),
    ("int", None, TypeError("Expected int; got NoneType")),
    ("unsigned_short", None, TypeError("Expected int; got NoneType")),
    ("unsigned_int", None, TypeError("Expected int; got NoneType")),
    ("unsigned_long", None, TypeError("Expected int; got NoneType")),
    ("float", None, TypeError("Expected float; got NoneType")),
    ("base::math::CVector2D", None, TypeError("Expected typing.Sequence; got NoneType")),
    ("base::math::CVector3D", None, TypeError("Expected typing.Sequence; got NoneType")),
    ("base::math::CVector4D", None, TypeError("Expected typing.Sequence; got NoneType")),
    ("base::global::CRntFile", None, TypeError('Expected bytes; got NoneType')),
    ("base::global::CName", None, TypeError('Expected str | int; got NoneType')),
    ("base::global::CName", None, TypeError('Expected str | int; got NoneType')),

    ("int", -2**33, ValueError('-8589934592 is out of range of [-0x80000000, 0x7fffffff]')),
    ("int", 2**33, ValueError('8589934592 is out of range of [-0x80000000, 0x7fffffff]')),
    ("unsigned_short", 2**16, ValueError('65536 is out of range of [0x0, 0xffff]')),
    ("unsigned_int", 2**32, ValueError('4294967296 is out of range of [0x0, 0xffffffff]')),
    ("unsigned_long", 2**64, ValueError('18446744073709551616 is out of range of [0x0, 0xffffffffffffffff]')),
    ("base::global::CName", -1, ValueError('-1 is out of range of [0x0, 0xffffffffffffffff]')),

    ("base::math::CVector2D", ["foo", "bar"], ValueError("Invalid CVector2D: ['foo', 'bar']")),
    ("base::math::CVector2D", [0.0], ValueError('Invalid CVector2D: [0.0]')),
    ("base::math::CVector3D", [0.0], ValueError('Invalid CVector3D: [0.0]')),
    ("base::math::CVector4D", [0.0], ValueError('Invalid CVector4D: [0.0]')),

    # struct
    ("base::reflection::CType", {
        "sName": "base::reflection::CFlagsetType",
        "sBaseTypeName": "base::reflection::CType",
    }, None),

    ("base::reflection::CType", None, TypeError('Expected base::reflection::CType; got NoneType')),
    ("base::reflection::CType", {
        "sName": True,
        "sBaaaseTypeName": "base::reflection::CType",
    }, TypeError(
        TypeError('Expected str; got bool'),
        AttributeError("Invalid attribute 'sBaaaseTypeName' for base::reflection::CType")
    )),

    # enum
    ("ETeleporterColorSphere", dread_types.ETeleporterColorSphere.PINK, None),
    ("ETeleporterColorSphere", 4, None),
    ("ETeleporterColorSphere", "PINK", None),

    (
        "ETeleporterColorSphere",
        dread_types.ECoolShinesparkSituation.Default,
        TypeError('Expected ETeleporterColorSphere; got ECoolShinesparkSituation')
    ),
    ("ETeleporterColorSphere", 40, ValueError('40 is not a valid ETeleporterColorSphere')),
    ("ETeleporterColorSphere", "PIIINK", TypeError('Expected ETeleporterColorSphere; got str')),

    # flagset
    ("TCoolShinesparkSituation", dread_types.ECoolShinesparkSituation.Default, None),
    ("TCoolShinesparkSituation", "Default|CooldownX", None),
    ("TCoolShinesparkSituation", 0b11, None),

    (
        "TCoolShinesparkSituation",
        dread_types.ETeleporterColorSphere.PINK,
        TypeError('Expected TCoolShinesparkSituation; got ETeleporterColorSphere')
    ),
    (
        "TCoolShinesparkSituation",
        "Default|CooldownY",
        TypeError("Contains invalid ECoolShinesparkSituation names: ['CooldownY']")
    ),
    ("TCoolShinesparkSituation", 0b111, TypeError('7 is not a valid TCoolShinesparkSituation')),

    # typedef
    ("GUI::CDisplayObjectTrack<bool>::SKey", {
        "iFrame": 0,
        "Value": True,
    }, None),
    ("GUI::CDisplayObjectTrack<bool>::SKey", {
        "iFrame": 1.2,
        "Vaalue": True,
    }, TypeError(
        TypeError('Expected int; got float'),
        AttributeError("Invalid attribute 'Vaalue' for GUI::CDisplayObjectTrackBool::SKey")
    )),

    # pointer
    ("CEnvironmentData::SCubeMap*", None, None),
    ("CEnvironmentData::SCubeMap*", {
        "fInterp": 0.0,
        "bEnabled": True,
        "sTexturePath": "",
    }, None),
    ("CEnvironmentData::SCubeMap*", {
        "@type": "CEnvironmentData::SCubeMap",
        "@value": {
            "fInterp": 0.0,
            "bEnabled": True,
            "sTexturePath": "",
        },
    }, None),
    ("game::logic::collision::CShape*", None, None),
    ("game::logic::collision::CShape*", {
        "@type": "game::logic::collision::CCircleShape2D",
        "@value": {
            "vPos": [0.0, 0.0, 0.0],
            "bIsSolid": False,
            "fRadius": 1.0,
        }
    }, None),

    ("CEnvironmentData::SCubeMap*", {
        "fIntep": 0.0,
        "bEnabled": None,
        "sTexturePath": "",
    }, TypeError(
        AttributeError("Invalid attribute 'fIntep' for CEnvironmentData::SCubeMap"),
        TypeError('Expected bool; got NoneType')
    )),
    ("CEnvironmentData::SCubeMap*", {
        "@type": "CEnvironmentData:::::SCubeMap",
        "@value": {
            "fInterp": 0.0,
            "bEnabled": True,
            "sTexturePath": "",
        },
    }, TypeError('CEnvironmentData:::::SCubeMap is not a valid target for CEnvironmentData::SCubeMap*')),
    ("game::logic::collision::CShape*", {
        "vPos": [0.0, 0.0, 0.0],
        "bIsSolid": False,
        "fRadius": 1.0,
    }, TypeError('No type specified for game::logic::collision::CShape*')),

    # vector
    ("base::global::CRntVector<bool>", [], None),
    ("base::global::CRntVector<bool>", [True, False, True], None),

    ("base::global::CRntVector<bool>", None, TypeError('NoneType is not iterable')),
    ("base::global::CRntVector<bool>", ["foo", True, 999], TypeError(
        (0, TypeError('Expected bool; got str')),
        (2, TypeError('Expected bool; got int'))
    )),

    # dictionary
    ("base::global::CRntSmallDictionary<base::global::CStrId, float>", {"foo": 1.0}, None),
    ("base::global::CRntSmallDictionary<base::global::CStrId, float>", {}, None),

    ("base::global::CRntSmallDictionary<base::global::CStrId, float>", {
        1.0: "foo",
        "bar": "baz",
        2.0: 1.0,
    }, TypeError(('Keys', {
        1.0: TypeError('Expected str; got float'),
        2.0: TypeError('Expected str; got float')
    }), ('Values', {
        1.0: TypeError('Expected float; got str'),
        'bar': TypeError('Expected float; got str')
    }))),
))
def test_find_type_errors(dread_type_lib: TypeLib, type_name, value, expected):
    type_class = dread_type_lib.get_type(type_name)
    err = type_class._find_type_errors(value)

    if expected is None:
        assert err is None
        ctx = contextlib.nullcontext()
    else:
        assert str(err) == str(expected)
        ctx = pytest.raises(type(expected))

    with ctx:
        type_class.verify_integrity(value)

    assert type_class.is_value_of_type(value) == (expected is None)


def test_get_parent_for(dread_type_lib: TypeLib):
    assert dread_type_lib.get_parent_for("base::core::CAsset") == "base::core::CBaseObject"
    assert dread_type_lib.get_parent_for("base::core::CBaseObject") is None
    assert dread_type_lib.get_parent_for("bool") is None


def test_is_child_of(dread_type_lib: TypeLib):
    assert dread_type_lib.is_child_of("CCharClassMushroomPlatformComponent", "base::core::CBaseObject")
    assert not dread_type_lib.is_child_of("bool", "base::core::CBaseObject")


def test_all_children_for(dread_type_lib: TypeLib):
    children = dread_type_lib.get_all_children_for("base::core::CBaseObject")
    for child in children:
        assert dread_type_lib.is_child_of(child, "base::core::CBaseObject")
    assert len(children) == 1194
