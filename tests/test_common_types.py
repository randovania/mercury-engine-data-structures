from __future__ import annotations

import pytest

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.common_types import Float


def test_make_dict_parse():
    data = b"\x02\x00\x00\x00foo\x00\x00\x00@?banana\x00\x00 \xa7D"
    con = common_types.make_dict(Float)

    # Run
    r = con.parse(data)

    # Assert
    assert r == {
        "foo": 0.75,
        "banana": 1337,
    }


def test_make_vector():
    data = ["banana", "foobar", "alfafa"]
    con = common_types.make_vector(common_types.StrId)

    # Run
    encoded = con.build(data)
    decoded = con.parse(encoded)

    # Assert
    assert data == decoded


def _parse_compare(
    raw: bytes,
    expected: list[float],
    con: common_types.construct.Construct,
    compiled: bool,
) -> common_types.Vec2:
    if compiled:
        con = con.compile()

    result = con.parse(raw)
    assert result == expected

    built = con.build(result)
    assert built == raw

    return result


@pytest.mark.parametrize("compiled", [False, True])
def test_cvector2d(compiled: bool) -> None:
    x = _parse_compare(
        b"\x00\x00\x80?\x00\x00 A",
        [1, 10],
        common_types.CVector2D,
        compiled,
    )
    assert type(x) == common_types.Vec2


@pytest.mark.parametrize("compiled", [False, True])
def test_cvector3d(compiled: bool) -> None:
    _parse_compare(
        b"\x00\x00\x80?\x00\x00 A\x00\x00\xa0@",
        [1, 10, 5],
        common_types.CVector3D,
        compiled,
    )


@pytest.mark.parametrize("compiled", [False, True])
def test_cvector4d(compiled: bool) -> None:
    _parse_compare(
        b"\x00\x00\x80?\x00\x00 A\x00\x00\xa0@\x00\x00\xa0@",
        [1, 10, 5, 5],
        common_types.CVector4D,
        compiled,
    )


@pytest.mark.parametrize("compiled", [False, True])
def test_cvector2d_vector(compiled: bool) -> None:
    _parse_compare(
        b"\x03\x00\x00\x00\x00\x00\x80?\x00\x00 A\x00\x00\xa0A\x00\x00\x06C\x00\x00\x80?\x00\x00\x00@",
        [[1, 10], [20, 134], [1, 2]],
        common_types.make_vector(common_types.CVector2D),
        compiled,
    )


@pytest.mark.parametrize("compiled", [False, True])
def test_cvector3d_vector(compiled: bool) -> None:
    _parse_compare(
        b"\x03\x00\x00\x00\x00\x00HB\x00\x00\xb8A\x00\x00 A\x00\x00\xa0A\x00\x80\xd9C\x00\x00\x06C\x00\x00\x80?\x00\x00\x06C\x00\x00\x00@",
        [[50, 23, 10], [20, 435, 134], [1, 134, 2]],
        common_types.make_vector(common_types.CVector3D),
        compiled,
    )


@pytest.mark.parametrize("compiled", [False, True])
def test_cvector4d_vector(compiled: bool) -> None:
    _parse_compare(
        b"\x03\x00\x00\x00\x00\x00\x80?\x00\x00 A\x00\x00\xc0@\x00\x00\x10A\x00\x00\xa0A\x00\x00\x06C\x00\x00\xc0B\x00\x00\xb8A\x00\x00\x80?\x00\x00\x00@\x00\x00HB\x00\x00\xb8A",
        [common_types.Vec4(1, 10, 6, 9), common_types.Vec4(20, 134, 96, 23), common_types.Vec4(1, 2, 50, 23)],
        common_types.make_vector(common_types.CVector4D),
        compiled,
    )


def test_vec_getters():
    v = common_types.Vec4(1, 2, 50, 23)
    assert v.x == v.r == 1
    assert v.y == v.g == 2
    assert v.z == v.b == 50
    assert v.w == v.a == 23
