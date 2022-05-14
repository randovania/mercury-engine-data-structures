import pytest

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.object import Object

TestClass = Object({
    "fTimeToChargeDoubleGroundShock": common_types.Float,
    "uNumShocks": common_types.UInt,
    "fTimeBetweenShockwaves": common_types.Float,
    "fTimeToEndShockwaves": common_types.Float,
})


@pytest.fixture(name="sample_object", params=[
    (
            {"fTimeToChargeDoubleGroundShock": 1.5, "uNumShocks": 15, "fTimeToEndShockwaves": 20.0},
            (b'\x03\x00\x00\x00w3t}\x9f{\xc4\x83\x00\x00\xc0?e|x\x01\xed|\x08D'
             b'\x0f\x00\x00\x00\x15\x849o@\xdb\x8a\xf3\x00\x00\xa0A')
    ),
    (
            [
                {"type": "fTimeToChargeDoubleGroundShock", "item": 1.5},
                {"type": "fTimeToChargeDoubleGroundShock", "item": 5.5},
                {"type": "uNumShocks", "item": 15},
            ],
            (b'\x03\x00\x00\x00w3t}\x9f{\xc4\x83\x00\x00\xc0?w3t}\x9f{\xc4\x83\x00\x00\xb0@'
             b'e|x\x01\xed|\x08D\x0f\x00\x00\x00')
    ),
])
def _sample_object(request):
    return request.param


def test_build_object(sample_object):
    result = TestClass.build(sample_object[0])
    assert result == sample_object[1]


def test_parse_object(sample_object):
    result = TestClass.parse(sample_object[1])
    assert result == sample_object[0]


def test_compile_build_object(sample_object):
    result = TestClass.compile().build(sample_object[0])
    assert result == sample_object[1]


def test_compile_parse_object(sample_object):
    result = TestClass.compile().parse(sample_object[1])
    assert result == sample_object[0]
