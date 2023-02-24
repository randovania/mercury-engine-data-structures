import pytest

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet

CEnemyPreset = Object({
    "sId": common_types.StrId,
    "fLife": common_types.Float,
    "sLifeTunable": common_types.StrId,
    "sLifeTunableVar": common_types.StrId,
})

CCentralUnitComponent_SStartPointInfo = Object({
    "wpStartPoint": common_types.StrId,
    "wpEmmyLandmark": common_types.StrId,
})

SingleType = PointerSet("SingleType")
SingleType.add_option("CEnemyPreset", CEnemyPreset)
SingleTypeConstruct = SingleType.create_construct()

TwoType = PointerSet("SingleType")
TwoType.add_option("CEnemyPreset", CEnemyPreset)
TwoType.add_option("CCentralUnitComponent::SStartPointInfo", CCentralUnitComponent_SStartPointInfo)
TwoTypeConstruct = TwoType.create_construct()


@pytest.fixture(name="single_type_sample", params=[
    (
            None,
            b'\xd3\x1a\x0f\xac e\x88\xce'
    ),
    (
            {"fLife": 1234.0, "sId": "foo"},
            (b'\x90T\xcc\xd8\x92\r\xceV\x02\x00\x00\x00\xe1\x10\x8bI\xc4%\xdf{\x00@\x9aD'
             b'\x9f\x05lwS\x87\xd4\xe9foo\x00'),
    )
])
def _single_type_sample(request):
    return request.param


@pytest.fixture(name="two_type_sample", params=[
    (
            None,
            b'\xd3\x1a\x0f\xac e\x88\xce'
    ),
    (
            {"@type": "CEnemyPreset", "fLife": 1234.0, "sId": "foo"},
            (b'\x90T\xcc\xd8\x92\r\xceV\x02\x00\x00\x00\xe1\x10\x8bI\xc4%\xdf{\x00@\x9aD'
             b'\x9f\x05lwS\x87\xd4\xe9foo\x00')
    ),
    (
            {"@type": "CCentralUnitComponent::SStartPointInfo", "wpStartPoint": "foo"},
            b'\xb1M\xeb\xac\xc4_u\x0c\x01\x00\x00\x00\x16t\x82\x93\xf2\x11BQfoo\x00'
    ),
])
def _two_type_sample(request):
    return request.param


def test_build_single_object(single_type_sample):
    result = SingleTypeConstruct.build(single_type_sample[0])
    assert result == single_type_sample[1]


def test_parse_single_object(single_type_sample):
    result = SingleTypeConstruct.parse(single_type_sample[1])
    assert result == single_type_sample[0]


# def test_compile_build_single_object(single_type_sample):
#     result = SingleTypeConstruct.compile(r"C:\Users\henri\programming\mercury-engine-data-structures\foo.py").build(
#         single_type_sample[0])
#     assert result == single_type_sample[1]


def test_compile_parse_single_object(single_type_sample):
    result = SingleTypeConstruct.compile().parse(single_type_sample[1])
    assert result == single_type_sample[0]


def test_build_two_object(two_type_sample):
    result = TwoTypeConstruct.build(two_type_sample[0])
    assert result == two_type_sample[1]


def test_parse_two_object(two_type_sample):
    result = TwoTypeConstruct.parse(two_type_sample[1])
    assert result == two_type_sample[0]


def test_compile_build_two_object(two_type_sample):
    result = TwoTypeConstruct.compile().build(two_type_sample[0])
    assert result == two_type_sample[1]


def test_compile_parse_two_object(two_type_sample):
    result = TwoTypeConstruct.compile().parse(two_type_sample[1])
    assert result == two_type_sample[0]
