from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.common_types import Float


def test_make_dict_parse():
    data = b'\x02\x00\x00\x00foo\x00\x00\x00@?banana\x00\x00 \xa7D'
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

