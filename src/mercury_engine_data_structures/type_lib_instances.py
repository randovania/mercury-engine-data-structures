import functools

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.type_lib import TypeLib


@functools.lru_cache
def get_type_lib_dread():
    return TypeLib(dread_data.get_raw_types())

@functools.lru_cache
def get_type_lib_samus_returns():
    return TypeLib(samus_returns_data.get_raw_types())

