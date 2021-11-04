from typing import Type

from mercury_engine_data_structures.formats.base_resource import BaseResource, AssetType
from mercury_engine_data_structures.formats.bmsad import Bmsad
from mercury_engine_data_structures.formats.bmscc import Bmscc
from mercury_engine_data_structures.formats.bmssd import Bmssd
from mercury_engine_data_structures.formats.brfld import Brfld
from mercury_engine_data_structures.formats.pkg import Pkg

ALL_FORMATS = {
    "PKG": Pkg,
    "BMSSD": Bmssd,
    "BMSAD": Bmsad,
    "BRFLD": Brfld,
    "BMSCC": Bmscc,
}


def format_for(type_name: AssetType) -> Type[BaseResource]:
    return ALL_FORMATS[type_name.upper()]
