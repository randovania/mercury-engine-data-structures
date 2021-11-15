from typing import Type

from mercury_engine_data_structures.formats.base_resource import BaseResource, AssetType
from mercury_engine_data_structures.formats.bmsad import Bmsad
from mercury_engine_data_structures.formats.bmscc import Bmscc
from mercury_engine_data_structures.formats.bmssd import Bmssd
from mercury_engine_data_structures.formats.brem import Brem
from mercury_engine_data_structures.formats.bres import Bres
from mercury_engine_data_structures.formats.brev import Brev
from mercury_engine_data_structures.formats.brfld import Brfld
from mercury_engine_data_structures.formats.brsa import Brsa
from mercury_engine_data_structures.formats.pkg import Pkg
from mercury_engine_data_structures.formats.toc import Toc

ALL_FORMATS = {
    "PKG": Pkg,
    "BMSSD": Bmssd,
    "BMSAD": Bmsad,
    "BRFLD": Brfld,
    "BMSCC": Bmscc,
    "BRSA": Brsa,
    "BREM": Brem,
    "BRES": Bres,
    "BREV": Brev,
    "TOC": Toc,
}


def format_for(type_name: AssetType) -> Type[BaseResource]:
    return ALL_FORMATS[type_name.upper()]
