from typing import Type

from mercury_engine_data_structures.formats.base_resource import BaseResource, AssetType
from mercury_engine_data_structures.formats.bldef import Bldef
from mercury_engine_data_structures.formats.bmbls import Bmbls
from mercury_engine_data_structures.formats.bmmap import Bmmap
from mercury_engine_data_structures.formats.bmmdef import Bmmdef
from mercury_engine_data_structures.formats.bmsad import Bmsad
from mercury_engine_data_structures.formats.bmsas import Bmsas
from mercury_engine_data_structures.formats.bmscc import Bmscc
from mercury_engine_data_structures.formats.bmscu import Bmscu
from mercury_engine_data_structures.formats.bmsld import Bmsld
from mercury_engine_data_structures.formats.bmsnav import Bmsnav
from mercury_engine_data_structures.formats.bmslgroup import Bmslgroup
from mercury_engine_data_structures.formats.bmslink import Bmslink
from mercury_engine_data_structures.formats.bmssd import Bmssd
from mercury_engine_data_structures.formats.bmtre import Bmtre
from mercury_engine_data_structures.formats.brem import Brem
from mercury_engine_data_structures.formats.bres import Bres
from mercury_engine_data_structures.formats.brev import Brev
from mercury_engine_data_structures.formats.brfld import Brfld
from mercury_engine_data_structures.formats.brsa import Brsa
from mercury_engine_data_structures.formats.ini import Ini
from mercury_engine_data_structures.formats.pkg import Pkg
from mercury_engine_data_structures.formats.toc import Toc
from mercury_engine_data_structures.formats.txt import Txt
from mercury_engine_data_structures.formats.gui_files import Bmscp, Bmssk, Bmsss

ALL_FORMATS = {
    "PKG": Pkg,
    "BLDEF": Bldef,
    "BMBLS": Bmbls,
    "BMMAP": Bmmap,
    "BMMDEF": Bmmdef,
    "BMSCP": Bmscp,
    "BMSSD": Bmssd,
    "BMSSK": Bmssk,
    "BMSSS": Bmsss,
    "BMSAD": Bmsad,
    "BMSAS": Bmsas,
    "BRFLD": Brfld,
    "BMSCC": Bmscc,
    "BMSCD": Bmscc,
    "BMSCU": Bmscu,
    "BMSLD": Bmsld,
    "BMSNAV": Bmsnav,
    "BMSLGROUP": Bmslgroup,
    "BMSLINK": Bmslink,
    "BMTRE": Bmtre,
    "BRSA": Brsa,
    "BREM": Brem,
    "BRES": Bres,
    "BREV": Brev,
    "TOC": Toc,
    "TXT": Txt,
    "INI": Ini,
}


def format_for(type_name: AssetType) -> Type[BaseResource]:
    return ALL_FORMATS[type_name.upper()]
