from typing import Type

from mercury_engine_data_structures.formats.bapd import Bapd
from mercury_engine_data_structures.formats.base_resource import AssetType, BaseResource
from mercury_engine_data_structures.formats.bcmdl import Bcmdl
from mercury_engine_data_structures.formats.bcskla import Bcskla
from mercury_engine_data_structures.formats.bctex import Bctex
from mercury_engine_data_structures.formats.bgsnds import Bgsnds
from mercury_engine_data_structures.formats.bldef import Bldef
from mercury_engine_data_structures.formats.blsnd import Blsnd
from mercury_engine_data_structures.formats.blut import Blut
from mercury_engine_data_structures.formats.bmbls import Bmbls
from mercury_engine_data_structures.formats.bmdefs import Bmdefs
from mercury_engine_data_structures.formats.bmmap import Bmmap
from mercury_engine_data_structures.formats.bmmdef import Bmmdef
from mercury_engine_data_structures.formats.bmsad import Bmsad
from mercury_engine_data_structures.formats.bmsas import Bmsas
from mercury_engine_data_structures.formats.bmsat import Bmsat
from mercury_engine_data_structures.formats.bmsbk import Bmsbk
from mercury_engine_data_structures.formats.bmscc import Bmscc
from mercury_engine_data_structures.formats.bmscu import Bmscu
from mercury_engine_data_structures.formats.bmsem import Bmsem
from mercury_engine_data_structures.formats.bmses import Bmses
from mercury_engine_data_structures.formats.bmsld import Bmsld
from mercury_engine_data_structures.formats.bmslgroup import Bmslgroup
from mercury_engine_data_structures.formats.bmslink import Bmslink
from mercury_engine_data_structures.formats.bmsmd import Bmsmd
from mercury_engine_data_structures.formats.bmsmsd import Bmsmsd
from mercury_engine_data_structures.formats.bmsnav import Bmsnav
from mercury_engine_data_structures.formats.bmssd import Bmssd
from mercury_engine_data_structures.formats.bmtre import Bmtre
from mercury_engine_data_structures.formats.bmtun import Bmtun
from mercury_engine_data_structures.formats.bnvib import Bnvib
from mercury_engine_data_structures.formats.bpsi import Bpsi
from mercury_engine_data_structures.formats.brem import Brem
from mercury_engine_data_structures.formats.bres import Bres
from mercury_engine_data_structures.formats.brev import Brev
from mercury_engine_data_structures.formats.brfld import Brfld
from mercury_engine_data_structures.formats.brsa import Brsa
from mercury_engine_data_structures.formats.brspd import Brspd
from mercury_engine_data_structures.formats.bsmat import Bsmat
from mercury_engine_data_structures.formats.gui_files import Bmscp, Bmssh, Bmssk, Bmsss
from mercury_engine_data_structures.formats.ini import Ini
from mercury_engine_data_structures.formats.lua import Lua
from mercury_engine_data_structures.formats.pkg import Pkg
from mercury_engine_data_structures.formats.toc import Toc
from mercury_engine_data_structures.formats.txt import Txt

ALL_FORMATS = {
    "PKG": Pkg,
    "BAPD": Bapd,
    "BCMDL": Bcmdl,
    "BCSKLA": Bcskla,
    "BCTEX": Bctex,
    "BGSNDS": Bgsnds,
    "BLDEF": Bldef,
    "BLSND": Blsnd,
    "BLUT": Blut,
    "BMBLS": Bmbls,
    "BMMAP": Bmmap,
    "BMMDEF": Bmmdef,
    "BMSBK": Bmsbk,
    "BMSCP": Bmscp,
    "BMSSD": Bmssd,
    "BMSSH": Bmssh,
    "BMSSK": Bmssk,
    "BMSSS": Bmsss,
    "BMSAD": Bmsad,
    "BMSAS": Bmsas,
    "BMSAT": Bmsat,
    "BMSES": Bmses,
    "BMTUN": Bmtun,
    "BRFLD": Brfld,
    "BMDEFS": Bmdefs,
    "BMSCC": Bmscc,
    "BMSCD": Bmscc,
    "BMSCU": Bmscu,
    "BMSEM": Bmsem,
    "BMSLD": Bmsld,
    "BMSMSD": Bmsmsd,
    "BMSNAV": Bmsnav,
    "BMSLGROUP": Bmslgroup,
    "BMSLINK": Bmslink,
    "BMSMD": Bmsmd,
    "BPSI": Bpsi,
    "BMTRE": Bmtre,
    "BNVIB": Bnvib,
    "BRSA": Brsa,
    "BRSPD": Brspd,
    "BREM": Brem,
    "BRES": Bres,
    "BREV": Brev,
    "BSMAT": Bsmat,
    "TOC": Toc,
    "TXT": Txt,
    "INI": Ini,
    "LUA": Lua,
}


def format_for(type_name: AssetType) -> Type[BaseResource]:
    return ALL_FORMATS[type_name.upper()]
