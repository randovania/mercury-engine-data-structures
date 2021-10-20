from construct import Construct

from mercury_engine_data_structures.formats.pkg import PKG

AssetType = str
AssetId = int

ALL_FORMATS = {
    "PKG": PKG,
}


def format_for(type_name: AssetType) -> Construct:
    return ALL_FORMATS[type_name.upper()]
