from typing import Optional

import construct

from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.type_lib import get_type_lib_dread


def create(name: str, version: int, root_name: Optional[str] = None, explicit_root: bool = False):
    # this maybe needs to change in the future if SR and Dread have different formats for type using this
    type_lib = get_type_lib_dread()
    if root_name is None:
        root_name = name

    if explicit_root:
        root = construct.FocusedSeq(
            "root",
            "type" / construct.Rebuild(PropertyEnum, name),
            "root" / type_lib.GetTypeConstruct(lambda this: this._.type)
        )
    else:
        root = type_lib.get_type(root_name).construct

    result = construct.Struct(
        _class_crc=construct.Const(name, PropertyEnum),
        _version=construct.Const(version, construct.Hex(construct.Int32ul)),

        root_type=construct.Const('Root', PropertyEnum),
        Root=root,

        _end=construct.Terminated,
    )
    result.name = name
    return result


def game_model(name: str, version: int):
    return create(name, version, "gameeditor::CGameModelRoot")
