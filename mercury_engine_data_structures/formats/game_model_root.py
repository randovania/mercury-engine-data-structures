import construct

from mercury_engine_data_structures.formats.dread_types import gameeditor_CGameModelRoot
from mercury_engine_data_structures.formats.property_enum import PropertyEnum


def create(name: str, magic_number: int):
    return construct.Struct(
        _magic=construct.Const(name, PropertyEnum),
        _magic_number=construct.Const(magic_number, construct.Hex(construct.Int32ul)),

        # gameeditor::CGameModelRoot
        root_type=construct.Const('Root', PropertyEnum),
        Root=gameeditor_CGameModelRoot,

        _end=construct.Terminated,
    )
