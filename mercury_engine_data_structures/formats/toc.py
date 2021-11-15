import construct

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.property_enum import FileNameEnumUnsafe
from mercury_engine_data_structures.game_check import Game


TOC = construct.Struct(
    files=common_types.make_dict(
        value=construct.Int32ul,
        key=FileNameEnumUnsafe,
    ),
)


class Toc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return TOC
