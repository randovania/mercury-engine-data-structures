import functools

import construct
from construct.core import Const, Construct, Enum, Float32l, Hex, Int32sl, Int32ul, Struct

from mercury_engine_data_structures.common_types import CVector2D, CVector3D, StrId, make_vector
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

BorderType = Enum(
    Int32sl,
    NONE=0,
    TOP_EDGE=1,
    BOTTOM_EDGE=2,
    HORIZONTAL_CENTER=3,
    LEFT_EDGE=4,
    TOP_LEFT_CORNER=5,
    BOTTOM_LEFT_CORNER=6,
    HORIZONTAL_LEFT=7,
    RIGHT_EDGE=8,
    TOP_RIGHT_CORNER=9,
    BOTTOM_RIGHT_CORNER=10,
    HORIZONTAL_RIGHT=11,
    VERTICAL_CENTER=12,
    VERTICAL_TOP=13,
    VERTICAL_BOTTOM=14,
    ALL_SIDES=15,
    TOP_EDGE_OPEN_TOP=16,
    TOP_EDGE_HIDDEN_TOP=17,
    HORIZONTAL_CENTER_HIDDEN_TOP=19,
    TOP_LEFT_CORNER_OPEN_TOP=21,
    HORIZONTAL_LEFT_OPEN_TOP=23,
    TOP_RIGHT_CORNER_OPEN_TOP=24,
    TOP_RIGHT_CORNER_HIDDEN_TOP=25,
    BOTTOM_EDGE_OPEN_BOTTOM=32,
    BOTTOM_EDGE_HIDDEN_BOTTOM=34,
    BOTTOM_LEFT_CORNER_OPEN_BOTTOM=38,
    BOTTOM_RIGHT_CORNER_OPEN_BOTTOM=40,
    HORIZONTAL_RIGHT_OPEN_BOTTOM=41,
    BOTTOM_RIGHT_CORNER_HIDDEN_BOTTOM=42,
    HORIZONTAL_RIGHT_HIDDEN_BOTTOM=43,
    VERTICAL_BOTTOM_OPEN_BOTTOM=46,
    LEFT_EDGE_OPEN_LEFT=64,
    TOP_LEFT_CORNER_OPEN_LEFT=65,
    BOTTOM_LEFT_CORNER_OPEN_LEFT=66,
    HORIZONTAL_LEFT_OPEN_LEFT=67,
    LEFT_EDGE_HIDDEN_LEFT=68,
    TOP_LEFT_CORNER_HIDDEN_LEFT=69,
    BOTTOM_LEFT_CORNER_HIDDEN_LEFT=70,
    HORIZONTAL_LEFT_HIDDEN_LEFT=71,
    HORIZONTAL_TOP_OPEN_LEFT=73,
    VERTICAL_BOTTOM_OPEN_LEFT=74,
    VERTICAL_CENTER_OPEN_LEFT=76,
    VERTICAL_TOP_OPEN_LEFT=77,
    VERTICAL_BOTTOM_HIDDEN_LEFT=78,
    SINGLE_OPEN_LEFT=79,
    RIGHT_EDGE_OPEN_RIGHT=128,
    TOP_RIGHT_CORNER_OPEN_RIGHT=129,
    BOTTOM_RIGHT_CORNER_OPEN_RIGHT=130,
    HORIZONTAL_RIGHT_OPEN_RIGHT=131,
    HORIZONTAL_CENTER_OPEN_RIGHT=132,
    VERTICAL_TOP_OPEN_RIGHT=133,
    VERTICAL_BOTTOM_OPEN_RIGHT=134,
    SINGLE_OPEN_RIGHT=135,
    RIGHT_EDGE_HIDDEN_RIGHT=136,
    TOP_RIGHT_CORNER_HIDDEN_RIGHT=137,
    BOTTOM_RIGHT_CORNER_HIDDEN_RIGHT=138,
    HORIZONTAL_RIGHT_HIDDEN_RIGHT_01=139,
    VERTICAL_TOP_HIDDEN_LEFT=141,
    VERTICAL_BOTTOM_HIDDEN_RIGHT=142,
    SINGLE_HIDDEN_RIGHT=143,
    TOP_RIGHT_CORNER_OPEN_TOP_RIGHT=153,
    HORIZONTAL_RIGHT_HIDDEN_RIGHT_02=155,
    VERTICAL_CENTER_OPEN_LEFT_RIGHT=204,
    VERTIAL_TOP_OPEN_LEFT_RIGHT=205,
    SINGLE_OPEN_LEFT_RIGHT=207
)

TileType = Enum(
    Int32ul,
    NORMAL=1,
    HEAT=2,
    ACID=4,
    ACID_RISE=8,
    ACID_FALL=12
)

IconPriority = Enum(
    Int32sl,
    METROID=-1,
    ACTOR=0,
    SHIP=1,
    ENERGY_CLOUD=2,
    DOOR=3,
    CHOZO_SEAL=4,
    HIDDEN_ITEM=5
)

# BMSMSD
BMSMSD = Struct(
    "_magic" / Const(b"MMSD"),
    "version" / Const(0x00070001, Hex(Int32ul)),
    "scenario" / StrId,
    "tile_size" / construct.Array(2, Float32l),
    "x_tiles" / Int32sl,
    "y_tiles" / Int32sl,
    "map_dimensions" / Struct(
        "bottom_left" / CVector2D,
        "top_right" / CVector2D,
    ),
    "tiles" / make_vector(
        Struct(
            "tile_coordinates" / construct.Array(2, Int32sl),
            "tile_dimension" / Struct(
                "bottom_left" / CVector2D,
                "top_right" / CVector2D,
            ),
            "border_type" / BorderType,
            "tile_type" / TileType,
            "icons" / make_vector(
                Struct(
                    "actor_name" / StrId,
                    "clear_condition" / StrId,
                    "icon" / StrId,
                    "icon_priority" / IconPriority,
                    "coordinates" / CVector3D,
                )
            ),
        )
    ),
    construct.Terminated,
)


class Bmsmsd(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSMSD
