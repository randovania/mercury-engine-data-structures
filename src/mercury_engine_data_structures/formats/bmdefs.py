import construct
from construct import (
    Const,
    Construct,
    Enum,
    Float32l,
    Int8ul,
    Int16ul,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, make_vector
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

Status = Enum(
    Int8ul,
    DISABLED=0,
    ENABLED=1,
)

EnemiesStruct = Struct(
    "enemy_name" / StrId,
    "areas" / make_vector(Struct(
        "area_name" / StrId,
        "layers" / make_vector(Struct(
            "layer_name" / StrId,
            "states" / make_vector(Struct(
                "type" / StrId,
                value=construct.Switch(
                    construct.this.type,
                    {
                        'COMBAT': Struct(
                            "unk1" / Int32ul,
                            "priority" / Int32ul,
                            "file_name" / StrId,
                            "fade_in" / Float32l,
                            "start_delay" / Float32l,
                            "volume" / Float32l,
                            "unk2" / Int32ul,
                            "unk3" / Int32ul,
                            "unk4" / Int32ul,
                            "status" / Status,
                            "float1" / Int32ul,
                            "inner_states" / make_vector(Struct(
                                "type" / StrId,
                                "unk1" / Float32l,
                            ))

                        ),
                        'DEATH': Struct(
                            "unk1" / Int32ul,
                            "priority" / Int32ul,
                            "file_name" / StrId,
                            "start_delay" / Float32l,
                            "fade_out" / Float32l,
                            "volume" / Float32l,
                            "unk2" / Int32ul,
                            "unk3" / Int32ul,
                            "unk4" / Int32ul,
                            "status" / Status,
                            "float1" / Float32l,
                            "unk5" / Int32ul,
                        ),
                    },
                )
            )),
        )),
    ))
)

BMDEFS = Struct(
    _magic=Const(b"MDEF"),
    major_version=Int16ul,
    minor_version=Int16ul,
    unk1=Int32ul,
    sounds=make_vector(Struct(
            "sound_name" / StrId,
            "unk1" / Int32ul,
            "priority" / Int32ul,
            "file_path" / StrId,
            "unk2" / Int32ul,
            "unk3" / Int32ul,
            "unk4" / Int32ul,
            "fadein" / Float32l,
            "fadeout" / Float32l,
            "volume" / Float32l,
            "status" / Status,
            "float1" / Float32l
    )),
    unk2=Int32ul,
    enemies_list=make_vector(EnemiesStruct),
    rest=construct.GreedyBytes,
)

class Bmdefs(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMDEFS
