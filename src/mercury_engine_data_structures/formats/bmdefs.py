from __future__ import annotations

import construct
from construct import (
    Const,
    Construct,
    Flag,
    Float32l,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

EnemyStruct = Struct(
    "enemy_name" / StrId,
    "areas" / make_vector(Struct(
        "area_name" / StrId,
        "layers" / make_vector(Struct(
            "layer_name" / StrId,
            "states" / make_vector(Struct(
                "type" / StrId,
                "properties" / construct.Switch(
                    construct.this.type,
                    {
                        'COMBAT': Struct(
                            "unk1" / Int32ul,
                            "priority" / Int32ul,
                            "file_path" / StrId,
                            "fade_in" / Float32l,
                            "start_delay" / Float32l,
                            "volume" / Float32l,
                            "unk2" / Int32ul,
                            "unk3" / Int32ul,
                            "unk4" / Int32ul,
                            "unk_bool" / Flag,
                            "environment_sfx_volume" / Float32l,
                            "inner_states" / make_vector(Struct(
                                "type" / StrId,
                                "unk1" / Float32l,
                            ))
                        ),
                        'DEATH': Struct(
                            "unk1" / Int32ul,
                            "priority" / Int32ul,
                            "file_path" / StrId,
                            "start_delay" / Float32l,
                            "fade_out" / Float32l,
                            "volume" / Float32l,
                            "unk2" / Int32ul,
                            "unk3" / Int32ul,
                            "unk4" / Int32ul,
                            "unk_bool" / Flag,
                            "environment_sfx_volume" / Float32l,
                            "inner_states" / make_vector(Struct(
                                "type" / StrId,
                                "unk1" / Float32l,
                            ))
                        ),
                    },
                )
            )),
        )),
    ))
)  # fmt: skip

BMDEFS = Struct(
    _magic=Const(b"MDEF"),
    version=VersionAdapter("1.5.0"),
    unk1=Int32ul,
    sounds=make_vector(
        Struct(
            "sound_name" / StrId,
            "unk1" / Int32ul,
            "priority" / Int32ul,
            "file_path" / StrId,
            "unk2" / Int32ul,
            "unk3" / Int32ul,
            "unk4" / Int32ul,
            "fade_in" / Float32l,
            "fade_out" / Float32l,
            "volume" / Float32l,
            "unk_bool" / Flag,
            "environment_sfx_volume" / Float32l,
        )
    ),  # fmt: skip
    unk2=Int32ul,
    enemies_list=make_vector(EnemyStruct),
    rest=construct.GreedyBytes,
)


class Bmdefs(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        if target_game == Game.SAMUS_RETURNS:
            return BMDEFS
        else:
            return standard_format.game_model("sound::CMusicManager", "4.0.2")
