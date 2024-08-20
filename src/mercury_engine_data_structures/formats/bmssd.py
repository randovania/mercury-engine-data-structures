import construct
from construct import (
    Byte,
    Const,
    Construct,
    Int8ul,
    Int32ul,
    Int64ul,
    Struct,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import CVector3D, StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.construct_extensions.strings import StaticPaddedString
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSSD = Struct(
    _magic=Const(b"MSSD"),
    unk1=VersionAdapter(),
    part_info=game_check.is_at_most(
        Game.SAMUS_RETURNS,
        make_vector(
            Struct(
                model_name=StrId,
                byte0=Byte,
                byte1=Byte,
                byte2=Byte,
                int3=Int32ul,
                int4=Int32ul,
                farr4=CVector3D,
                farr5=CVector3D,
            )
        ),
        make_vector(
            Struct(
                model_name=StrId,
                byte0=Byte,
                byte1=Byte,
                byte2=Byte,
                int3=Int32ul,
                byte4=Byte,
                farr4=CVector3D,
                farr5=CVector3D,
                farr6=CVector3D,
            )
        ),
    ),
    model_info=make_vector(
        Struct(
            str1=StrId,
            elems=make_vector(
                Struct(
                    float1=CVector3D,
                    float2=CVector3D,
                    float3=CVector3D,
                )
            ),
        )
    ),
    strings_a=make_vector(StrId),
    unk_structs_a=game_check.is_at_most(
        Game.SAMUS_RETURNS,
        make_vector(
            Struct(
                str1=StrId,
                char2=Byte,
                char3=Byte,
                char4=Byte,
                int5=Int32ul,
                int6=Int32ul,
                int7=Int32ul,
                char8=Byte,
                char9=Byte,
                int10=Int32ul,
                float13=CVector3D,
                int11=Int8ul,
            )
        ),
        make_vector(
            Struct(
                str1=StrId,
                char2=Byte,
                char3=Byte,
                char4=Byte,
                int5=Int32ul,
                int6=Int32ul,
                int7=Int32ul,
                char8=Byte,
                char9=Byte,
                int10=Int32ul,
                str11=StaticPaddedString(16, "utf-8"),
                int12=Int32ul,
                float13=CVector3D,
                float14=CVector3D,
                float15=CVector3D,
                int16=Int32ul,
                float17=CVector3D,
            )
        ),
    ),
    strings_b=make_vector(
        StrId,
    ),
    scene_groups=game_check.is_at_most(
        Game.SAMUS_RETURNS,
        make_vector(
            Struct(
                sg_name=StrId,
                models_per_sg=Int32ul,
                model_groups=make_vector(
                    Struct(
                        model_group=Int32ul,
                        models=make_vector(
                            Struct(
                                model_id=Int32ul,
                            )
                        ),
                    )
                ),
            )
        ),
        make_vector(
            Struct(
                str1=StrId,
                int2=Int32ul,
                struct4=make_vector(
                    Struct(
                        int1=Int32ul,
                        long3=make_vector(Int64ul),
                    )
                ),
            )
        ),
    ),
    rest=construct.GreedyBytes,
).compile()


class Bmssd(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSSD
