from __future__ import annotations

from typing import TYPE_CHECKING

from construct.core import (
    Const,
    Flag,
    Struct,
    Terminated,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_dict, make_vector

if TYPE_CHECKING:
    from construct import Construct

    from mercury_engine_data_structures.game_check import Game

Camera_Subarea_Setup = Struct(
    "environment_preset" / StrId, # bmsev
    "sound" / StrId, # bmses

    # the following 3 are almost always none, possibly extra groups?
    "unk2" / StrId, # lg or eg, only used in cockpit/credits scenarios
    "entity_group" / StrId,
    "block_group" / StrId,

    "cc_names" / make_vector(StrId),
    "actors_in_scenario" / make_vector(StrId),
    "cutscenes" / make_vector(StrId), # bmscu files
    "collision_layer" / StrId, # bmscd: entry in collision_layer
    "unk9" / Flag,
)  # fmt: skip

CollisionCamera = Struct("setups" / make_dict(Camera_Subarea_Setup))

BMSSA = Struct(
    "_magic" / Const(b"MSSA"),
    "version" / VersionAdapter("1.22.0"),
    "cameras" / make_dict(CollisionCamera),
    Terminated,
)


class Bmssa(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSSA
