from __future__ import annotations

from typing import TYPE_CHECKING

import construct
from construct.core import (
    Const,
    Construct,
    Struct,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import (
    StrId,
    VersionAdapter,
    make_vector,
)
from mercury_engine_data_structures.formats.collision import CollisionEntry, CollisionEntryConstruct

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

CollisionLayer = Struct(
    "name" / StrId,
    "entries" / make_vector(CollisionEntryConstruct),
)

PartsComponent = Struct(
    "group" / StrId,
    "components" / make_vector(Struct("name" / StrId)),
)

BMSCC = Struct(
    "_magic" / Const(b"MSCD"),
    "_version"
    / game_check.is_sr_or_else(
        VersionAdapter("1.13.0"),
        VersionAdapter("1.16.0"),
    ),
    "layers" / make_vector(CollisionLayer),
    "parts" / construct.Optional(make_vector(PartsComponent)),
    construct.Terminated,
)


class Bmscc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCC

    # Bmscc has one entry per collision_camera, Bmscd has one entry per file
    def get_entry(self, entry_idx: int = 0) -> CollisionEntry:
        return CollisionEntry(self.raw.layers[0].entries[entry_idx])
