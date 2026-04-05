from __future__ import annotations

from enum import Enum

import construct
from construct.core import (
    Const,
    Construct,
    Container,
    Flag,
    Float32l,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_dict, make_vector
from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.game_check import Game


class StateType(str, Enum):
    COMBAT = "COMBAT"
    DEATH = "DEATH"


class InnerStateType(str, Enum):
    DEATH = "DEATH"
    RELAX = "RELAX"


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
                            "inner_states" / make_dict(Float32l)
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
                            "inner_states" / make_dict(EnumAdapter(InnerStateType, StrId), Float32l)
                        ),
                    },
                )
            )),
        )),
    ))
)  # fmt: skip

BMDEFS = Struct(
    "_magic" / Const(b"MDEF"),
    "version" / VersionAdapter("1.5.0"),
    "_number_of_sounds" / Int32ul,
    "sounds"
    / make_vector(
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
    "_number_of_enemy_groups" / Int32ul,
    "enemies_list" / make_vector(EnemyStruct),
    construct.Terminated,
)


class EnemyStates:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def state_type(self) -> StateType:
        return self._raw.type

    @state_type.setter
    def state_type(self, value: StateType) -> None:
        self._raw.type = value

    def get_sound_properties(self) -> EnemySounds:
        return EnemySounds(self._raw.properties)


class EnemyLayers:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def layer_name(self) -> str:
        return self._raw.layer_name

    @layer_name.setter
    def layer_name(self, value: str) -> None:
        self._raw.layer_name = value

    def get_state(self, state_idx: int) -> EnemyStates:
        return EnemyStates(self._raw.states[state_idx])


class Areas:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def area_name(self) -> str:
        return self._raw.area_name

    @area_name.setter
    def area_name(self, value: str) -> None:
        self._raw.area_name = value

    def get_layer(self, layer_idx: int) -> EnemyLayers:
        return EnemyLayers(self._raw.layers[layer_idx])


class EnemiesList:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def enemy_name(self) -> str:
        return self._raw.enemy_name

    @enemy_name.setter
    def enemy_name(self, value: str) -> None:
        self._raw.enemy_name = value

    @property
    def start_delay(self) -> float:
        return self._raw.start_delay

    @start_delay.setter
    def start_delay(self, value: float) -> None:
        self._raw.start_delay = value

    @property
    def inner_states(self) -> dict[InnerStateType, float]:
        return self._raw.inner_states

    @inner_states.setter
    def inner_states(self, value: dict[InnerStateType, float]) -> None:
        for name, value in value.items():
            self._raw.inner_states[name] = value

    def get_area(self, area_idx: int) -> Areas:
        return Areas(self._raw.areas[area_idx])


class Sounds:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    @property
    def sound_name(self) -> str:
        return self._raw.sound_name

    @sound_name.setter
    def sound_name(self, value: str) -> None:
        self._raw.sound_name = value

    @property
    def priority(self) -> int:
        return self._raw.priority

    @priority.setter
    def priority(self, value: int) -> None:
        self._raw.priority = value

    @property
    def file_path(self) -> str:
        return self._raw.file_path

    @file_path.setter
    def file_path(self, value: str) -> None:
        self._raw.file_path = value

    @property
    def fade_in(self) -> float:
        return self._raw.fade_in

    @fade_in.setter
    def fade_in(self, value: float) -> None:
        self._raw.fade_in = value

    @property
    def fade_out(self) -> float:
        return self._raw.fade_out

    @fade_out.setter
    def fade_out(self, value: float) -> None:
        self._raw.fade_out = value

    @property
    def volume(self) -> float:
        return self._raw.volume

    @volume.setter
    def volume(self, value: float) -> None:
        self._raw.volume = value

    @property
    def environment_sfx_volume(self) -> float:
        return self._raw.environment_sfx_volume

    @environment_sfx_volume.setter
    def environment_sfx_volume(self, value: float) -> None:
        self._raw.environment_sfx_volume = value


class EnemySounds(Sounds):
    @property
    def start_delay(self) -> float:
        return self._raw.start_delay

    @start_delay.setter
    def start_delay(self, value: float) -> None:
        self._raw.start_delay = value

    @property
    def inner_states(self) -> dict[InnerStateType, float]:
        return self._raw.inner_states

    @inner_states.setter
    def inner_states(self, value: dict[InnerStateType, float]) -> None:
        for name, value in value.items():
            self._raw.inner_states[name] = value


class Bmdefs(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        if target_game == Game.SAMUS_RETURNS:
            return BMDEFS
        else:
            return standard_format.game_model("sound::CMusicManager", "4.0.2")

    def get_sound(self, sound_idx: int) -> Sounds:
        return Sounds(self.raw.sounds[sound_idx])

    def get_enemy(self, enemy_idx: int) -> EnemiesList:
        return EnemiesList(self.raw.enemies_list[enemy_idx])
