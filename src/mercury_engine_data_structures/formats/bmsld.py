from __future__ import annotations

import copy
import logging
from enum import IntEnum
from typing import TYPE_CHECKING

import construct
from construct import Const, Construct, Container, Flag, Hex, Int32ul, ListContainer, Struct, Switch

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import (
    CVector3D,
    Float,
    StrId,
    Vec3,
    VersionAdapter,
    make_dict,
    make_vector,
)
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.construct_extensions.strings import StaticPaddedString
from mercury_engine_data_structures.crc import crc32
from mercury_engine_data_structures.formats.collision import CollisionEntry, collision_formats

if TYPE_CHECKING:
    from collections.abc import Iterator

    from mercury_engine_data_structures.game_check import Game

logger = logging.getLogger(__name__)

FunctionArgument = Struct(
    "type" / StaticPaddedString(4, "ascii"),
    "value"
    / construct.Switch(
        construct.this.type,
        {
            "s": StrId,
            "f": Float,
            "b": Flag,
            "i": Int32ul,
        },
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError),
    ),
)

ProperActor = Struct(
    "type" / StrId,
    "position" / CVector3D,
    "rotation" / CVector3D,
    "component_functions"
    / make_vector(
        Struct(
            "component_type" / StrId,
            "command" / StrId,
            "arguments" / make_vector(FunctionArgument),
        )
    ),
)

CollisionObject = Struct(
    "object_type" / StrId,
    "data"
    / Switch(
        construct.this.object_type,
        collision_formats,
        ErrorWithMessage(lambda ctx: f"Type {ctx.type} not known, valid types are {list(collision_formats.keys())}."),
    ),
)

ExtraActors = Struct(
    "actors" / make_vector(Struct("name" / StrId)),
)


BMSLD = Struct(
    "_magic" / Const(b"MSLD"),
    "version" / VersionAdapter("1.20.0"),
    "unk1" / CVector3D,
    "unk2" / Float,
    # locations where Samus gets repositioned after a cutscene/collecting dna, etc
    "landmarks"
    / make_vector(
        Struct(
            "name" / StrId,
            "position" / CVector3D,
            "rotation" / CVector3D,
        )
    ),
    # paths that enemies follow (could be bounds?)
    "enemy_paths"
    / make_vector(
        Struct(
            "name" / StrId,
            "unk01" / Hex(Int32ul),
            "coordinates" / make_vector(CVector3D),
        )
    ),
    # areas of influence for enemies
    "logic_shapes" / make_dict(CollisionObject),
    # areas for spawngroups
    "spawn_groups" / make_dict(CollisionObject),
    # boss camera data
    "boss_cameras"
    / make_vector(
        Struct(
            "name" / StrId,
            "unk01" / StrId,
            "unk02" / Hex(Int32ul),
            "unk03" / Hex(Int32ul),
            "unk04" / Hex(Int32ul),
            "unk05" / Hex(Int32ul),
            "unk06" / Hex(Int32ul),
            "unk07" / Hex(Int32ul),
            "unk08" / Hex(Int32ul),
            "position" / CVector3D,
            "type" / StrId,
            "unk14" / Hex(Int32ul),
        )
    ),
    # layers for actors
    "actor_layers" / make_dict(ProperActor)[18],
    # collision_cameras and groups
    "sub_areas" / make_dict(make_vector(StrId)),
    # only used in s000_mainmenu, s010_cockpit, s020_credits
    "extra_data" / construct.Optional(make_dict(ExtraActors)),
    construct.Terminated,
).compile()


class ActorLayer(IntEnum):
    TRIGGER = 0
    ENV_TRIGGER = 2
    SPAWNGROUP = 3
    SPAWNPOINT = 4
    STARTPOINT = 5
    PASSIVE = 9
    PLATFORM = 10
    DOOR = 15
    CHOZO_SEAL = 16
    HIDDEN_POWERUP = 17


class BmsldActor:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    @property
    def actor_type(self) -> str:
        return self._raw.type

    @actor_type.setter
    def actor_type(self, value: str) -> None:
        self._raw.type = value

    @property
    def position(self) -> Vec3:
        return self._raw.position

    @position.setter
    def position(self, value: Vec3) -> None:
        self._raw.position = value

    @property
    def rotation(self) -> Vec3:
        return self._raw.rotation

    @rotation.setter
    def rotation(self, value: Vec3) -> None:
        self._raw.rotation = value

    def get_component_function(self, component_idx: int = 0) -> ComponentFunction:
        return ComponentFunction(self._raw.component_functions[component_idx])


ArgumentType = int | float | str | bool

ARGUMENT_TYPES = {
    "s": str,
    "f": float,
    "b": bool,
    "i": int,
}


class ComponentFunction:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    def __repr__(self) -> str:
        arguments = [repr(arg.value) for arg in self._raw.arguments]
        arg_repr = ", ".join(arguments)
        return f"{self._raw.component_type}.{self._raw.command}({arg_repr})"

    def set_argument(self, argument_idx: int, value: ArgumentType) -> None:
        argument = self._raw.arguments[argument_idx]
        expected_type = ARGUMENT_TYPES[argument.type]
        if not isinstance(value, expected_type):
            raise TypeError(f"Invalid argument type: expected {expected_type}, got {type(value)} ({value})")
        argument.value = value


class Bmsld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLD

    def all_actors(self) -> Iterator[tuple[ActorLayer, str, BmsldActor]]:
        for layer in self.raw.actor_layers:
            for actor_name, actor in layer.items():
                yield layer, actor_name, actor

    @property
    def actor_groups(self) -> dict[str, list[str]]:
        return self.raw.sub_areas

    @actor_groups.setter
    def actor_groups(self, value: dict[str, list[str]]) -> None:
        self.raw.sub_areas = value

    def is_actor_in_group(self, group_name: str, actor_name: str) -> bool:
        return actor_name in self.actor_groups[group_name]

    def get_actor_group(self, group_name: str) -> Container:
        group = next((sub_area for sub_area in self.actor_groups if sub_area == group_name), None)
        if group is None:
            raise KeyError(f"No group found with name for {group_name}")
        return group

    def all_actor_group_names_for_actor(self, actor_name: str) -> list[str]:
        return [group_name for group_name, group in self.actor_groups.items() if actor_name in group]

    def remove_actor_from_group(self, group_name: str, actor_name: str):
        logger.debug("Remove actor %s from group %s", actor_name, group_name)
        self.actor_groups[group_name].remove(actor_name)

    def remove_actor_from_all_groups(self, actor_name: str):
        group_names = self.all_actor_group_names_for_actor(actor_name)
        for group_name in group_names:
            self.remove_actor_from_group(group_name, actor_name)

    def add_actor_to_entity_groups(self, collision_camera_name: str, actor_name: str, all_groups: bool = False):
        """
        Adds an actor to either all entity groups or one entity group, which follow the name pattern of eg_SubArea_NAME.
        In case an actor needs to be added to an entity group not following this name pattern
        use `insert_into_sub_area`.

        collision_camera_name: Name of the collision camera to find the entity groups for
        actor_name: Actor name to add to the entity group
        all_groups: A boolean which defines if the actor should be added to all entity groups starting with the name
                   pattern or just to one entity group matching the name pattern exactly
        """

        def compare_func(first: str, second: str) -> bool:
            if all_groups:
                return first.startswith(f"eg_SubArea_{second}")
            else:
                return first == f"eg_SubArea_{second}"

        collision_camera_groups = [group for group in self.actor_groups if compare_func(group, collision_camera_name)]
        if len(collision_camera_groups) == 0:
            raise Exception(f"No entity group found for {collision_camera_name}")
        for group in collision_camera_groups:
            logger.debug("Add actor %s to group %s", actor_name, group)
            self.insert_into_entity_group(group, actor_name)

    def insert_into_entity_group(self, sub_area: Container, name_to_add: str) -> None:
        # MSR requires to have the names in the sub area list sorted by their crc32 value
        entity_group = self.actor_groups[sub_area]
        entity_group.append(name_to_add)
        entity_group.sort(key=crc32)

    def _get_layer(self, layer: ActorLayer) -> ListContainer:
        """Returns a layer of actors"""
        return self.raw.actor_layers[layer]

    def _check_if_actor_exists(self, layer: ActorLayer, actor_name: str) -> None:
        if actor_name not in self._get_layer(layer):
            raise KeyError(f"No actor named '{actor_name}' found in '{layer}!'")

    def get_actor(self, layer: ActorLayer, actor_name: str) -> BmsldActor:
        """Returns an actor given a layer and an actor name"""
        self._check_if_actor_exists(layer, actor_name)
        return BmsldActor(self.raw.actor_layers[layer][actor_name])

    def remove_actor(self, layer: ActorLayer, actor_name: str) -> None:
        """Deletes an actor given a layer and an actor name"""
        self._check_if_actor_exists(layer, actor_name)
        self._get_layer(layer).pop(actor_name)
        self.remove_actor_from_all_groups(actor_name)

    def copy_actor(
        self,
        position: list[float],
        template_actor: BmsldActor,
        new_name: str,
        layer: ActorLayer,
        offset: tuple = (0, 0, 0),
    ) -> BmsldActor:
        """
        Copies an actor to a new position

        param position: the x, y, z position for the copied actor
        param template_actor: the actor being copied
        param new_name: the name for the copied actor
        param layer: the layer the copied actor will be added to
        param offset: adds an additional offset the copied actor's coordinates

        """
        new_actor = BmsldActor(copy.deepcopy(template_actor))
        self.raw.actor_layers[layer][new_name] = new_actor._raw
        new_actor.position = Vec3([p + o for p, o in zip(position, offset)])

        return new_actor

    def get_logic_shape(self, logic_shape: str) -> CollisionEntry:
        """Returns a logic shape by name"""
        return CollisionEntry(self.raw["logic_shapes"][logic_shape])
