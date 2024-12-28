from __future__ import annotations

import copy
import logging
from enum import IntEnum
from typing import TYPE_CHECKING

import construct
from construct import Const, Construct, Container, Flag, Hex, Int32ul, Struct, Switch

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import CVector3D, Float, StrId, VersionAdapter, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.construct_extensions.strings import StaticPaddedString
from mercury_engine_data_structures.crc import crc32
from mercury_engine_data_structures.formats.collision import collision_formats

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
    "components"
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
    "group" / StrId,
    "actors" / make_vector(Struct("name" / StrId)),
)


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


BMSLD = Struct(
    "_magic" / Const(b"MSLD"),
    "version" / VersionAdapter("1.20.0"),
    "unk1" / CVector3D,
    "unk2" / Float,
    "objects_a"
    / make_vector(
        Struct(
            "name" / StrId,
            "position" / CVector3D,
            "rotation" / CVector3D,
        )
    ),
    "enemy_paths"
    / make_vector(
        Struct(
            "name" / StrId,
            "unk01" / Hex(Int32ul),
            "coordinates" / make_vector(CVector3D),
        )
    ),
    "logic_shapes" / make_dict(CollisionObject),
    "spawn_groups" / make_dict(CollisionObject),
    "bosses"
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
            "position?" / CVector3D,
            "type" / StrId,
            "unk14" / Hex(Int32ul),
        )
    ),
    "actor_layers" / make_dict(ProperActor)[18],
    "sub_areas"
    / make_vector(
        Struct(
            "name" / StrId,
            "objects" / make_vector(StrId),
        )
    ),
    "extra_sub_area" / construct.Optional(make_vector(ExtraActors)),
    construct.Terminated,
).compile()


class Bmsld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLD

    def all_actors(self) -> Iterator[tuple[int, str, construct.Container]]:
        for layer in self.raw.actor_layers:
            for actor_name, actor in layer.items():
                yield layer, actor_name, actor

    def all_actor_groups(self) -> Iterator[tuple[str, Container]]:
        for sub_area in self.raw.sub_areas:
            yield sub_area.name, sub_area

    def is_actor_in_group(self, group_name: str, actor_name: str) -> bool:
        generator = (area for area in self.raw.sub_areas if area.name == group_name)
        for area in generator:
            return actor_name in area.objects
        return False

    def get_actor_group(self, group_name: str) -> Container:
        group = next(
            (sub_area for sub_area_name, sub_area in self.all_actor_groups() if sub_area_name == group_name), None
        )
        if group is None:
            raise KeyError(f"No group found with name for {group_name}")
        return group

    def all_actor_group_names_for_actor(self, actor_name: str) -> list[str]:
        return [
            actor_group_name
            for actor_group_name, actor_group in self.all_actor_groups()
            if actor_name in actor_group.objects
        ]

    def remove_actor_from_group(self, group_name: str, actor_name: str):
        logger.debug("Remove actor %s from group %s", actor_name, group_name)
        group = self.get_actor_group(group_name)
        group.objects.remove(actor_name)

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

        collision_camera_groups = [
            group for group_name, group in self.all_actor_groups() if compare_func(group_name, collision_camera_name)
        ]
        if len(collision_camera_groups) == 0:
            raise Exception(f"No entity group found for {collision_camera_name}")
        for group in collision_camera_groups:
            logger.debug("Add actor %s to group %s", actor_name, group.name)
            self.insert_into_entity_group(group, actor_name)

    def insert_into_entity_group(self, sub_area: Container, name_to_add: str) -> None:
        # MSR requires to have the names in the sub area list sorted by their crc32 value
        sub_area.objects.append(name_to_add)
        sub_area.objects.sort(key=crc32)

    def get_layer(self, layer: ActorLayer) -> Container:
        """Returns a layer of actors using an enum"""
        return self.raw.actor_layers[layer]

    def _check_if_actor_exists(self, layer: ActorLayer, actor_name: str) -> None:
        if actor_name not in self.get_layer(layer):
            raise KeyError(f"No actor named '{actor_name}' found in '{layer}!'")

    def get_actor(self, layer: ActorLayer, actor_name: str) -> Container:
        """Returns an actor given a layer using an enum and an actor name"""
        self._check_if_actor_exists(layer, actor_name)
        return self.raw.actor_layers[layer][actor_name]

    def remove_actor(self, layer: ActorLayer, actor_name: str) -> None:
        """Deletes an actor given a layer using an enum and an actor name"""
        self._check_if_actor_exists(layer, actor_name)
        self.get_layer(layer).pop(actor_name)
        self.remove_actor_from_all_groups(actor_name)

    def copy_actor(
        self,
        coords: list[float],
        template_actor: Container,
        new_name: str,
        layer: ActorLayer,
        offset: tuple = (0, 0, 0),
    ) -> Container:
        """Copies an actor to a new position"""
        new_actor = copy.deepcopy(template_actor)
        self.raw.actor_layers[layer][new_name] = new_actor
        for i in range(2):
            new_actor["position"][i] = coords[i] + offset[i]

        return new_actor

    def get_logic_shape(self, logic_shape: str) -> Container:
        """Returns a logic shape by name"""
        return self.raw["logic_shapes"][logic_shape]

    ArgumentValue = int | float | str | bool

    def set_argument(
        self, layer_idx: int, actor_name: str, component_idx: int, argument_idx: int, value: ArgumentValue
    ):
        """
        Modify the value of an argument for an actor's component field

        param layer_idx: the layer the actor is in, numbered 0-17
        param actor_name: the actor to be modified
        param component_idx: the index for the list of components of the actor
        param argument_idx: the index of argument for the the component
        param value: the value of the specified argument. can be an integer, float, string, or bool

        """
        actor = self.get_actor(layer_idx, actor_name)
        actor["components"][component_idx]["arguments"][argument_idx]["value"] = value
