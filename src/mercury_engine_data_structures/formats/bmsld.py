import logging
from typing import Iterator, Tuple

import construct
from construct import Const, Construct, Container, Flag, Float32l, Hex, Int32ul, Struct, Switch

from mercury_engine_data_structures.common_types import CVector3D, Float, StrId, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.crc import crc32
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.collision import collision_formats
from mercury_engine_data_structures.game_check import Game

logger = logging.getLogger(__name__)

FunctionArgument = Struct(
    type=construct.PaddedString(4, 'ascii'),
    value=construct.Switch(
        construct.this.type,
        {
            's': StrId,
            'f': Float,
            'b': Flag,
            'i': Int32ul,
        },
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError)
    )
)

Components = {
    "TRIGGER": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "SPAWNGROUP": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "SPAWNPOINT": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "STARTPOINT": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "MODELUPDATER": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
}

ProperActor = Struct(
    type=StrId,

    position=CVector3D,
    rotation=CVector3D,
    components=make_vector(Struct(
        component_type=StrId,
        command=StrId,
        arguments=make_vector(FunctionArgument),
        # data=construct.Switch(
        #     construct.this.component_type,
        #     Components,
        #     ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx.component_type}", construct.SwitchError),
        # ),
    )),
)

CollisionObject = Struct(
    object_type=StrId,
    data=Switch(
        construct.this.object_type,
        collision_formats,
        ErrorWithMessage(
            lambda ctx: f"Type {ctx.type} not known, valid types are {list(collision_formats.keys())}."
        )
    ),
)

BMSLD = Struct(
    _magic=Const(b"MSLD"),
    version=Const(0x00140001, Hex(Int32ul)),

    unk1=Int32ul,
    unk2=Int32ul,
    unk3=Int32ul,
    unk4=Int32ul,

    objects_a=make_vector(Struct(
        name=StrId,
        unk1=Hex(Int32ul),
        unk2=Hex(Int32ul),
        unk3=Hex(Int32ul),
        unk4=Hex(Int32ul),
        unk5=Hex(Int32ul),
        unk6=Hex(Int32ul),
    )),

    object_b=make_vector(Struct(
        name=StrId,
        unk01=Hex(Int32ul),
        unk02=make_vector(Struct(
            x=Float32l,
            y=Float32l,
            z=Float32l,
        )),
    )),

    objects_c=make_dict(CollisionObject),

    objects_d=make_dict(CollisionObject),

    objects_e=make_vector(Struct(
        name=StrId,
        unk01=StrId,
        unk02=Hex(Int32ul),
        unk03=Hex(Int32ul),
        unk04=Hex(Int32ul),
        unk05=Hex(Int32ul),
        unk06=Hex(Int32ul),
        unk07=Hex(Int32ul),
        unk08=Hex(Int32ul),
        unk09=Float,
        unk10=Float,
        unk11=Hex(Int32ul),

        unk13=StrId,
        unk14=Hex(Int32ul),
    )),

    actors=make_dict(ProperActor)[18],

    sub_areas=make_vector(Struct(
        name=StrId,
        names=make_vector(StrId),
    )),

    rest=construct.GreedyBytes,
)


class Bmsld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLD

    def all_actors(self) -> Iterator[Tuple[int, str, construct.Container]]:
        for layer in self.raw.actors:
            for actor_name, actor in layer.items():
                yield layer, actor_name, actor

    def all_actor_groups(self) -> Iterator[tuple[str, Container]]:
        for sub_area in self.raw.sub_areas:
            yield sub_area.name, sub_area

    def is_actor_in_group(self, group_name: str, actor_name: str) -> bool:
        generator = (area for area in self.raw.sub_areas if area.name == group_name)
        for area in generator:
            return actor_name in area.names
        return False

    def get_actor_group(self, group_name: str) -> Container:
        group = next(
            (sub_area for sub_area_name, sub_area in self.all_actor_groups()
            if sub_area_name == group_name),
            None
        )
        if group is None:
            raise KeyError(f"No group found with name for {group_name}")
        return group

    def all_actor_group_names_for_actor(self, actor_name: str) -> list[str]:
        return [
            actor_group_name
            for actor_group_name, actor_group in self.all_actor_groups()
            if actor_name in actor_group.names
        ]

    def remove_actor_from_group(self, group_name: str, actor_name: str):
        logger.debug("Remove actor %s from group %s", actor_name, group_name)
        group = self.get_actor_group(group_name)
        group.names.remove(actor_name)

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

        collision_camera_groups = [group for group_name, group in self.all_actor_groups()
                                    if compare_func(group_name, collision_camera_name)]
        if len(collision_camera_groups) == 0:
            raise Exception(f"No entity group found for {collision_camera_name}")
        for group in collision_camera_groups:
            logger.debug("Add actor %s to group %s", actor_name, group.name)
            self.insert_into_entity_group(group, actor_name)

    def insert_into_entity_group(self, sub_area: Container, name_to_add: str) -> None:
        # MSR requires to have the names in the sub area list sorted by their crc32 value
        sub_area.names.append(name_to_add)
        sub_area.names.sort(key=crc32)
