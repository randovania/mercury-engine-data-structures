import functools
import logging
from enum import Enum, auto
from typing import Iterator, List, Tuple

import construct

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

logger = logging.getLogger(__name__)


class ActorLayer(Enum):
    ENTITIES = auto
    SOUNDS = auto
    LIGHTS = auto


class Brfld(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return standard_format.game_model("CScenario", "49.0.2")

    def actors_for_sublayer(self, sublayer_name: str, actor_layer_name: ActorLayer = ActorLayer.ENTITIES) -> dict:
        return self.raw.Root.pScenario[actor_layer_name].dctSublayers[sublayer_name].dctActors

    def sublayers_for_actor_layer(self, actor_layer_name: ActorLayer = ActorLayer.ENTITIES) -> Iterator[str]:
        yield from self.raw.Root.pScenario[actor_layer_name].dctSublayers.keys()

    def all_actors_in_actor_layer(
        self, actor_layer_name: ActorLayer = ActorLayer.ENTITIES
    ) -> Iterator[Tuple[str, str, construct.Container]]:
        for sublayer_name, sublayer in self.raw.Root.pScenario[actor_layer_name].dctSublayers.items():
            for actor_name, actor in sublayer.dctActors.items():
                yield sublayer_name, actor_name, actor

    def follow_link(self, link: str):
        if link != "{EMPTY}":
            result = self.raw
            for part in link.split(":"):
                result = result[part]
            return result

    def link_for_actor(
        self, actor_name: str, sublayer_name: str = "default", actor_layer_name: ActorLayer = ActorLayer.ENTITIES
    ) -> str:
        return ":".join(["Root", "pScenario", actor_layer_name, "dctSublayers", sublayer_name, "dctActors", actor_name])

    def actor_groups_for_actor_layer(self, actor_layer_name: ActorLayer = ActorLayer.ENTITIES) -> Iterator[str]:
        yield from self.raw.Root.pScenario[actor_layer_name].dctActorGroups.keys()

    def get_actor_group(self, group_name: str, actor_layer_name: ActorLayer = ActorLayer.ENTITIES) -> List[str]:
        return self.raw.Root.pScenario[actor_layer_name].dctActorGroups[group_name]

    def is_actor_in_group(
        self,
        group_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer_name: ActorLayer = ActorLayer.ENTITIES,
    ) -> bool:
        return self.link_for_actor(actor_name, sublayer_name, actor_layer_name) in self.get_actor_group(group_name)

    def add_actor_to_group(
        self,
        group_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer_name: ActorLayer = ActorLayer.ENTITIES,
    ):
        group = self.get_actor_group(group_name, actor_layer_name)
        actor_link = self.link_for_actor(actor_name, sublayer_name, actor_layer_name)
        if actor_link not in group:
            group.append(actor_link)

    def remove_actor_from_group(
        self,
        group_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer_name: ActorLayer = ActorLayer.ENTITIES,
    ):
        group = self.get_actor_group(group_name, actor_layer_name)
        actor_link = self.link_for_actor(actor_name, sublayer_name, actor_layer_name)
        if actor_link in group:
            group.remove(actor_link)

    def add_actor_to_entity_groups(
        self,
        collision_camera_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer_name: ActorLayer = ActorLayer.ENTITIES,
    ):
        """
        adds an actor to all entity groups starting with "eg_" + collision_camera_name

        param collision_camera_name: name of the collision camera group
        (prefix "eg_" is added to find the entity groups)
        param actor_name: name of the actor to add to the group
        param sublayer_name: name of the sublayer the actor belongs to
        param actor_layer_name: the actor layer the sublayer belongs to
        """
        collision_camera_groups = [
            group for group in self.all_actor_groups() if group.startswith(f"eg_{collision_camera_name}")
        ]
        for group in collision_camera_groups:
            logger.debug("Add actor %s to group %s", actor_name, group)
            self.add_actor_to_group(group, actor_name, sublayer_name, actor_layer_name)
