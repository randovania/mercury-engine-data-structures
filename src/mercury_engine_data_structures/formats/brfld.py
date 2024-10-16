import functools
import logging
from collections.abc import Iterator
from enum import Enum
from typing import Any

import construct

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

logger = logging.getLogger(__name__)

ActorLink = str


class ActorLayer(str, Enum):
    ENTITIES = "rEntitiesLayer"
    SOUNDS = "rSoundsLayer"
    LIGHTS = "rLightsLayer"


class Brfld(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return standard_format.game_model("CScenario", "49.0.2")

    def actors_for_sublayer(self, sublayer_name: str, actor_layer: ActorLayer = ActorLayer.ENTITIES) -> dict:
        """
        Gets the actors in a sublayer

        param sublayer_name: the name of the sublayer to get the actors of
        param actor_layer: the actor_layer the sublayer is in
        returns: the actors in the sublayer"""
        return self.raw.Root.pScenario[actor_layer].dctSublayers[sublayer_name].dctActors

    def sublayers_for_actor_layer(self, actor_layer: ActorLayer = ActorLayer.ENTITIES) -> Iterator[str]:
        """
        Iterably gets the names of every sublayer in an actor layer

        param actor_layer: the actor layer to get the sublayers of
        returns: the name of each sublayer"""
        yield from self.raw.Root.pScenario[actor_layer].dctSublayers.keys()

    def all_actors_in_actor_layer(
        self, actor_layer: ActorLayer = ActorLayer.ENTITIES
    ) -> Iterator[tuple[str, str, construct.Container]]:
        """
        Iterably gets every actor in an actor layer

        param actor_layer: the actor layer to get the actors of
        returns: each actor in the actor layer"""
        for sublayer_name, sublayer in self.raw.Root.pScenario[actor_layer].dctSublayers.items():
            for actor_name, actor in sublayer.dctActors.items():
                yield sublayer_name, actor_name, actor

    def follow_link(self, link: str) -> Any | None:
        """
        Gets the object a link is referencing

        param link: the link to follow
        returns: the part of the BRFLD link is referencing"""
        if link != "{EMPTY}":
            result = self.raw
            for part in link.split(":"):
                result = result[part]
            return result

    def link_for_actor(
        self, actor_name: str, sublayer_name: str = "default", actor_layer: ActorLayer = ActorLayer.ENTITIES
    ) -> ActorLink:
        """
        Builds a link for an actor

        param actor_name: the name of the actor
        sublayer_name: the name of the sublayer the actor is in
        actor_layer: the actor layer the actor is in
        returns: a string representing where in the BRFLD the actor is"""
        return ":".join(
            ["Root", "pScenario", actor_layer, "dctSublayers", sublayer_name, "dctActors", actor_name]
        )

    def actor_groups_for_actor_layer(self, actor_layer: ActorLayer = ActorLayer.ENTITIES) -> Iterator[str]:
        """
        Iterably gets every actor group in an actor layer

        param actor_layer: the actor layer to get the actor groups of
        returns: each actor group in the actor layer"""
        yield from self.raw.Root.pScenario[actor_layer].dctActorGroups.keys()

    def get_actor_group(self, group_name: str, actor_layer: ActorLayer = ActorLayer.ENTITIES) -> list[ActorLink]:
        """
        Gets an actor group

        param group_name: the name of the actor group
        param actor_layer: the actor layer the actor group is in
        returns: a list of links to actors"""
        return self.raw.Root.pScenario[actor_layer].dctActorGroups[group_name]

    def is_actor_in_group(
        self,
        group_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer: ActorLayer = ActorLayer.ENTITIES,
    ) -> bool:
        """
        Checks if an actor is in an actor group

        param group_name: the name of the actor group
        param actor_name: the name of the actor
        param sublayer_name: the name of the sublayer the actor is in
        param actor_layer: the actor layer the actor is in
        returns: true if the actor is in the actor group, false otherwise"""
        return self.link_for_actor(actor_name, sublayer_name, actor_layer) in self.get_actor_group(
            group_name, actor_layer
        )

    def add_actor_to_group(
        self,
        group_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer: ActorLayer = ActorLayer.ENTITIES,
    ) -> None:
        """
        Adds an actor to an actor group

        param group_name: the name of the actor group
        param actor_name: the name of the actor
        param sublayer_name: the name of the sublayer the actor is in
        param actor_layer: the actor layer the actor is in"""
        group = self.get_actor_group(group_name, actor_layer)
        actor_link = self.link_for_actor(actor_name, sublayer_name, actor_layer)
        if actor_link not in group:
            group.append(actor_link)
        else:
            raise ValueError(f"Actor {actor_link} is already in actor group {group_name}")

    def remove_actor_from_group(
        self,
        group_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer: ActorLayer = ActorLayer.ENTITIES,
    ) -> None:
        """
        Removes an actor from an actor group

        param group_name: the name of the actor group
        param actor_name: the name of the actor
        param sublayer_name: the name of the sublayer the actor is in
        param actor_layer: the actor layer the actor is in"""
        group = self.get_actor_group(group_name, actor_layer)
        actor_link = self.link_for_actor(actor_name, sublayer_name, actor_layer)
        if actor_link in group:
            group.remove(actor_link)
        else:
            raise ValueError(f"Actor {actor_link} is not in actor group {group_name}")

    def add_actor_to_actor_groups(
        self,
        collision_camera_name: str,
        actor_name: str,
        sublayer_name: str = "default",
        actor_layer: ActorLayer = ActorLayer.ENTITIES,
    ) -> None:
        """
        Adds an actor to all actor groups starting with collision_camera_name

        param collision_camera_name: the name of the collision camera group
        param actor_name: the name of the actor to add to the group
        param sublayer_name: the name of the sublayer the actor belongs to
        param actor_layer: the actor layer the sublayer belongs to
        """
        collision_camera_groups = [
            group for group in self.actor_groups_for_actor_layer(actor_layer) if group.startswith(collision_camera_name)
        ]
        for group in collision_camera_groups:
            logger.debug("Add actor %s to group %s", actor_name, group)
            self.add_actor_to_group(group, actor_name, sublayer_name, actor_layer)
