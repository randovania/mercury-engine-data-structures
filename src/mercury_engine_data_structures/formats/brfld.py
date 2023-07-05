from typing import Iterator, Tuple, List
import logging

import construct

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

logger = logging.getLogger(__name__)
BRFLD = standard_format.game_model('CScenario', 0x02000031).compile()


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BRFLD

    def actors_for_layer(self, name: str) -> dict:
        return self.raw.Root.pScenario.rEntitiesLayer.dctSublayers[name].dctActors

    def all_layers(self) -> Iterator[str]:
        yield from self.raw.Root.pScenario.rEntitiesLayer.dctSublayers.keys()

    def all_actors(self) -> Iterator[Tuple[str, str, construct.Container]]:
        for layer_name, sublayer in self.raw.Root.pScenario.rEntitiesLayer.dctSublayers.items():
            for actor_name, actor in sublayer.dctActors.items():
                yield layer_name, actor_name, actor

    def follow_link(self, link: str):
        if link != '{EMPTY}':
            result = self.raw
            for part in link.split(":"):
                result = result[part]
            return result

    def link_for_actor(self, actor_name: str, layer_name: str = "default") -> str:
        return ":".join(["Root", "pScenario", "rEntitiesLayer", "dctSublayers", layer_name, "dctActors", actor_name])

    def all_actor_groups(self) -> Iterator[str]:
        yield from self.raw.Root.pScenario.rEntitiesLayer.dctActorGroups.keys()

    def get_actor_group(self, group_name: str) -> List[str]:
        return self.raw.Root.pScenario.rEntitiesLayer.dctActorGroups[group_name]

    def is_actor_in_group(self, group_name: str, actor_name: str, layer_name: str = "default") -> bool:
        return self.link_for_actor(actor_name, layer_name) in self.get_actor_group(group_name)

    def add_actor_to_group(self, group_name: str, actor_name: str, layer_name: str = "default"):
        group = self.get_actor_group(group_name)
        actor_link = self.link_for_actor(actor_name, layer_name)
        if actor_link not in group:
            group.append(actor_link)

    def remove_actor_from_group(self, group_name: str, actor_name: str, layer_name: str = "default"):
        group = self.get_actor_group(group_name)
        actor_link = self.link_for_actor(actor_name, layer_name)
        if actor_link in group:
            group.remove(actor_link)

    def add_actor_to_entity_groups(self, collision_camera_name: str, actor_name: str, layer_name: str = "default"):
        """
        adds an actor to all entity groups starting with "eg_" + collision_camera_name
        
        param collision_camera_name: name of the collision camera group (prefix "eg_" is added to find the entity groups)
        param actor_name: name of the actor to add to the group
        param layer_name: name of the layer the actor belongs to
        """
        collision_camera_groups = [group for group in self.all_actor_groups() if group.startswith(f"eg_{collision_camera_name}")]
        for group in collision_camera_groups:
            logger.debug("Add actor %s to group %s", actor_name, group)
            self.add_actor_to_group(group, actor_name, layer_name)