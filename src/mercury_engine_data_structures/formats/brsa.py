from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from construct import Container, ListContainer

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    from collections.abc import Iterator

    from construct import Construct

    from mercury_engine_data_structures.game_check import Game


class Brsa(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.game_model("CSubAreaManager", "2.1.2")

    @property
    def subarea_setups(self) -> Iterator[Container]:
        yield from self.raw.Root.pSubareaManager.vSubareaSetups

    @property
    def charclass_groups(self) -> Iterator[Container]:
        yield from self.raw.Root.pSubareaManager.vCharclassGroups

    def get_subarea_setup(self, setup_id: str) -> Container:
        """Gets a setup

        param setup_id: the name of the setup
        returns: the setup"""
        return next(setup for setup in self.subarea_setups if setup.sId == setup_id)

    def add_setup(self, setup_id: str) -> Container:
        """Adds a new setup

        param setup_id: the name of the new setup
        returns: the newly created setup"""
        new_setup = Container({"sId": setup_id, "vSubareaConfigs": ListContainer()})
        self.raw.Root.pSubareaManager.vSubareaSetups.append(new_setup)

        return new_setup

    def get_subarea_config(self, subarea_id: str, setup_id: str = "Default") -> Container:
        """Gets a config for a subarea

        param subarea_id: the name of the subarea the config is for
        param setup_id: the name of the setup the config is in
        returns: the config for the subarea"""
        return next(config for config in self.get_subarea_setup(setup_id).vSubareaConfigs if config.sId == subarea_id)

    def add_subarea_config(
        self,
        subarea_id: str,
        setup_id: str = "Default",
        *,
        disable_subarea=False,
        camera_distance=-1.0,
        ignore_camera_offsets=False,
        charclass_group: str = "No Enemies",
        camera_ids: list[str] = [],
        cutscene_ids: list[str] = [],
    ) -> Container:
        """Adds a config for a subarea

        param subarea_id: the name of the subarea the config is for
        param setup_id: the name of the setup the config will be in
        returns: the newly created config"""
        new_config = Container(
            {
                "sId": subarea_id,
                "sSetupId": setup_id,
                "bDisableSubarea": disable_subarea,
                "fCameraZDistance": camera_distance,
                "bIgnoreMetroidCameraOffsets": ignore_camera_offsets,
                "sCharclassGroupId": charclass_group,
                "asItemsIds": [""] * 9,
                "vsCameraCollisionsIds": camera_ids if camera_ids else [],
                "vsCutscenesIds": cutscene_ids if cutscene_ids else [],
            }
        )
        self.get_subarea_setup(setup_id).vSubareaConfigs.append(new_config)

        return new_config

    def set_scenario_collider(self, subarea_id: str, collider_name: str, setup_id: str = "Default") -> None:
        """Sets the scenario collider for a subarea

        param subarea_id: the name of the subarea
        param collider_name: the name of the collider
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[0] = collider_name

    def set_light_group(self, subarea_id: str, group_name: str, setup_id: str = "Default") -> None:
        """Sets the light group for a subarea

        param subarea_id: the name of the subarea
        param group_name: the name of the group
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[1] = group_name

    def set_sound_group(self, subarea_id: str, group_name: str, setup_id: str = "Default") -> None:
        """Sets the sound group for a subarea

        param subarea_id: the name of the subarea
        param collider_name: the name of the group
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[2] = group_name

    def set_scene_group(self, subarea_id: str, group_name: str, setup_id: str = "Default") -> None:
        """Sets the scene group for a subarea

        param subarea_id: the name of the subarea
        param group_name: the name of the group
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[3] = group_name

    def set_entity_group(self, subarea_id: str, group_name: str, setup_id: str = "Default") -> None:
        """Sets the entity group for a subarea

        param subarea_id: the name of the subarea
        param group_name: the name of the group
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[4] = group_name

    def set_tilegroup_group(self, subarea_id: str, group_name: str, setup_id: str = "Default") -> None:
        """Sets the tilegroup group for a subarea

        param subarea_id: the name of the subarea
        param group_name: the name of the group
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[5] = group_name

    def set_visual_preset(self, subarea_id: str, preset_name: str, setup_id: str = "Default") -> None:
        """Sets the visual preset for a subarea

        param subarea_id: the name of the subarea
        param preset_name: the name of the preset
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[6] = preset_name

    def set_sound_preset(self, subarea_id: str, preset_name: str, setup_id: str = "Default") -> None:
        """Sets the sound preset for a subarea

        param subarea_id: the name of the subarea
        param preset_name: the name of the preset
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[7] = preset_name

    def set_music_preset(self, subarea_id: str, preset_name: str, setup_id: str = "Default") -> None:
        """Sets the music preset for a subarea

        param subarea_id: the name of the subarea
        param preset_name: the name of the preset
        param setup_id: the name of the setup the subarea is in"""
        self.get_subarea_config(subarea_id, setup_id).asItemsIds[8] = preset_name

    def get_charclass_group(self, group_id: str) -> Container:
        """Gets a charclass group

        param group_id: the name of the group
        returns: the charclass group"""
        return next(group for group in self.charclass_groups if group.sId == group_id)

    def add_charclass_group(self, group_id: str, charclasses: list[str] = []) -> Container:
        """Adds a new charclass group

        param group_id: the name of the new group
        param charclasses: the charclasses in this group
        returns: the newly created charclass group"""
        new_group = Container({"sId": group_id, "vsCharClassesIds": charclasses if charclasses else ListContainer()})
        self.raw.Root.pSubareaManager.vCharclassGroups.append(new_group)

        return new_group
