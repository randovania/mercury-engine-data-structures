from __future__ import annotations

from typing import TYPE_CHECKING

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    import construct
    from construct import Container

    from mercury_engine_data_structures.game_check import Game


class Brem(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return standard_format.game_model("CEnvironmentMusicPresets", "4.0.2")

    @property
    def presets(self) -> Container:
        return self.raw.Root.pEnvironmentManager.pMusicPresets.dicPresets

    @property
    def boss_presets(self) -> Container:
        return self.raw.Root.pEnvironmentManager.pMusicPresets.dicBossPresets

    def set_preset_track(self, preset_id: str, track_name: str) -> None:
        """Sets the track on a preset. If the preset contains multiple tracks, all tracks will be changed.

        param preset_id: the preset to update
        param track_name: the path to the track"""
        preset = self.presets[preset_id]

        for track in preset.tPreset.vTracks:
            for file in track.vFiles:
                file.sWav = track_name
