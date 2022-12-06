from typing import Optional, Iterator

import construct

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.base_resource import NameOrAssetId, resolve_asset_id
from mercury_engine_data_structures.formats.pkg import Construct_AssetId
from mercury_engine_data_structures.game_check import Game

TOC_Raw = construct.Struct(
    files=common_types.make_dict(
        value=construct.Int32ul,
        key=Construct_AssetId,
    ),
)
TOC = TOC_Raw.compile()


class Toc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return TOC

    @classmethod
    def system_files_name(cls) -> str:
        return "system/files.toc"

    def get_size_for(self, asset_id: NameOrAssetId) -> Optional[int]:
        asset_id = resolve_asset_id(asset_id, self.target_game)
        return self.raw.files.get(asset_id)

    def add_file(self, asset_id: NameOrAssetId, file_size: int):
        asset_id = resolve_asset_id(asset_id, self.target_game)
        self.raw.files[asset_id] = file_size

    def remove_file(self, asset_id: NameOrAssetId):
        resolved_asset_id = resolve_asset_id(asset_id, self.target_game)
        if resolved_asset_id not in self.raw.files:
            raise ValueError(f"Unknown asset_id: {asset_id}")

        del self.raw.files[resolved_asset_id]

    def get_all_asset_id(self) -> Iterator[int]:
        yield from self.raw.files.keys()
