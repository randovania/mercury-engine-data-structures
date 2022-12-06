import typing

from construct import Construct, Container

from mercury_engine_data_structures.game_check import Game


class BaseResource:
    _raw: Container
    target_game: Game

    def __init__(self, raw: Container, target_game: Game):
        self._raw = raw
        self.target_game = target_game

    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        raise NotImplementedError()

    @classmethod
    def parse(cls, data: bytes, target_game: Game) -> "BaseResource":
        return cls(cls.construct_class(target_game).parse(data, target_game=target_game),
                   target_game)

    def build(self) -> bytes:
        return self.construct_class(self.target_game).build(self._raw, target_game=self.target_game)

    @property
    def raw(self) -> Container:
        return self._raw


AssetType = str
AssetId = int
NameOrAssetId = typing.Union[str, AssetId]


def resolve_asset_id(value: NameOrAssetId, game: Game) -> AssetId:
    if isinstance(value, str):
        return game.hash_asset(value)
    return value
