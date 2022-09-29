import argparse
import json
from pathlib import Path

from mercury_engine_data_structures import cli
from mercury_engine_data_structures.game_check import Game


def main():
    parser = argparse.ArgumentParser()
    cli.add_game_argument(parser)
    parser.add_argument("game_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    if args.game == Game.SAMUS_RETURNS:
        short_game = "sr"
    elif args.game == Game.DREAD:
        short_game = "dread"
    else:
        raise ValueError(f"unsupported game {args.game}")

    path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures",
                                              f"{short_game}_resource_names.json")
    known_names: dict[str, int] = json.loads(path.read_text())
    name_for_asset_id: dict[int, str] = {asset_id: name for name, asset_id in known_names.items()}

    game_root: Path = args.game_root
    output: Path = args.output

    output.mkdir(parents=True, exist_ok=True)

    from mercury_engine_data_structures.formats import Pkg
    for pkg_path in game_root.rglob("*.pkg"):
        with pkg_path.open("rb") as f:
            pkg = Pkg.parse_stream(f, target_game=args.game)
            for asset in pkg.all_assets:
                if asset.asset_id in name_for_asset_id:
                    target_path = output.joinpath(name_for_asset_id[asset.asset_id])
                else:
                    target_path = output.joinpath("unknown", f"{asset.asset_id:08x}")

                print(f"* Writing {target_path}")
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(asset.data)


if __name__ == '__main__':
    main()
