import argparse
import json
from pathlib import Path

from mercury_engine_data_structures import cli
from mercury_engine_data_structures.formats import Toc
from mercury_engine_data_structures.game_check import Game


def main():
    parser = argparse.ArgumentParser()
    cli.add_game_argument(parser)
    parser.add_argument("toc_file", type=Path)
    args = parser.parse_args()

    if args.game == Game.SAMUS_RETURNS:
        short_game = "sr"
    elif args.game == Game.DREAD:
        short_game = "dread"
    else:
        raise ValueError(f"unsupported game {args.game}")

    path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures",
                                              f"{short_game}_resource_names.json")

    toc = Toc.parse(
        args.toc_file.read_bytes(),
        args.game,
    )
    all_asset_id = set(toc.get_all_asset_id())
    print(toc)

    known_names: dict[str, int] = json.loads(path.read_text())
    filtered_names = {
        name: value
        for name, value in known_names.items()
        if value in all_asset_id
    }
    path.write_text(json.dumps(
        filtered_names,
        indent=4,
    ))


if __name__ == '__main__':
    main()