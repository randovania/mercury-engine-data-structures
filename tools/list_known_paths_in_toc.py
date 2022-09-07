import argparse
from pathlib import Path

from mercury_engine_data_structures import cli, samus_returns_data, dread_data
from mercury_engine_data_structures.formats import Toc
from mercury_engine_data_structures.game_check import Game


def main():
    parser = argparse.ArgumentParser()
    cli.add_game_argument(parser)
    parser.add_argument("game_root", type=Path)
    args = parser.parse_args()

    game_root: Path = args.game_root
    toc = Toc.parse(
        game_root.joinpath(Toc.system_files_name()).read_bytes(),
        args.game,
    )

    if args.game == Game.SAMUS_RETURNS:
        id_mapping = samus_returns_data.all_asset_id_to_name()
    elif args.game == Game.DREAD:
        id_mapping = dread_data.all_asset_id_to_name()
    else:
        raise ValueError(f"unsupported game {args.game}")

    for asset_id in toc.get_all_asset_id():
        print("{:016x}: {}".format(
            asset_id,
            id_mapping.get(asset_id, ""),
        ))


if __name__ == '__main__':
    main()
