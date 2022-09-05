import argparse
import json
import traceback
from pathlib import Path

from mercury_engine_data_structures import cli, crc
from mercury_engine_data_structures.formats import Toc
from mercury_engine_data_structures.game_check import Game


def main():
    parser = argparse.ArgumentParser()
    cli.add_game_argument(parser)
    parser.add_argument("--possible-new-paths", type=Path)
    parser.add_argument("game_root", type=Path)
    args = parser.parse_args()

    if args.game == Game.SAMUS_RETURNS:
        short_game = "sr"
    elif args.game == Game.DREAD:
        short_game = "dread"
    else:
        raise ValueError(f"unsupported game {args.game}")

    path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures",
                                              f"{short_game}_resource_names.json")

    game_root: Path = args.game_root
    toc = Toc.parse(
        game_root.joinpath(Toc.system_files_name()).read_bytes(),
        args.game,
    )
    all_asset_id = set(toc.get_all_asset_id())

    known_names: dict[str, int] = json.loads(path.read_text())

    if args.possible_new_paths:
        with args.possible_new_paths.open() as f:
            for line in f:
                assert isinstance(line, str)
                name = line.strip()
                known_names[name] = crc.crc32(name)

    filtered_names = {
        name: value
        for name, value in known_names.items()
        if value in all_asset_id
    }
    path.write_text(json.dumps(
        filtered_names,
        indent=4,
        sort_keys=True,
    ))
    asset_ids_with_names = set(filtered_names.values())

    print(f"Paths in toc: {len(all_asset_id)}")
    print(f"Known paths: {len(filtered_names)}")
    print("\n\n")

    from mercury_engine_data_structures.formats import Pkg
    for pkg_path in game_root.rglob("*.pkg"):
        with pkg_path.open("rb") as f:
            # print(f"\n\n=== {pkg_path.relative_to(game_root)}")
            pkg = Pkg.parse_stream(f, target_game=args.game)
            missing_ids = 0
            known_ids = 0
            files = []
            for asset in pkg.all_assets:
                files.append(asset.asset_name)
                if asset.asset_id in asset_ids_with_names:
                    known_ids += 1
                else:
                    missing_ids += 1

            # print("\n".join(files))

            if missing_ids:
                print(f"{pkg_path.relative_to(game_root)}: {known_ids} known ids, {missing_ids} missing ids")


if __name__ == '__main__':
    main()