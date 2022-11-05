import argparse
import json
import os
import typing
from pathlib import Path

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import Bmsld, Bmscc
from mercury_engine_data_structures.game_check import Game

world_names = {
    'maps/levels/c10_samus/s000_surface/s000_surface.brfld': "Surface - East",
    'maps/levels/c10_samus/s010_area1/s010_area1.brfld': "Area 1",
    'maps/levels/c10_samus/s020_area2/s020_area2.brfld': "Area 2 - Exterior",
    'maps/levels/c10_samus/s025_area2b/s050_area2b.brfld': "Area 2 - Interior",
    'maps/levels/c10_samus/s028_area2c/s028_area2c.brfld': "Area 2 - Entrance",
    'maps/levels/c10_samus/s030_area3/s030_area3.brfld': "Area 3 - Exterior",
    'maps/levels/c10_samus/s033_area3b/s033_area3b.brfld': "Area 3 - Interior (Lower)",
    'maps/levels/c10_samus/s036_area3c/s036_area3c.brfld': "Area 3 - Interior (Upper)",
    'maps/levels/c10_samus/s040_area4/s040_area4.brfld': "Area 4 - West",
    'maps/levels/c10_samus/s050_area5/s050_area5.brfld': "Area 4 - East",
    'maps/levels/c10_samus/s060_area6/s060_area6.brfld': "Area 5 - Entrance",
    'maps/levels/c10_samus/s065_area6b/s065_area6b.brfld': "Area 5 - Exterior",
    'maps/levels/c10_samus/s067_area6c/s067_area6c.brfld': "Area 5 - Interior",
    'maps/levels/c10_samus/s070_area7/s070_area7.brfld': "Area 6",
    'maps/levels/c10_samus/s090_area9/s090_area9.brfld': "Area 7",
    'maps/levels/c10_samus/s100_area10/s100_area10.brfld': "Area 8",
    'maps/levels/c10_samus/s110_surfaceb/s110_surfaceb.brfld': "Surface - West",
}
id_to_name = {
    os.path.splitext(path.split("/")[-1])[0]: name
    for path, name in world_names.items()
}
pickup_index = 0
bmscc: typing.Optional[Bmscc] = None
# brsa: typing.Optional[Brsa] = None
bmsld: typing.Optional[Bmsld] = None
events: dict[str, dict] = {}


def decode_world(root: Path, target_level: str, out_path: Path, only_update_existing_areas: bool = True,
                 skip_existing_actors: bool = True):
    global pickup_index, bmscc, bmsld
    all_names = samus_returns_data.all_asset_id_to_name()
    game = Game.SAMUS_RETURNS

    pkg_editor = FileTreeEditor(root, target_game=game)

    for asset_id, name in all_names.items():
        if target_level not in name:
            continue

        if name.endswith("bmscc"):
            print(f"Reading {name}...")
            bmscc = Bmscc.parse(pkg_editor.get_raw_asset(asset_id), game)

        elif name.endswith("bmsld"):
            print(f"Reading {name}...")
            bmsld = Bmsld.parse(pkg_editor.get_raw_asset(asset_id), game)

    if bmscc is None or bmsld is None:
        raise ValueError("DATA IS NONE")


def decode_all_worlds(root: Path, out_path: Path):
    header_path = out_path.joinpath("header.json")
    with header_path.open() as f:
        header = json.load(f)

    events.clear()
    events.update(header["resource_database"]["events"])

    for area_path in world_names.keys():
        level_name = os.path.splitext(os.path.split(area_path)[1])[0]
        decode_world(root, level_name, out_path)

    header["resource_database"]["events"] = events

    with header_path.open("w") as f:
        json.dump(header, f, indent=4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("game_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--only", help="Only process the given world")
    args = parser.parse_args()

    if args.only is not None:
        decode_world(args.game_root, args.only, args.output)
    else:
        decode_all_worlds(args.game_root, args.output)


if __name__ == '__main__':
    main()
