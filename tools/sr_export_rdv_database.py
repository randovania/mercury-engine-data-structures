import argparse
import hashlib
import json
import os
import typing
from pathlib import Path

import numpy
from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon as mtPolygon


from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import Bmsld, Bmscc
from mercury_engine_data_structures.game_check import Game

world_names = {
    'maps/levels/c10_samus/s000_surface/s000_surface.bmsld': "Surface - East",
    'maps/levels/c10_samus/s010_area1/s010_area1.bmsld': "Area 1",
    'maps/levels/c10_samus/s020_area2/s020_area2.bmsld': "Area 2 - Exterior",
    'maps/levels/c10_samus/s025_area2b/s050_area2b.bmsld': "Area 2 - Interior",
    'maps/levels/c10_samus/s028_area2c/s028_area2c.bmsld': "Area 2 - Entrance",
    'maps/levels/c10_samus/s030_area3/s030_area3.bmsld': "Area 3 - Exterior",
    'maps/levels/c10_samus/s033_area3b/s033_area3b.bmsld': "Area 3 - Interior (Lower)",
    'maps/levels/c10_samus/s036_area3c/s036_area3c.bmsld': "Area 3 - Interior (Upper)",
    'maps/levels/c10_samus/s040_area4/s040_area4.bmsld': "Area 4 - West",
    'maps/levels/c10_samus/s050_area5/s050_area5.bmsld': "Area 4 - East",
    'maps/levels/c10_samus/s060_area6/s060_area6.bmsld': "Area 5 - Entrance",
    'maps/levels/c10_samus/s065_area6b/s065_area6b.bmsld': "Area 5 - Exterior",
    'maps/levels/c10_samus/s067_area6c/s067_area6c.bmsld': "Area 5 - Interior",
    'maps/levels/c10_samus/s070_area7/s070_area7.bmsld': "Area 6",
    'maps/levels/c10_samus/s090_area9/s090_area9.bmsld': "Area 7",
    'maps/levels/c10_samus/s100_area10/s100_area10.bmsld': "Area 8",
    'maps/levels/c10_samus/s110_surfaceb/s110_surfaceb.bmsld': "Surface - West",
}
id_to_name = {
    os.path.splitext(path.split("/")[-1])[0]: name
    for path, name in world_names.items()
}
pickup_index = 0
bmscc: typing.Optional[Bmscc] = None
# brsa: typing.Optional[Brsa] = None
bmsld: typing.Optional[Bmsld] = None
bmsld_path: str = None
events: dict[str, dict] = {}

_camera_skip = {}


def _get_area_name_from_actors_in_existing_db(out_path: Path) -> dict[str, dict[str, str]]:
    area_name_by_world_and_actor = {}

    for world_name in world_names.values():
        try:
            with out_path.joinpath(f"{world_name}.json").open() as f:
                area_name_by_world_and_actor[world_name] = {}
                for area_name, area_data in json.load(f)["areas"].items():
                    for node_data in area_data["nodes"].values():
                        for variable in ["actor_name", "start_point_actor_name"]:
                            if variable in node_data["extra"]:
                                area_name_by_world_and_actor[world_name][node_data["extra"][variable]] = area_name
        except FileNotFoundError:
            area_name_by_world_and_actor[world_name] = {}

    return area_name_by_world_and_actor


def decode_world(root: Path, target_level: str, out_path: Path, only_update_existing_areas: bool = True,
                 skip_existing_actors: bool = True):
    global pickup_index, bmscc, bmsld, bmsld_path
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
            bmsld_path = name

    if bmscc is None or bmsld is None:
        raise ValueError("DATA IS NONE")

    all_rooms = {}

    area_name_by_world_and_actor = _get_area_name_from_actors_in_existing_db(out_path)

    try:
        with out_path.joinpath(f"{world_names[bmsld_path]}.json").open() as f:
            world: dict = json.load(f)
    except FileNotFoundError:
        world: dict = {
            "name": world_names[bmsld_path],
            "extra": {
                "asset_id": bmsld_path,
            },
            "areas": {}
        }

    area_names = {
        entry.name: f"{entry.name} ({world_names[bmsld_path][0]})"
        for entry in bmscc.raw.layers[0].entries
    }

    def rand_color(s):
        return [x / 300.0 for x in hashlib.md5(bytes(str(sorted(s)), 'ascii')).digest()[0:3]]

    handles = []
    plt.figure(1, figsize=(20, 10))
    plt.title(target_level)

    for entry in bmscc.raw.layers[0].entries:
        assert entry.type == "POLYCOLLECTION2D"

        x1, y1, x2, y2 = entry.data.total_boundings
        if abs(x1) > 59999 or abs(y1) > 59999 or abs(x2) > 59999 or abs(y2) > 59999:
            continue

        area_name = area_names[entry.name]

        if (target_level, entry.name) in _camera_skip:
            world["areas"].pop(area_name, None)
            continue

        assert len(entry.data.polys) == 1
        raw_vertices = []
        for v in entry.data.polys[0].points:
            raw_vertices.append((v.x, v.y))

        # raw_vertices = _polygon_override.get((target_level, entry.name), raw_vertices)
        vertices = numpy.array(raw_vertices)

        c = [0.2, 0.7, 0.6]
        patch = mtPolygon(vertices, linewidth=1, edgecolor=c, facecolor=(c[0], c[1], c[2], 0.1))
        plt.gca().add_patch(patch)
        plt.text((x1 + x2) / 2, (y1 + y2) / 2, entry.name[17:], color=c, ha='center', size='x-small')
        handles.append(patch)

        all_rooms[area_name] = Polygon(vertices)
        if only_update_existing_areas and area_name in world["areas"]:
            continue

        world["areas"][area_name] = {
            "default_node": None,
            "valid_starting_location": False,
            "extra": {
                "total_boundings": {
                    "x1": x1,
                    "x2": x2,
                    "y1": y1,
                    "y2": y2,
                },
                "polygon": raw_vertices,
                "asset_id": entry.name,
            },
            "nodes": {},
        }

    # handles_by_label = {}
    # handles_by_label = {
    #     key: value
    #     for key, value in sorted(handles_by_label.items(), key=lambda it: it[0])
    # }
    # plt.legend(handles_by_label.values(), handles_by_label.keys())

    # plt.savefig(f"{target_level}.png", dpi=200, bbox_inches='tight')
    # plt.close()

    print(f"Writing updated {world_names[bmsld_path]}")
    with out_path.joinpath(f"{world_names[bmsld_path]}.json").open("w") as f:
        json.dump(world, f, indent=4)


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
