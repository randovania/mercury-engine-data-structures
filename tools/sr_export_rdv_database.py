import argparse
import copy
import hashlib
import json
import os
import re
import typing
from pathlib import Path

import construct
import numpy
from shapely.geometry import Point
from shapely.geometry.polygon import Polygon
from matplotlib.patches import Polygon as mtPolygon


from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import Bmsld, Bmscc
from mercury_engine_data_structures.game_check import Game

world_names = {
    'maps/levels/c10_samus/s000_surface/s000_surface.bmsld': "Surface - East",
    'maps/levels/c10_samus/s010_area1/s010_area1.bmsld': "Area 1",
    'maps/levels/c10_samus/s020_area2/s020_area2.bmsld': "Area 2 - Exterior",
    'maps/levels/c10_samus/s025_area2b/s025_area2b.bmsld': "Area 2 - Interior",
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


class NodeDefinition(typing.NamedTuple):
    name: str
    data: dict[str, typing.Any]


class ActorDetails:
    actor_type: str

    def __init__(self, name: str, actor: construct.Container, all_rooms: dict[str, Polygon],
                 layer_name: str = "default"):
        self.name = name
        self.actor = actor
        self.actor_type = actor.type
        self.actor_layer = layer_name
        self.position = Point([actor.x, actor.y])
        self.rooms: list[str] = [name for name, pol in all_rooms.items() if pol.contains(self.position)]

        self.is_door = self.actor_type.startswith("door")
        # self.is_start_point = "STARTPOINT" in actor.pComponents and "dooremmy" not in self.actor_type
        self.is_pickup = any(self.actor_type.startswith(prefix) for prefix in ["powerup_", "item_", "itemsphere_"])
        self.is_usable = self.actor_type == "weightactivatedplatform"

    def create_node_template(
            self, node_type: str,
            default_name: str,
            existing_data: typing.Optional[dict[str, NodeDefinition]],
    ) -> NodeDefinition:

        result: dict = {
            "node_type": node_type,
            "heal": False,
            "coordinates": {
                "x": self.actor.x,
                "y": self.actor.y,
                "z": self.actor.z,
            },
            "description": "",
            "extra": {
                "actor_name": self.name,
                "actor_type": self.actor.type,
            },
        }
        if self.actor_layer != "default":
            result["extra"]["actor_layer"] = self.actor_layer

        if node_type == "dock":
            result["destination"] = {
                "world_name": None,
                "area_name": None,
                "node_name": None,
            }
            result["dock_type"] = "other"
            result["dock_weakness"] = "Not Determined"

        elif node_type == "pickup":
            result["pickup_index"] = None
            result["major_location"] = None

        elif node_type == "teleporter":
            result["destination"] = {
                "world_name": None,
                "area_name": None,
            }
            result["keep_name_when_vanilla"] = True
            result["editable"] = True

        elif node_type == "event":
            result["event_name"] = None

        if existing_data is not None and self.name in existing_data:
            old_node_data = existing_data[self.name]
            node_name = old_node_data.name
            if node_type == "generic" and old_node_data.data["node_type"] != "generic":
                new_result = copy.deepcopy(old_node_data.data)
                new_result["coordinates"] = result["coordinates"]
                new_result["extra"].update(result["extra"])
                result = new_result
            else:
                result["heal"] = old_node_data.data["heal"]
                result["description"] = old_node_data.data["description"]
                result["connections"] = old_node_data.data["connections"]
                for extra_key in old_node_data.data["extra"]:
                    if extra_key not in result["extra"]:
                        result["extra"][extra_key] = old_node_data.data["extra"][extra_key]
        else:
            node_name = default_name
            result["connections"] = {}

        return NodeDefinition(node_name, result)


def current_world_file_name():
    return re.sub(r'[^a-zA-Z0-9\- ]', r'', world_names[bmsld_path]) + ".json"


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


def decode_world(root: Path, target_level: str, out_path: Path, only_update_existing_areas: bool = False,
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
        with out_path.joinpath(current_world_file_name()).open() as f:
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
    import matplotlib.pyplot as plt
    plt.figure(1, figsize=(20, 10))
    plt.title(target_level)

    # Parse Camera Groups

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
        raw_vertices = [(v.x, v.y) for v in entry.data.polys[0].points]
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

    # Parse Actors
    all_default_details: dict[str, ActorDetails] = {}

    for i, actor_list in enumerate(bmsld.raw.actors):
        print(f"=== List {i}")
        for name, actor in actor_list.items():
            all_default_details[name] = ActorDetails(name, actor, all_rooms)

            d = all_default_details[name]
            if d.is_pickup or d.is_door or d.is_usable:
                plt.annotate(name, [actor.x, actor.y], fontsize='xx-small', ha='center')
                plt.plot(actor.x, actor.y, "o", color=rand_color(d.actor_type))

                # plt.text(actor.x, actor.y, name, color=[1.0, 0.7, 0.6], ha='center', size='small')
                # print(name, actor.type, actor.x, actor.y)

            # if actor_type in {"elevator", "weightactivatedplatform"}:
            #     print(name)
            #     print(actor)

    handles_by_label = {}
    handles_by_label = {
        key: value
        for key, value in sorted(handles_by_label.items(), key=lambda it: it[0])
    }
    plt.legend(handles_by_label.values(), handles_by_label.keys())

    plt.plot()
    plt.savefig(f"{target_level}.png", dpi=200, bbox_inches='tight')
    # plt.show()
    plt.close()

    print(f"Writing updated {current_world_file_name()}")
    with out_path.joinpath(current_world_file_name()).open("w") as f:
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
        if current_world_file_name() not in header["worlds"]:
            header["worlds"].append(current_world_file_name())

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
