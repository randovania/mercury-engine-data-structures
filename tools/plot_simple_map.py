import hashlib
import json
import os
import typing
from pathlib import Path

import numpy

from mercury_engine_data_structures import hashed_names
from mercury_engine_data_structures.formats import Bmscc, Brfld, Brsa
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.pkg_editor import PkgEditor

area_names = {
    'maps/levels/c10_samus/s010_cave/s010_cave.brfld': "Artaria",
    'maps/levels/c10_samus/s020_magma/s020_magma.brfld': "Cataris",
    'maps/levels/c10_samus/s030_baselab/s030_baselab.brfld': "Dairon",
    'maps/levels/c10_samus/s040_aqua/s040_aqua.brfld': "Burenia",
    'maps/levels/c10_samus/s050_forest/s050_forest.brfld': "Ghavoran",
    'maps/levels/c10_samus/s060_quarantine/s060_quarantine.brfld': "Elun",
    'maps/levels/c10_samus/s070_basesanc/s070_basesanc.brfld': "Ferenia",
    'maps/levels/c10_samus/s080_shipyard/s080_shipyard.brfld': "Hanubia",
    'maps/levels/c10_samus/s090_skybase/s090_skybase.brfld': "Itorash",
}
pickup_index = 0

_polygon_override = {
    ("s010_cave", "collision_camera_010"): [
        [-1200.0, 2200.0],
        [-5200.0, 2200.0],
        [-5200.0, -5600.0],
        [-4800.0, -5600.0],
        [-3300.0, -6200.0],
        [-1200.0, -6200.0]
    ],
    ("s010_cave", "collision_camera_023"): [
        [24900.0, 5100.0], [17800.0, 5100.0], [17800.0, 3500.0], [24900.0, 3500.0]
    ],
    ("s010_cave", "collision_camera_048"): [
        [800.0, 3900.0],
        [-1200.0, 3900.0],
        [-1200.0, 5200.0],
        [-5200.0, 5200.0],
        [-5200.0, 2100.0],
        [-1000.0, 2100.0],
        [-1000.0, 1500.0],
        [500.0, 1500.0],
        [800.0, 1500.0]
    ],
    ("s040_aqua", "collision_camera_023_B"): [
        [4100.0, -9800.0],
        [2000.0, -9800.0],
        [2000.0, -12150.0],
        [3500.0, -12150.0],
        [3500.0, -12500.0],
        [4100.0, -12500.0],
    ],
    ("s070_basesanc", "collision_camera_003"): [
        [-4400.0, -2100.0],
        [-10500.0, -2100.0],
        [-10500.0, -4900.0],
        [-8400.0, -4900.0],
        [-8400.0, -3800.0],
        [-6400.0, -3800.0],
        [-4400.0, -4100.0],
    ],
}
_camera_skip = {
    ("s010_cave", "collision_camera_999"),
    ("s040_aqua", "collision_camera_001_B"),
    ("s050_forest", "collision_camera_024_B"),
    ("s050_forest", "collision_camera_025"),
    ("s050_forest", "collision_camera_025_C"),
    ("s080_shipyard", "collision_camera_009_C"),
}


def decode_world(root: Path, target_level: str):
    global pickup_index
    all_names = hashed_names.all_asset_id_to_name()
    game = Game.DREAD

    with PkgEditor.open_pkgs_at(root) as pkg_editor:
        pkg_editor = typing.cast(PkgEditor, pkg_editor)

        bmscc: Bmscc = None
        brsa: Brsa = None
        brfld: Brfld = None
        brfld_path: str

        for asset_id, name in all_names.items():
            if target_level not in name:
                continue

            if name.endswith("bmscc"):
                print(f"Reading {name}...")
                bmscc = Bmscc.parse(pkg_editor.get_asset_with_asset_id(asset_id), game)

            elif name.endswith("brsa"):
                print(f"Reading {name}...")
                brsa = Brsa.parse(pkg_editor.get_asset_with_asset_id(asset_id), game)

            elif name.endswith("brfld"):
                print(f"Reading {name}...")
                brfld = Brfld.parse(pkg_editor.get_asset_with_asset_id(asset_id), game)
                brfld_path = name

    if bmscc is None or brsa is None:
        raise ValueError("DATA IS NONE")

    cams: dict[str, set[str]] = {}

    for setup in brsa.raw.Root.pSubareaManager.vSubareaSetups:
        for config in setup.vSubareaConfigs:
            for cam in config.vsCameraCollisionsIds:
                cams[cam] = cams.get(cam, set())
                if config.sCharclassGroupId:
                    cams[cam].add(config.sCharclassGroupId)

    import matplotlib.pyplot as plt
    from shapely.geometry import Point
    from shapely.geometry.polygon import Polygon
    from matplotlib.patches import Polygon as mtPolygon

    def rand_color(s):
        return [x / 300.0 for x in hashlib.md5(bytes(str(sorted(s)), 'ascii')).digest()[0:3]]

    handles = []
    rooms = {}
    world = {
        "name": area_names[brfld_path],
        "dark_name": None,
        "asset_id": brfld_path,
        "areas": []
    }

    area_by_name: dict[str, dict] = {}
    plt.figure(1, figsize=(20, 10))
    plt.title(target_level)

    for entry in bmscc.raw.layers[0].entries:
        assert entry.type == "POLYCOLLECTION2D"

        x1, y1, x2, y2 = entry.data.total_boundings
        if abs(x1) > 59999 or abs(y1) > 59999 or abs(x2) > 59999 or abs(y2) > 59999:
            continue

        if (target_level, entry.name) in _camera_skip:
            continue

        if entry.name not in cams:
            continue

        assert len(entry.data.polys) == 1
        raw_vertices = []
        for v in entry.data.polys[0].points:
            raw_vertices.append((v.x, v.y))

        raw_vertices = _polygon_override.get((target_level, entry.name), raw_vertices)
        vertices = numpy.array(raw_vertices)
        c = [0.2, 0.7, 0.6]

        patch = mtPolygon(vertices, linewidth=1, edgecolor=c, facecolor=(c[0], c[1], c[2], 0.1))
        plt.gca().add_patch(patch)
        plt.text((x1 + x2) / 2, (y1 + y2) / 2, entry.name[17:], color=c, ha='center', size='x-small')
        handles.append(patch)
        rooms[entry.name] = Polygon(vertices)
        world["areas"].append({
            "name": entry.name,
            "in_dark_aether": False,
            "asset_id": entry.name,
            "default_node_index": None,
            "valid_starting_location": False,
            "nodes": [],
            "extra": {
                "total_boundings": {
                    "x1": x1,
                    "x2": x2,
                    "y1": y1,
                    "y2": y2,
                },
                "polygon": raw_vertices,
            }
        })
        area_by_name[entry.name] = world["areas"][-1]

    handles_by_label = {}
    door_color = [0.8, 0.2, 0.2]
    item_color = [0.2, 0.2, 0.8]
    actor_positions = {}

    def count_docks(rm: str) -> int:
        return sum(
            1 for node in area_by_name[rm]["nodes"]
            if node["node_type"] == "dock"
        )

    for actor in brfld.actors_for_layer("default").values():
        actor_def = os.path.splitext(os.path.split(actor.oActorDefLink)[1])[0]
        # is_door = "door" in actor.sName.lower()
        is_door = "LIFE" in actor.pComponents and "CDoorLifeComponent" == actor.pComponents.LIFE["@type"]

        if is_door or "actors/items" in actor.oActorDefLink:
            handles_by_label[actor_def], = plt.plot(actor.vPos[0], actor.vPos[1], "o", color=rand_color(actor_def))

            p = Point(actor.vPos)
            if others := [name for name, other in actor_positions.items() if p.distance(other) < 3]:
                print(f"{actor.sName} is very close to {[other for other in others]}")
            actor_positions[actor.sName] = p
            rooms_for_actor = [name for name, pol in rooms.items() if pol.contains(p)]

            va = "bottom" if is_door else "top"
            plt.annotate(actor.sName, actor.vPos[:2], fontsize='xx-small', ha='center', va=va)
            if is_door:
                extra = {
                    "actor_def": actor.oActorDefLink,
                    "left_shield": actor.pComponents.LIFE.wpLeftDoorShieldEntity,
                    "right_shield": actor.pComponents.LIFE.wpLeftDoorShieldEntity,
                }

                if len(rooms_for_actor) == 2:
                    for i, room_name in enumerate(rooms_for_actor):
                        area_by_name[room_name]["nodes"].append({
                            "name": f"Door ({actor.sName})",
                            "heal": False,
                            "coordinates": {
                                "x": actor.vPos[0],
                                "y": actor.vPos[1],
                                "z": actor.vPos[2],
                            },
                            "extra": extra,
                            "node_type": "dock",
                            "dock_index": count_docks(room_name),
                            "connected_area_asset_id": rooms_for_actor[(i + 1) % 2],
                            "connected_dock_index": count_docks(rooms_for_actor[(i + 1) % 2]),
                            "dock_type": 2,
                            "dock_weakness_index": 1,
                            "connections": {}
                        })
                elif len(rooms_for_actor) > 2:
                    print("multiple rooms for door!", actor.sName, rooms_for_actor)
                    for i, room_name in enumerate(rooms_for_actor):
                        area_by_name[room_name]["nodes"].append({
                            "name": f"Door ({actor.sName})",
                            "heal": False,
                            "coordinates": {
                                "x": actor.vPos[0],
                                "y": actor.vPos[1],
                                "z": actor.vPos[2],
                            },
                            "extra": extra,
                            "node_type": "generic",
                            "connections": {}
                        })
            else:
                for room_name in rooms_for_actor:
                    area_by_name[room_name]["nodes"].append({
                        "name": f"Pickup ({actor.sName})",
                        "heal": False,
                        "coordinates": {
                            "x": actor.vPos[0],
                            "y": actor.vPos[1],
                            "z": actor.vPos[2],
                        },
                        "extra": {
                            "actor_def": actor.oActorDefLink,
                        },
                        "node_type": "pickup",
                        "pickup_index": pickup_index,
                        "major_location": "tank" not in actor_def,
                        "connections": {}
                    })
                if len(rooms_for_actor) != 1:
                    print("wrong item!", actor.sName, rooms_for_actor)
                pickup_index += 1

        # else:
        #     plt.annotate(actor.sName, actor.vPos[:2], fontsize='xx-small', ha='center')
        #     plt.plot(actor.vPos[0], actor.vPos[1], "o", color=item_color)

    handles_by_label = {
        key: value
        for key, value in sorted(handles_by_label.items(), key=lambda it: it[0])
    }

    plt.legend(handles_by_label.values(), handles_by_label.keys())
    # plt.show()
    # plt.savefig(f"{target_level}.png", dpi=200, bbox_inches='tight')
    plt.close()

    with open(f"{world['name']}.json", "w") as f:
        json.dump(world, f, indent=4)


def decode_all_worlds(root: Path):
    for area_path in area_names.keys():
        level_name = os.path.splitext(os.path.split(area_path)[1])[0]
        decode_world(root, level_name)


if __name__ == '__main__':
    decode_all_worlds(Path("E:/DreadExtract"))
    # decode_world(Path("E:/DreadExtract"), "s080_shipyard")
