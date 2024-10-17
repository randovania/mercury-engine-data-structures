from __future__ import annotations

from collections import defaultdict
from enum import Enum

import construct
from construct.core import (
    Adapter,
    Byte,
    Const,
    Construct,
    Int8ul,
    Int32ul,
    Int64ul,
    Rebuild,
    Struct,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import CVector3D, StrId, VersionAdapter, make_dict, make_vector
from mercury_engine_data_structures.crc import crc32, crc64
from mercury_engine_data_structures.game_check import Game

TransformStruct = Struct("position" / CVector3D, "rotation" / CVector3D, "scale" / CVector3D)

BMSSD = Struct(
    "_magic" / Const(b"MSSD"),
    "_version"
    / game_check.is_sr_or_else(
        VersionAdapter("1.12.0"),
        VersionAdapter("1.19.0"),
    ),
    # static models (just bcmdl and bsmat), stored en mass in maps/levels/c10_samus/<scenario>/models/
    "scene_blocks"
    / game_check.is_sr_or_else(
        make_vector(
            Struct(
                "model_name" / StrId,
                "byte0" / Byte,
                "byte1" / Byte,
                "byte2" / Byte,
                "int3" / Int32ul,
                "int4" / Int32ul,
                "farr4" / CVector3D,
                "farr5" / CVector3D,
            )
        ),
        make_vector(
            Struct(
                "model_name" / StrId,
                "byte0" / Const(1, Byte),
                "byte1" / Const(1, Byte),
                "byte2" / Const(1, Byte),
                "int3" / Const(1, Int32ul),
                "byte4" / Const(1, Byte),
                "transform" / TransformStruct,
            )
        ),
    ),
    # map objects (bcmdl, bsmat and bcskla), stored in the standard actor format in maps/objects/
    "objects" / make_vector(Struct("model_name" / StrId, "transforms" / make_vector(TransformStruct))),
    Const(0, Int32ul),  # likely unused array
    "lights"
    / make_vector(  # only used in MSR
        Struct(
            "model_name" / StrId,
            "char2" / Byte,
            "char3" / Byte,
            "char4" / Byte,
            "int5" / Int32ul,
            "int6" / Int32ul,
            "int7" / Int32ul,
            "char8" / Byte,
            "char9" / Byte,
            "int10" / Int32ul,
            "float13" / CVector3D,
            "int11" / Int8ul,
        )
    ),
    Const(0, Int32ul),  # likely unused array
    "scene_groups"
    / make_vector(
        Struct(
            "sg_name" / StrId,
            "item_count" / Rebuild(Int32ul, lambda ctx: sum([len(g) for g in ctx.item_groups.values()])),
            "item_groups" / make_dict(make_vector(game_check.is_sr_or_else(Int32ul, Int64ul)), Int32ul),
        )
    ),
    construct.Terminated,
)


def crc_func(obj):
    return crc32 if obj._version == "1.12.0" else crc64


class BmssdAdapter(Adapter):
    ItemTypes = {
        0: "scene_blocks",
        1: "objects",
        2: "lights",
    }

    def _decode(self, obj, context, path):
        crc = crc_func(obj)

        res = construct.Container(
            _version=obj._version,
            _scene_blocks={crc(blk.model_name): blk for blk in obj.scene_blocks},
            _objects=[
                construct.Container(model_name=o.model_name, transform=t) for o in obj.objects for t in o.transforms
            ],
            _lights={crc(lgt.model_name): lgt for lgt in obj.lights},
            scene_groups=construct.Container(),
        )

        for sg in obj.scene_groups:
            res.scene_groups[sg.sg_name] = construct.Container()

            for ig_value, items in sg.item_groups.items():
                group_type = self.ItemTypes[ig_value]
                res.scene_groups[sg.sg_name][group_type] = construct.ListContainer()

                # objects are indexed and not hashed
                if ig_value == 1:
                    res.scene_groups[sg.sg_name][group_type] = construct.ListContainer(
                        [res._objects[block] for block in items]
                    )
                else:
                    res.scene_groups[sg.sg_name][group_type] = construct.ListContainer(
                        [
                            # use raw hash value instead of block value if it doesn't exist above
                            res[f"_{group_type}"][block] if res[f"_{group_type}"].get(block, None) else block
                            for block in items
                        ]
                    )

        return res

    def _encode(self, obj, context, path):
        def obj_to_tuple(o):
            return (
                o["model_name"],
                o["transform"]["position"][0],
                o["transform"]["position"][1],
                o["transform"]["position"][2],
                o["transform"]["rotation"][0],
                o["transform"]["rotation"][1],
                o["transform"]["rotation"][2],
                o["transform"]["scale"][0],
                o["transform"]["scale"][1],
                o["transform"]["scale"][2],
            )

        objects = defaultdict(list)
        for o in obj._objects:
            objects[o["model_name"]].append(o)

        object_order = dict()
        object_containers = construct.ListContainer()
        i = 0
        for name, objs in objects.items():
            object_containers.append(
                construct.Container(model_name=name, transforms=construct.ListContainer(o["transform"] for o in objs))
            )
            for o in objs:
                object_order[obj_to_tuple(o)] = i
                i += 1

        crc = crc_func(obj)

        res = construct.Container(
            _version=obj._version,
            scene_blocks=[blk for blk in obj._scene_blocks.values()],
            objects=object_containers,
            lights=[lgt for lgt in obj._lights.values()],
            scene_groups=construct.ListContainer(),
        )

        for sg_name, sg in obj.scene_groups.items():
            sg_cont = construct.Container(sg_name=sg_name, item_groups=construct.Container())

            for group_type, items in sg.items():
                group_type_int = [it for it in self.ItemTypes if self.ItemTypes[it] == group_type][0]

                if group_type_int == 1:
                    sg_cont.item_groups[group_type_int] = [object_order[obj_to_tuple(o)] for o in items]
                else:
                    sg_cont.item_groups[group_type_int] = [
                        # handle integers (unmatched crc's in decode)
                        o if isinstance(o, int) else crc(o["model_name"])
                        for o in items
                    ]

            res.scene_groups.append(sg_cont)

        return res


class ItemType(Enum):
    SCENE_BLOCK = 0, "scene_blocks"
    OBJECT = 1, "objects"
    LIGHT = 2, "lights"

    def __new__(cls, value: int, group_name: str):
        member = object.__new__(cls)
        member._value_ = value
        member.group_name = group_name
        return member


class Bmssd(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BmssdAdapter(BMSSD)

    def get_item(self, item_name_or_id: str | int, item_type: ItemType) -> construct.Container:
        if isinstance(item_name_or_id, int):
            if item_type == ItemType.OBJECT:
                return self.raw._objects[item_name_or_id]
            else:
                return self.raw[f"_{item_type.group_name}"].get(item_name_or_id, None)

        if item_type == ItemType.OBJECT:
            raise ValueError("If accessing an Object type item, must use the index!")

        crc = crc_func(self.raw)
        return self.raw[f"_{item_type.group_name}"].get(crc(item_name_or_id), None)

    def get_scene_group(self, scene_group: str) -> construct.Container:
        return self.raw.scene_groups.get(scene_group, None)

    def scene_groups_for_item(self, item: str | construct.Container, item_type: str) -> list[str]:
        if isinstance(item, str):
            item = self.get_item(item, item_type)

        return [sg_name for sg_name, sg_val in self.raw.scene_groups.items() if item in sg_val[item_type.group_name]]

    def add_item(self, item: construct.Container, item_type: ItemType, scene_groups: list[str] = None):
        if item_type == ItemType.OBJECT:
            self.raw._objects.append(item)
        else:
            crc = crc_func(self.raw)
            self.raw[f"_{item_type.group_name}"][crc(item["model_name"])] = item

        for sg_name in scene_groups:
            self.get_scene_group(sg_name)[item_type.group_name].append(item)

    def remove_item_from_group(self, item: construct.Container, item_type: ItemType, scene_group: str):
        sg = self.get_scene_group(scene_group)
        if sg and item_type.group_name in sg and item in sg[item_type.group_name]:
            sg[item_type.group_name].remove(item)

    def remove_item(self, item: construct.Container, item_type: ItemType):
        groups = self.scene_groups_for_item(item, item_type)
        for sg in groups:
            self.remove_item_from_group(item, item_type, sg)

        self.raw[f"_{item_type.group_name}"].remove(item)
