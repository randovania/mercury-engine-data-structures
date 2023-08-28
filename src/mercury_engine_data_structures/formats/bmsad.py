import copy
import functools
import typing
from collections.abc import Sequence

import construct
from construct.core import (
    Array,
    Byte,
    Const,
    Construct,
    Flag,
    Float32l,
    Hex,
    IfThenElse,
    Int8ul,
    Int16ul,
    Int32sl,
    Int32ul,
    Struct,
    Switch,
)
from construct.lib.containers import Container, ListContainer

from mercury_engine_data_structures import common_types, game_check, type_lib
from mercury_engine_data_structures.common_types import Char, CVector3D, Float, StrId, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.alignment import PrefixedAllowZeroLen
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource, dread_types
from mercury_engine_data_structures.formats.bmsas import BMSAS_SR, Bmsas
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.type_lib import get_type_lib_dread, get_type_lib_for_game


def SR_or_Dread(sr, dread):
    return IfThenElse(
        game_check.current_game_at_most(Game.SAMUS_RETURNS),
        sr,
        dread,
    )


# Functions
FunctionArgument = Struct(
    type=Char,
    value=Switch(
        construct.this.type,
        {
            's': StrId,
            'f': Float,
            'b': Flag,
            'i': Int32ul,
        },
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError)
    )
)
Functions = make_vector(Struct(
    name=StrId,
    unk1=Flag,
    unk2=Flag,
    params=common_types.DictAdapter(common_types.make_vector(
        common_types.DictElement(
            FunctionArgument,
            key=PropertyEnum,
        )
    )),
))


# Fields
ExtraFields = common_types.DictAdapter(make_vector(
    common_types.DictElement(Struct(
        "type" / StrId,
        "value" / Switch(
            construct.this.type,
            {
                "bool": Flag,
                "string": StrId,
                "float": Float,

                "int": Int32sl,
                "vec3": CVector3D,
            },
            ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError)
        )
    ))
), allow_duplicates=True)


@functools.cache
def fieldtypes(game: Game) -> dict[str, Construct]:
    if game == Game.DREAD:
        return {k: v for k, v in vars(dread_types).items() if isinstance(v, Construct)}
    raise ValueError(f"No field types defined for {game}")


def find_charclass_for_type(type_name: str) -> str:
    if type_name == "CActorComponent":
        return "CActorComponentDef"

    as_char = "CCharClass" + type_name[1:]
    if as_char in fieldtypes(Game.DREAD):
        return as_char

    return find_charclass_for_type(
        get_type_lib_dread().get_parent_for(type_name),
    )


# Dependencies
def DreadDependencies():
    component_dependencies = {
        "CFXComponent": make_vector(Struct(
            "file" / StrId,
            "unk1" / Int32ul,
            "unk2" / Int32ul,
            "unk3" / Byte
        )),
        "CCollisionComponent": Struct(
            "file" / StrId,
            "unk" / Int16ul
        ),
        "CGrabComponent": make_vector(Struct(
            "unk1" / StrId,
            "unk2" / StrId,
            "unk3" / StrId,
            "unk4" / Float32l,
            "unk5" / Byte,
            "unk6" / Byte,
            "unk7" / Int16ul,
            "unk8" / Array(2, Struct(
                "unk2" / Int16ul,
                "unk1" / Array(8, Float32l),
            )),
        )),
        "CBillboardComponent": Struct(
            "id1" / StrId,
            "unk1" / make_vector(Struct(
                "id" / StrId,
                "unk1" / Array(3, Int32ul),
                "unk2" / Byte,
                "unk3" / Array(2, Int32ul),
                "unk4" / Float32l
            )),
            "id2" / StrId,
            "unk2" / make_vector(Struct(
                "id" / StrId,
                "unk1" / Byte,
                "unk2" / Array(4, Int32ul)
            )),
        ),
        "CSwarmControllerComponent": Struct(
            "unk1" / make_vector(StrId),
            "unk2" / make_vector(StrId),
            "unk3" / make_vector(StrId)
        )
    }
    component_dependencies["CStandaloneFXComponent"] = component_dependencies["CFXComponent"]

    def component_type(this):
        for component_type in component_dependencies.keys():
            if get_type_lib_dread().is_child_of(this.type, component_type):
                return component_type
        return None

    return Switch(component_type, component_dependencies)


def SRDependencies():
    component_dependencies = {
        "CAnimationComponent": make_vector(StrId),
        "CFXComponent": make_vector(Struct(
            "file" / StrId,
            "unk1" / Int32ul,
            "unk2" / Int32ul,
        )),
        "CCollisionComponent": Struct(
            "file" / StrId,
            "unk" / Int16ul
        ),
        "CGrabComponent": make_vector(Struct(
            a=StrId,
            b=StrId,
            c=StrId,
            d=Hex(Int32ul)[2],
            e=Float[8],
            f=Hex(Int32ul)[9],
        )),
        "CGlowflyAnimationComponent": make_vector(StrId),
        "CSceneModelAnimationComponent": make_dict(make_dict(StrId)),

        "CBillboardComponent": Struct(
            "id1" / StrId,
            "unk1" / make_dict(Struct(
                "unk1" / Int32ul[3],
                "unk2" / Byte,
                "unk3" / Int32ul[2],
                "unk4" / Float32l
            )),
            "id2" / StrId,
            "unk3" / make_vector(Struct(
                "id" / StrId,
                "unk1" / Byte,
                "unk2" / make_vector(Struct(
                    "a" / Float,
                    "b" / Float,
                    "c" / Float,
                )),
            )),
        ),

        "CSwarmControllerComponent": Struct(
            "unk1" / make_vector(StrId),
            "unk2" / make_vector(StrId),
            "unk3" / make_vector(StrId)
        ),
    }
    for dep in [
        "CTsumuriAcidDroolCollision",
        "CBillboardCollisionComponent",
        "CQueenPlasmaArcCollision",
    ]:
        component_dependencies[dep] = component_dependencies["CCollisionComponent"]

    for dep in [
        "CFlockingSwarmControllerComponent",
        "CBeeSwarmControllerComponent",
    ]:
        component_dependencies[dep] = component_dependencies["CSwarmControllerComponent"]

    return Switch(construct.this.type, component_dependencies)


# Components
DreadComponent = Struct(
    type=StrId,
    unk_1=Int32sl,
    unk_2=Int32sl,
    fields=PrefixedAllowZeroLen(
        Int32ul,
        Struct(
            empty_string=PropertyEnum,
            root=PropertyEnum,
            fields=Switch(
                lambda ctx: find_charclass_for_type(ctx._._.type),
                fieldtypes(Game.DREAD),
                ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx._._.type}", construct.SwitchError)
            )
        )
    ),
    extra_fields=construct.If(
        lambda this: get_type_lib_dread().is_child_of(this.type, "CComponent"),
        ExtraFields,
    ),
    functions=Functions,
    dependencies=DreadDependencies(),
)

SRComponent = Struct(
    type=StrId,
    unk_1=Hex(Int32ul),
    unk_2=Float32l,
    functions=Functions,
    fields=ExtraFields,
    dependencies=SRDependencies(),
)


# Header
_CActorDefFields = {
    "unk_1": Flag,
    "unk_2": Flag,
    "unk_3": Int32ul,
    "unk_4": Flag,
    "unk_5": Flag,
    "sub_actors": make_vector(StrId),
}

CActorDefHeader = Struct(**_CActorDefFields)

CCharClassHeader = Struct(
    model_name=StrId,
    **_CActorDefFields,
    unk_6=Float,
    unk_7=Float,
    unk_8=Float,
    unk_9=Float,
    unk_10=Float,
    unk_11=CVector3D,
    unk_12=Float,
    magic=Const(0xFFFFFFFF, Hex(Int32ul)),
    unk_13=Flag,
    category=StrId,
)

SRHeader = Struct(
    model_name=StrId,
    unk_1=Int8ul,
    unk_2a=Float,
    unk_2b=Float,
    unk_2c=Float,
    unk_2d=Float,
    unk_2e=Float,
    unk_2f=CVector3D,
    unk_2g=Float,
    unk_3=Int8ul,
    unk_4=Int32ul,
    other_magic=Int32sl,
    unk_5=Flag,
    unk_5b=Flag,
    unk_6=Flag,
    category=StrId,
    unk_7=Flag,
    sub_actors=make_vector(StrId),
    unk_8=Int32ul,
)


# BMSAD
BMSAD_SR = Struct(
    "_magic" / Const(b"MSAD"),
    "version" / Const(0x002C0001, Hex(Int32ul)),

    "name" / StrId,

    "header" / SRHeader,

    "components" / make_dict(SRComponent),

    "unk_1" / Int32ul,
    "unk_1a" / construct.If(lambda this: this.unk_1 == 2, construct.Bytes(9)),
    "unk_1b" / construct.If(lambda this: this.unk_1 == 0, construct.Bytes(15)),
    "unk_2" / StrId,
    "unk_3" / Int32ul,

    "action_sets" / make_vector(BMSAS_SR),
    "_remaining" / construct.Peek(construct.GreedyBytes),
    "sound_fx" / construct.If(
        lambda this: (
            (this._parsing and this._remaining)
            or (this._building and (this.sound_fx is not None))
        ),
        make_vector(StrId >> Byte)
    ),

    construct.Terminated,
)

BMSAD_Dread = Struct(
    "_magic" / Const(b"MSAD"),
    "version" / Const(0x0200000F, Hex(Int32ul)),

    "name" / StrId,
    "type" / StrId,

    "header" / Switch(
        construct.this.type,
        {
            "CCharClass": CCharClassHeader,
            "CActorDef": CActorDefHeader
        },
        ErrorWithMessage(lambda ctx: f"Unknown property type: {ctx.type}"),
    ),
    "unk" / Flag,
    "components" / make_dict(DreadComponent),
    "action_sets" / make_vector(StrId),
    "sound_fx" / make_vector(StrId >> Byte),
    construct.Terminated,
)


ArgAnyType = str | float | bool | int
class ActorDefFunc:
    def __init__(self, raw: dict) -> None:
        self._raw = raw

    @classmethod
    def new(cls,
            name: str,
            unk1: bool = True,
            unk2: bool = False,
        ):
        return cls(Container(
            name=name,
            unk1=unk1,
            unk2=unk2,
            params=Container()
        ))

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, ActorDefFunc):
            return False
        if self.name != __value.name:
            return False
        if self.raw.unk1 != __value.raw.unk1:
            return False
        if self.raw.unk2 != __value.raw.unk2:
            return False
        return self.params == __value.params

    @property
    def raw(self) -> dict:
        return self._raw

    @property
    def name(self) -> str:
        return self.raw.name

    @name.setter
    def name(self, value: str):
        self.raw.name = value

    @property
    def params(self) -> dict[str, dict]:
        return self.raw["params"]

    @params.setter
    def params(self, value: dict[str, dict]):
        self.raw["params"] = value

    def _param_name(self, param_name: int | str) -> str:
        if isinstance(param_name, int):
            return f"Param{param_name}"
        return param_name

    def _param(self, param_name: int | str) -> Container:
        return self.params.get(self._param_name(param_name))

    def get_param(self, param_name: int | str) -> ArgAnyType:
        return self._param(param_name).value

    def set_param(self, param_name: int | str, value: ArgAnyType):
        if not isinstance(value, ArgAnyType):
            raise TypeError(f"Expected {ArgAnyType}; got {type(value).__name__}")

        param = self._param(param_name)
        if param is None:
            self.params[self._param_name(param_name)] = Container()
            param = self._param(param_name)

        types = {
            str: 's',
            float: 'f',
            bool: 'b',
            int: 'i',
        }
        for t, s in types.items():
            if isinstance(value, t):
                param.type = s
                break

        param.value = value


T = typing.TypeVar('T', bound=ArgAnyType)
class ActorDefFuncParam(typing.Generic[T]):
    def __init__(self, index: int) -> None:
        self.index = index

    def __get__(self, inst: ActorDefFunc, objtype=None) -> T:
        return inst.get_param(self.index)

    def __set__(self, inst: ActorDefFunc, value: T):
        inst.set_param(self.index, value)


Vec3 = list
FieldType = typing.Union[bool, str, float, int, Vec3]
class ComponentFields:
    def __init__(self, parent: "Component") -> None:
        self.parent = parent

    def _get_extra_field(self, fields: Container, name: str) -> FieldType:
        return fields[name].value

    def _set_extra_field(self, fields: Container, name: str, value: FieldType) -> None:
        if not isinstance(value, FieldType):
            raise TypeError(f"Invalid type {type(value)} for field {name}")
        if isinstance(value, bool):
            type_ = "bool"
        elif isinstance(value, str):
            type_ = "string"
        elif isinstance(value, int):
            type_ = "int"
        elif isinstance(value, float):
            type_ = "float"
        elif isinstance(value, Vec3):
            err = f"Invalid Vec3 {name}: {value}"
            if len(value) != 3:
                raise ValueError(err)
            if not all(isinstance(v, float) for v in value):
                raise TypeError(err)
            type_ = "vec3"

        fields[name].type = type_
        fields[name].value = value

    def __getattr__(self, __name: str) -> typing.Any:
        if self.parent.target_game == Game.SAMUS_RETURNS:
            return self._get_extra_field(self.parent.raw.fields, __name)

        if self.parent.target_game == Game.DREAD:
            if __name in self.parent.raw.extra_fields:
                return self._get_extra_field(self.parent.raw.extra_fields, __name)

            if (
                self.parent.raw.fields is not None
                and __name in self.parent.raw.fields.fields
            ):
                return self.parent.raw.fields.fields[__name]

            cctype = self.parent.get_component_type_class()
            if __name in cctype.fields:
                return None

            raise self._get_attr_error(__name)

    def __setattr__(self, __name: str, __value: typing.Any) -> None:
        if __name == "parent":
            return super().__setattr__(__name, __value)

        if self.parent.target_game == Game.SAMUS_RETURNS:
            self._set_extra_field(self.parent.raw.fields, __name, __value)
            return

        if self.parent.target_game == Game.DREAD:
            if __name in self.parent.raw.extra_fields:
                self._set_extra_field(self.parent.raw.extra_fields, __name, __value)
                return

            cctype = self.parent.get_component_type_class()
            if __name not in cctype.all_fields:
                raise self._get_attr_error(__name)

            if __value is None:
                if self.parent.raw.fields is not None:
                    self.parent.raw.fields.fields.pop(__name, None)
                    if not self.parent.raw.fields.fields:
                        self.parent.raw.fields = None
                return

            if self.parent.raw.fields is None:
                self.parent.raw.fields = Container(
                    empty_string="",
                    root="Root",
                    fields=Container(),
                )

            new_fields = copy.copy(self.parent.raw.fields.fields)
            new_fields[__name] = __value
            cctype.verify_integrity(new_fields)

            self.parent.raw.fields.fields[__name] = __value

    def _get_attr_error(self, __name: str) -> AttributeError:
        return AttributeError(
            f"'{self.parent.get_component_type()}' object has no field '{__name}'",
            name=__name, obj=self
        )


class Component:
    def __init__(self, raw: Container, target_game: Game) -> None:
        self._raw = raw
        self.target_game = target_game

    @property
    def raw(self) -> Container:
        return self._raw

    def get_component_type(self) -> str:
        return find_charclass_for_type(self.type)

    @property
    def type(self) -> str:
        if self.target_game == Game.SAMUS_RETURNS:
            raise AttributeError(name="type", obj=self)
        if self.target_game == Game.DREAD:
            return self.raw.type

    @type.setter
    def type(self, value: str):
        if self.target_game == Game.SAMUS_RETURNS:
            raise AttributeError(name="type", obj=self)
        if self.target_game == Game.DREAD:
            self.raw.type = value

    def get_component_type_class(self) -> type_lib.StructType:
        return get_type_lib_for_game(self.target_game).get_type(self.get_component_type())

    @property
    def fields(self) -> ComponentFields:
        return ComponentFields(self)

    def copy_fields_from(self, value: ComponentFields):
        self.raw.fields = value.parent.raw.fields
        if self.target_game == Game.DREAD:
            self.raw.extra_fields = value.parent.raw.extra_fields

    # FIXME: mypy doesn't support getter/setter with different types: https://github.com/python/mypy/issues/13127
    @property
    def functions(self) -> Sequence[ActorDefFunc]:
        return tuple(ActorDefFunc(func) for func in self.raw.functions)

    @functions.setter
    def functions(self, value: Sequence[ActorDefFunc]):
        self.raw.functions = ListContainer(
            Container(func.raw) for func in value
        )

    @property
    def dependencies(self) -> Container | ListContainer | None:
        return self.raw.dependencies

    @dependencies.setter
    def dependencies(self, value: Container | ListContainer | None):
        self.raw.dependencies = value


class Bmsad(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return {
            Game.SAMUS_RETURNS: BMSAD_SR,
            Game.DREAD: BMSAD_Dread,
        }[target_game]

    @property
    def name(self) -> str:
        return self.raw.name

    @name.setter
    def name(self, value: str):
        self.raw.name = value

    @property
    def model_name(self) -> str:
        if self.target_game == Game.DREAD and self.raw.type == "CActorDef":
            raise AttributeError(name="model_name", obj=self)
        return self.raw.header.model_name

    @model_name.setter
    def model_name(self, value: str):
        if self.target_game == Game.DREAD and self.raw.type == "CActorDef":
            raise AttributeError(name="model_name", obj=self)
        self.raw.header.model_name = value

    @property
    def sub_actors(self) -> list[str]:
        return self.raw.header.sub_actors

    @sub_actors.setter
    def sub_actors(self, value: typing.Iterable[str]):
        self.raw.header.sub_actors = ListContainer(value)

    @property
    def components(self) -> dict[str, Component]:
        return {
            name: Component(raw, self.target_game)
            for name, raw in self.raw.components.items()
        }

    @components.setter
    def components(self, value: dict[str, Component]):
        self.raw.components = Container({
            name: component.raw
            for name, component in value.items()
        })

    @property
    def action_sets(self) -> list[Bmsas]:
        if self.target_game == Game.DREAD:
            return [
                self.editor.get_file(ref, Bmsas)
                for ref in self.action_set_refs
            ]
        if self.target_game == Game.SAMUS_RETURNS:
            return [
                Bmsas(action_set, Game.SAMUS_RETURNS)
                for action_set in self.raw.action_sets
            ]

    @action_sets.setter
    def action_sets(self, value: typing.Iterable[Bmsas]):
        if self.target_game == Game.DREAD:
            raise AttributeError(name="action_sets", obj=self)
        if self.target_game == Game.SAMUS_RETURNS:
            self.raw.action_sets = ListContainer([
                action_set.raw
                for action_set in value
            ])

    @property
    def action_set_refs(self) -> list[str]:
        if self.target_game == Game.SAMUS_RETURNS:
            raise AttributeError(name="action_set_refs", obj=self)
        if self.target_game == Game.DREAD:
            return self.raw.action_sets

    @action_set_refs.setter
    def action_set_refs(self, value: typing.Iterable[str]):
        if self.target_game == Game.SAMUS_RETURNS:
            raise AttributeError(name="action_set_refs", obj=self)
        if self.target_game == Game.DREAD:
            self.raw.action_sets = ListContainer(value)

    @property
    def sound_fx(self) -> list[tuple[str, int]]:
        if self.raw.sound_fx is None:
            return []
        return [(sfx[0], sfx[1]) for sfx in self.raw.sound_fx]

    @sound_fx.setter
    def sound_fx(self, value: typing.Iterable[tuple[str, int]]):
        self.raw.sound_fx = ListContainer(
            ListContainer(sfx) for sfx in value
        )
        if self.target_game == Game.SAMUS_RETURNS and not self.raw.sound_fx:
            self.raw.sound_fx = None

