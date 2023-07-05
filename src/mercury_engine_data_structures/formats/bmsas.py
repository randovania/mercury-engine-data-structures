import construct
from construct.core import (
	Array, Byte, Const, Construct, Flag, Hex, If, IfThenElse, Int16ul, Int32ul, Int32sl, Int64ul, Int64sl, Optional, Peek, Select, Struct, Switch
)

from mercury_engine_data_structures.common_types import Float, make_vector, DictAdapter
from mercury_engine_data_structures.formats import BaseResource 
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.construct_extensions.strings import PascalStringRobust

StrId = PascalStringRobust(Int16ul, "utf-8")

Argument = Struct(
	key=PropertyEnum,
	value=Switch(
		construct.this.key[0],
		{
			's': Select(StrId, Hex(Int64ul)),
			'f': Float,
			'b': Flag,
			'u': Int32ul,
			'i': Int32sl,
			'e': Int32ul,
			'o': Int32ul,
			'v': Switch(
				construct.this.key,
				{
					'vColorStart': Int32ul,
					'vColorEnd': Int32ul,
				},
				default=Array(3, Float)
			),
			't': Int32ul,
		},
		default=construct.Error
	)
)

ArgList = DictAdapter(make_vector(Argument))

Event = Struct(
	type = PropertyEnum,
	unk = Int32ul,
	args = ArgList
)

EventList = Struct(
	counts = Array(5, Int16ul),
	events0 = Array(construct.this.counts[0], Struct(
		unk = Int32ul,
		event = Event,
	)),
	events1 = Array(construct.this.counts[1], Event),
	events2 = Array(construct.this.counts[2], Event),
	events3 = Array(construct.this.counts[3], Event),
	events4 = Array(construct.this.counts[4], Event),
)

Track = Struct(
	type = PropertyEnum,
	unk0 = Int32ul,
	unk1 = Int32ul,
	args = ArgList,
)

TrackList = make_vector(Track)

Animation = Struct(
	prefix = PropertyEnum, # CAnimationPrefix::SPrefix
	name = StrId,
	action_type = PropertyEnum,
	unk0 = Int32ul,
	unk1 = Flag,
	unk2 = Byte, # Between 0 and 3
	unk3 = Flag,
	unk4 = Flag,
	unk5 = Int32ul,
	unk6 = Float,
	unk7 = Float,
	unk8 = Int32ul,
	unk9 = Float,
	unk10 = If(construct.this.unk0 & 32, Select(PropertyEnum, Hex(Int64ul))),
	unk11 = If(construct.this.unk0 & 64, StrId),
	unk12 = make_vector(Struct(
		unk1=Float,
		unk2=Float,
		unk3=Float,
	)),
	unk13 = make_vector(Struct(
		name = StrId,
		unk0 = make_vector(Struct(
			unk0 = Array(3, Hex(Int64ul)),
			unk1 = StrId,
		)),
		tracks = TrackList,
		events = EventList,
	)),
	tracks = TrackList,
	events = EventList,
	unk14 = make_vector(Struct(
		unk0 = Int64ul,
		curve = StrId,
		unk1 = make_vector(Select(PropertyEnum, Hex(Int64ul))),
		unk2 = Int32ul,
	)),
)

BMSAS = Struct(
	_magic=Const(b"MSAS"),
	_version=Const(0x00170003, Hex(Int32ul)),
	name=StrId,
	unk=Hex(Int32ul),
	animations=make_vector(Animation),
	_end = construct.Terminated,
)
class Bmsas(BaseResource):
	@classmethod
	def construct_class(cls, target_game: Game) -> Construct:
		return BMSAS
