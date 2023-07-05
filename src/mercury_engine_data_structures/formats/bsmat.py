import construct
from construct.core import (
    Array,
    Byte,
    Const,
    Construct,
    Container,
    Enum,
    Flag,
    Hex,
    Int32sl,
    Int32ul,
    PrefixedArray,
    Struct,
    Switch,
)

from mercury_engine_data_structures.common_types import Char, Float, StrId
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

# these seem to be using Unity ShaderLab, or at least the gist I borrowed this from uses similar teminology
# source for most binary info: https://gist.github.com/KillzXGaming/9817455559544cb3613f99184aa3ed68

# === ENUMS ===

# seems to be missing some values, example: missile expansion material uses 8
# cant seem to find info on google easily so no docs
translucency_type = Enum(
    Int32ul,
    TILING_CLAMP=0,
    TILING_CLAMPCOLOR=1,
    TILING_REPEAT=2,
    TILING_MIRROR=3,
    TILING_INVALID=0xffffffff
)

# blend operation
# https://docs.unity3d.com/Manual/SL-BlendOp.html
blend_op = Enum(
    Int32ul,
    ADD=0,
    SUB=1,
    REV_SUB=2,
    MIN=3,
    MAX=4,
    INVALID=0xffffffff
)

# blend mode
# https://docs.unity3d.com/Manual/SL-Blend.html
blend_mode = Enum(
    Int32ul,
    ZERO=0,
    ONE=1,
    SRC_COLOR=2,
    ONE_MINUS_SRC_COLOR=3,
    DST_COLOR=4,
    ONE_MINUS_DST_COLOR=5,
    SRC_ALPHA=6,
    ONE_MINUS_SRC_ALPHA=7,
    DST_ALPHA=8,
    ONE_MINUS_DST_ALPHA=9,
    INVALID=0xffffffff
)

# cull command
# https://docs.unity3d.com/Manual/SL-Cull.html
polygon_cull_mode = Enum(
    Int32ul,
    BACK = 2,
    FRONT = 3,
    OFF = 4,
    INVALID = 0xffffffff
)

# stencil operation value
# https://docs.unity3d.com/Manual/SL-Stencil.html#stencil-operation-values
stencil_op = Enum(
    Int32ul,
    KEEP=0,
    ZERO=1,
    REPLACE=2,
    INCR_SAT=3,
    DECR_SAT=4,
    INVERT=5,
    INCR_WRAP=6,
    DECR_WRAP=7,
    INVALID=0xffffffff
)

compare_mode = Enum(
    Int32ul,
    CMPMODE_ALWAYS=0,
    CMPMODE_NEVER=1,
    CMPMODE_EQUAL=2,
    CMPMODE_NOTEQUAL=3,
    CMPMODE_LESS=4,
    CMPMODE_LESSEQUAL=5,
    CMPMODE_GREATER=6,
    CMPMODE_GREATEREQUAL=7,
    CMPMODE_MAX_COUNT=8,
    CMPMODE_INVALID=0xffffffff
)

fill_mode = Enum(
    Int32ul,
    SOLID=0,
    WIRE=1,
    INVALID=0xffffffff
)

shader_type = Enum(
    Int32ul,
    VERTEX=0,
    PIXEL=1,
    GEOMETRY=2,
    INVALID=0xffffffff
)

# seems to be a fancier version of point/bilinear/trilinear with extra trilinear/mipmap stuff
filter_mode = Enum(
    Int32ul,
    FILTER_NEAREST=0,
    FILTER_LINEAR=1,
    FILTER_NEAREST_MIP_NEAREST=2,
    FILTER_NEAREST_MIP_LINEAR=3,
    FILTER_LINEAR_MIP_NEAREST=4,
    FILTER_LINEAR_MIP_LINEAR=5,
    FILTER_INVALID=0xffffffff
)

tile_wrap_mode = Enum(
    Int32ul,
    TILING_CLAMP=0,
    TILING_CLAMP_COLOR=1,
    TILING_REPEAT=2,
    TILING_MIRROR=3,
    TILING_INVALID=0xffffffff
)

# === STRUCTS ===

# seems to be a combo of Blend and BlendOp
# ie "Blend source dest && BlendOp operation"
blend_state = Struct(
    enabled = Flag,
    operation = blend_op,
    source = blend_mode,
    dest = blend_mode
)

# Stencil test
# https://docs.unity3d.com/Manual/SL-Stencil.html
stencil_test = Struct(
    enabled = Flag,
    mask = Int32ul,
    ref = Int32ul,
    fail = stencil_op,
    success  = stencil_op, # "pass" is from gist, but keywords exist :P
    depth_fail = stencil_op,
    depth_success = stencil_op,
    cmp_mode = compare_mode
)

# alpha test, seems to be deprecated/not exist in HLSL
# https://docs.unity3d.com/Manual/SL-AlphaTest.html
alpha_test = Struct(
    enabled=Flag,
    function=compare_mode,
    ref=Float
)

# depth test
depth_state = Struct(
    depth_test=Byte,
    depth_write=Byte,
    depth_mode=compare_mode,
    z_prepass=Byte
)

# uniform params, stuff like "vConstant0" or "fAlbedoEmissiveMultiplier"
uniform_param = Struct(
    name=StrId,
    type=Char,
    value=Switch(
        construct.this.type,
        {
            "f": PrefixedArray(Int32ul, Float),
            "i": PrefixedArray(Int32ul, Int32sl),
            "u": PrefixedArray(Int32ul, Int32ul)
        }
    )
)

# sampler params, imports texture files typically
sampler_param = Struct(
    name=StrId,
    sampler=StrId,
    type=StrId,
    index=Int32ul,
    filepath=StrId,
    min_filter=filter_mode,
    max_filter=filter_mode,
    mip_filter=filter_mode,
    cmp_mode=compare_mode,
    wrap_mode_U=tile_wrap_mode,
    wrap_mode_V=tile_wrap_mode,
    border_color=Array(4, Byte),
    min_lod=Float,
    lod_bias=Float,
    anisotropic=Float,
    max_mip_level=Float,
    max_anisotropy=Float
)

shader_stage = Struct(
    # there was a Int32ul "type" param in the gist here, that seems to be gone now.
    uniform_params=PrefixedArray(Int32ul, uniform_param),
    sampler_params=PrefixedArray(Int32ul, sampler_param)
)

BSMAT = Struct(
    _magic = Const(b"MSUR"),
    _ver = Const(0x00110002, Hex(Int32ul)),
    name = StrId,

    # Binary shader data
    type = translucency_type,
    render_layer = Int32ul,
    shader_path = StrId,
    blendstate = blend_state,
    cullstate = polygon_cull_mode,
    stencilstate = stencil_test,
    alphastate = alpha_test,
    fillmode = fill_mode,
    depth = depth_state,

    # differs from the gist but its const across all files
    _const0 = Const(0, Int32ul), # 0
    _const1 = Const(2, Int32ul), # 2
    _const2 = Const(0, Int32ul), # 0

    # these also differ from gist and mostly are only in system shaders, from what I can tell
    extra_uniforms = PrefixedArray(Int32ul, uniform_param),
    extra_samplers = PrefixedArray(Int32ul, sampler_param),

    # important stuff here!
    shader_stages = PrefixedArray(Int32ul, shader_stage),

    _end = construct.Terminated
)

class Bsmat(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BSMAT

    def _get_param(self, uniform_name: str, uniforms_arr: Construct) -> Container:
        for u in uniforms_arr:
            if u.name == uniform_name:
                return u
        return None

    def get_uniform(self, uniform_name: str, in_extra: bool = False, shader_stage: int = 0):
        if in_extra:
            return self._get_param(uniform_name, self.raw.extra_uniforms)
        else:
            return self._get_param(uniform_name, self.raw.shader_stages[shader_stage].uniform_params)

    def get_sampler(self, sampler_name: str, in_extra: bool = False, shader_stage: int = 0):
        if in_extra:
            return self._get_param(sampler_name, self.raw.extra_samplers)
        else:
            return self._get_param(sampler_name, self.raw.shader_stages[shader_stage].sampler_params)
