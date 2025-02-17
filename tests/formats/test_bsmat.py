from __future__ import annotations

import pytest
from construct.core import ListContainer
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bsmat import Bsmat


@pytest.mark.parametrize("bsmat_path", dread_data.all_files_ending_with(".bsmat"))
def test_compare_bsmat_dread(dread_tree_100, bsmat_path):
    parse_build_compare_editor(Bsmat, dread_tree_100, bsmat_path)


def test_get_uniform(dread_tree_100):
    mat = dread_tree_100.get_parsed_asset(
        "system/engine/surfaces/mp_accesspointabstractcubesorbital.bsmat", type_hint=Bsmat
    )

    extra_uniform = mat.get_uniform("vConstant0", in_extra=True)
    assert extra_uniform.name == "vConstant0"
    assert extra_uniform.type == "f"
    assert extra_uniform.value == ListContainer([1.0, 0.0, 0.0, 0.0])

    standard_uniform = mat.get_uniform("fAlbedoEmissiveColorMultiplier")
    assert standard_uniform.name == "fAlbedoEmissiveColorMultiplier"
    assert standard_uniform.type == "f"
    assert standard_uniform.value == ListContainer([1.0, 1.0, 1.0, 1.0])


def test_get_sampler(dread_tree_100):
    mat = dread_tree_100.get_parsed_asset(
        "system/engine/surfaces/mp_accesspointabstractcubesorbital.bsmat", type_hint=Bsmat
    )

    extra_sampler = mat.get_sampler("texVoice", in_extra=True)
    assert extra_sampler.name == "texVoice"
    assert extra_sampler.type == "texture2D"
    assert extra_sampler.anisotropic == 8.0

    standard_sampler = mat.get_sampler("texNormals")
    assert standard_sampler.name == "texNormals"
    assert standard_sampler.type == "texture2D"
    assert standard_sampler.anisotropic == 8.0
