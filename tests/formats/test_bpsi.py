import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bpsi import Bpsi


@pytest.mark.parametrize("bpsi_path", dread_data.all_files_ending_with(".bpsi"))
def test_bpsi_dread_100(dread_tree_100, bpsi_path):
    parse_build_compare_editor(Bpsi, dread_tree_100, bpsi_path)


@pytest.mark.parametrize("bpsi_path", dread_data.all_files_ending_with(".bpsi"))
def test_bpsi_dread_210(dread_tree_210, bpsi_path):
    parse_build_compare_editor(Bpsi, dread_tree_210, bpsi_path)


@pytest.mark.parametrize("bpsi_path", samus_returns_data.all_files_ending_with(".bpsi"))
def test_bpsi_sr(samus_returns_tree, bpsi_path):
    parse_build_compare_editor(Bpsi, samus_returns_tree, bpsi_path)
