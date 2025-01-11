from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor_parsed

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmscc import Bmscc

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bmscc",
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bmscd",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bmscc",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bmscd",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bmscc",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bmscd",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bmscc",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bmscd",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bmscc",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bmscd",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bmscc",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bmscd",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bmscc",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bmscd",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bmscc",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bmscd",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bmscc",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bmscd",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bmscc",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bmscd",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bmscc",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bmscd",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bmscc",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bmscd",
]

sr_missing_cc = [
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmscc",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmscc",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmscc",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmscc",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmscc",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmscc",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmscc",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmscc",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmscc",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmscc",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmscc",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmscc",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmscc",
]

sr_missing_cd = [
    "actors/props/doorcreatureleft/collisions/doorcreatureleft.bmscd",
    "actors/props/grapplemovable4x1/collisions/grapplemovable4x1.bmscd",
    "actors/props/ridleyclouds/collisions/ridleyclouds.bmscd",
    "actors/props/spenergybestowalstatue/collisions/spenergybestowalstatue.bmscd",
    "actors/props/unlockarea/collisions/unlockarea.bmscd",
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmscd",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmscd",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmscd",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmscd",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmscd",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmscd",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmscd",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmscd",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmscd",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmscd",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmscd",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmscd",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmscd",
]


@pytest.mark.parametrize(
    "file_path",
    dread_data.all_files_ending_with(".bmscc", bossrush_assets)
    + dread_data.all_files_ending_with(".bmscd", bossrush_assets),
)
def test_compare_collision_dread_100(dread_tree_100, file_path):
    parse_build_compare_editor_parsed(Bmscc, dread_tree_100, file_path)


@pytest.mark.parametrize("file_path", bossrush_assets)
def test_compare_dread_210(dread_tree_210, file_path):
    parse_build_compare_editor_parsed(Bmscc, dread_tree_210, file_path)


@pytest.mark.parametrize(
    "file_path",
    samus_returns_data.all_files_ending_with(".bmscc", sr_missing_cc)
    + samus_returns_data.all_files_ending_with(".bmscd", sr_missing_cd),
)
def test_compare_collision_msr(samus_returns_tree, file_path):
    parse_build_compare_editor_parsed(Bmscc, samus_returns_tree, file_path)


@pytest.fixture()
def surface_bmscc(samus_returns_tree) -> Bmscc:
    return samus_returns_tree.get_parsed_asset("maps/levels/c10_samus/s000_surface/s000_surface.bmscd", type_hint=Bmscc)


def test_get_data(surface_bmscc: Bmscc):
    entry = surface_bmscc.get_entry()
    assert len(entry.data) == 5
    assert len(entry.polys) == 17
    assert entry.position.raw == [0.0, 0.0, 0.0]


def test_modifying_collision(surface_bmscc: Bmscc):
    poly = surface_bmscc.get_entry().get_poly(2)
    point = poly.get_point(5)
    assert point.position.raw == [-900.0, -7400.0]


def test_get_boundings(surface_bmscc: Bmscc):
    total_boundings = surface_bmscc.get_entry().total_boundings
    polys = surface_bmscc.get_entry().polys
    for i, poly in enumerate(polys):
        poly_boundings = surface_bmscc.get_entry().get_poly(i).boundings
        # Boundings for polygons are in the order: x (Left), y (Bottom), z (Right), w (Top)
        # Assert that the boundings are confined within the total bounds of the collision_camera
        assert poly_boundings.x >= total_boundings.x
        assert poly_boundings.y >= total_boundings.y
        assert poly_boundings.z <= total_boundings.z
        assert poly_boundings.w <= total_boundings.w


def test_get_poly(surface_bmscc: Bmscc):
    poly = surface_bmscc.get_entry().get_poly(5)
    assert poly.num_points == 12


def test_add_point(surface_bmscc: Bmscc):
    point = (6000.0, -5400.0)
    poly = surface_bmscc.get_entry().get_poly(3)
    poly.add_point(point)
    assert poly.get_point(0) is not None
