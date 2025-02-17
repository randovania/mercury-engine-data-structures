from __future__ import annotations

import contextlib

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bcmdl import Bcmdl

# these models are copied into the pkg from the original scenarios, confirmed to bytematch
dread_bcmdl_duplicate = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_cut01.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_cut02.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_floor.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_lshaft01.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_lshaft02.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_lshaft05.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel001.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel002.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel006.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel007.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel008.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel012.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel025.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel028.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel030.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel038.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel040.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel044.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel048.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel050.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel052.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel055.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel057.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel058.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel062.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel066.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/part011_m1_mapmodel067.bcmdl",
    "maps/levels/c10_samus/s201_bossrush_scorpius/models/vignette_part011_m1_vignette.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_decals01.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_decals02.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_decals03.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_decals04.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_lshaft01.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel00.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel01.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel018_breakable.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel02.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel03.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel04.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel05.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel06.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel07.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel08.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel09.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel10.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel11.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel12.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel13.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel14.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/part027_n2_mapmodel15.bcmdl",
    "maps/levels/c10_samus/s202_bossrush_kraid/models/vignette_part027_n2_mapmodel00.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_02.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_05.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_06.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_07.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_08.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_10.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_11.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_12.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_15.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_18.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_19.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_23.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_mapmodel_25.bcmdl",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/models/part028_s5_vignette_001.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/part020_jp6_mapmodel01.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/part020_jp6_mapmodel02.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/part020_jp6_mapmodel03.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/part020_jp6_mapmodel05.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/part020_jp6_mapmodel06.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/part020_jp6_mapmodel07.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/vignette_part020_jp6_00.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/vignette_part020_jp6_01.bcmdl",
    "maps/levels/c10_samus/s204_bossrush_drogyga/models/vignette_part020_jp6_02.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_lightshaft001.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel00.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel01.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel02.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel03.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel04.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel05.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel06.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel07.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel08.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel09.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel10.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mapmodel12.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/part020_f3_mattepaint00.bcmdl",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/models/vignette_part020_f3.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_p_lightshaft01.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_pb6_mapmodel007.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_pb6_mapmodel008.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_pb6_mapmodel017.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_pb6_matte01.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_pb6_matte02.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/part006_pb6_planereflection.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/vignette_p_part006model.bcmdl",
    "maps/levels/c10_samus/s206_bossrush_escue/models/vignette_part006_pb6_01.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_p2_columnsbreak.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_p2_columnsbreakpost.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_p_lava.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s2_mattepaint_rocks.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s2_mattepaint_skybox.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_01.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_027.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_028.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_029.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_05.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_06.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_08.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_21.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_24.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_25.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_26.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_mapmodel_tapa.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_s3_shadow.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_x1_mapmodel_1901.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/part003_x1_mapmodel_1904.bcmdl",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/models/vignette_part003_x1_vignette_00.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_casca43000.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel00.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel00b.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel02.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel03.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel03b.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel08.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_mapmodel10d.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_sg_casca050.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_sg_casca051.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_sg_casca052.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_sg_casca43001.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/part009_jp11_sg_casca43002.bcmdl",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/models/vignette_part009_jp11_00.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_lightshaft01.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_lightshaft02.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel000.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel001.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel002.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel003.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel004.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel005.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel006.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel007.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel008.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel009.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel010.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mapmodel011.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_mattepaint001.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_sg_casca106.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/part018_pb7_sg_casca107.bcmdl",
    "maps/levels/c10_samus/s209_bossrush_golzuna/models/vignette_part018_pb7_00.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_decal02.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_decal04.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_hideable00.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_hideable02.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_hideable03.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mapmodel00.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mapmodel01.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mapmodel03.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mapmodel04.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mapmodel06.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mapmodel07.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mattepaint01.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/part007_e11_mattepaint02.bcmdl",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/models/vignette_part007_e11_vignette00.bcmdl",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/models/part003_jg13_centralunit00.bcmdl",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/models/part003_jg13_centralunit02.bcmdl",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/models/part003_jg13_centralunitl01.bcmdl",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/models/part003_jg13_mapmodel17.bcmdl",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/models/part003_jg13_tapa01.bcmdl",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/models/vignette_part003_jg13_mapmodel_vignette.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_lshaft02.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_lshaft03.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_lshaft04.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel00.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel01.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel04.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel05.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel06.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel07.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel09.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel10.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_mapmodel11_sky1.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca1000.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca1001.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca1002.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca1003.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca1004.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca2000.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca2001.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca2002.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca2003.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_jp6_sg_casca2004.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part001_p_lshaft01.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part002_n1_planereflection.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_mapmodel02_sky004.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_mapmodel02_sky005_hideable.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_mapmodel03.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_mapmodel04.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_mapmodel05_decals.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_planereflect01.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_jp5_planereflect02.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_p0_lshaft01.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_p0_lshaft02.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/part004_p_cut0101.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/vignette_part001_jp6_00.bcmdl",
    "maps/levels/c10_samus/s212_bossrush_commander/models/vignette_part004_jp5_00.bcmdl",
]
dread_bcmdl_expected_failure = [
    "actors/characters/morphball/models/labase.bcmdl",
    "actors/characters/morphball/models/ladamage.bcmdl",
    "actors/characters/samus/models/phasedisplacement_new.bcmdl",
    "actors/items/powerup_sonar/models/powerup_sonar.bcmdl",
    "actors/props/teleporter/models/samusaura.bcmdl",
    "actors/props/teleporter/models/teleporttunnel.bcmdl",
    "actors/weapons/grapplebeam/models/grapplelightning_1.bcmdl",
    "actors/weapons/weaponboost/models/weaponboost.bcmdl",
    "actors/weapons/weaponboost/models/weaponboostmorphball.bcmdl",
    "system/engine/models/immune.bcmdl",
    "system/engine/models/sedisolve.bcmdl",
    "system/engine/models/sedisolver.bcmdl",
    "system/engine/models/selected_hi.bcmdl",
    "system/engine/models/selected_lo.bcmdl",
]


@pytest.mark.parametrize("bcmdl_path", dread_data.all_files_ending_with(".bcmdl", dread_bcmdl_duplicate))
def test_compare_bcmdl_dread(dread_tree_100, bcmdl_path):
    if bcmdl_path in dread_bcmdl_expected_failure:
        expectation = pytest.raises(AssertionError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(Bcmdl, dread_tree_100, bcmdl_path)


def test_change_material(dread_tree_100):
    construct_class = Bcmdl.construct_class(dread_tree_100.target_game)
    model = dread_tree_100.get_parsed_asset(
        "actors/props/doorshieldsupermissile/models/doorshieldsupermissile.bcmdl", type_hint=Bcmdl
    )

    # ensure replacing it with the exact length works
    replace = "actors/props/doorshieldsupermissile/models/imats/doorshieldsupermissile_mp_opaque_69.bsmat"
    model.change_material_path("mp_opaque_01", replace)
    encoded = construct_class.build(model.raw, target_game=dread_tree_100.target_game)

    assert encoded[0x5845:0x58A0] == (
        b"actors/props/doorshieldsupermissile/models/imats/doorshieldsupermissile_mp_opaque_69.bsmat\0"
    )

    # ensure replacing it with a shorter length works
    replace = "actors/props/doorshieldsupermiss/models/imats/doorshieldsupermiss_mp_opaque_01.bsmat"
    model.change_material_path("mp_opaque_01", replace)
    encoded2 = construct_class.build(model.raw, target_game=dread_tree_100.target_game)

    assert encoded2[0x5845:0x58A0] == (
        b"actors/props/doorshieldsupermiss/models/imats/doorshieldsupermiss_mp_opaque_01.bsmat\0\0\0\0\0\0\0"
    )

    long_path = "actors/props/doorshieldsupermissile/models/imats/doorshieldsupermissile_mp_opaque_420.bsmat"
    expectation = pytest.raises(ValueError)
    with expectation:
        model.change_material_path("mp_opaque_01", long_path)
