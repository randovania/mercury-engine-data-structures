import typing
from pathlib import Path

import numpy
from matplotlib.patches import Polygon

from mercury_engine_data_structures import hashed_names
from mercury_engine_data_structures.formats import Bmscc, Brfld
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


def main(root: Path, target_level: str):
    all_names = hashed_names.all_asset_id_to_name()
    game = Game.DREAD

    with PkgEditor.open_pkgs_at(root) as pkg_editor:
        pkg_editor = typing.cast(PkgEditor, pkg_editor)

        bmscc: Bmscc = None
        brfld: Brfld = None

        for asset_id, name in all_names.items():
            if target_level not in name:
                continue

            if name.endswith("bmscc"):
                print(f"Reading {name}...")
                bmscc = Bmscc.parse(pkg_editor.get_asset_with_asset_id(asset_id), game)
            #
            # elif name.endswith("brfld"):
            #     print(f"Reading {name}...")
            #     brfld = Brfld.parse(pkg_editor.get_asset_with_asset_id(asset_id), game)

    if bmscc is None:
        raise ValueError("DATA IS NONE")

    import matplotlib.pyplot as plt

    handles = []

    for entry in bmscc.raw.layers[0].entries:
        assert entry.type == "POLYCOLLECTION2D"

        x1, y1, x2, y2 = entry.data.total_boundings
        if abs(x1) > 59999 or abs(y1) > 59999 or abs(x2) > 59999 or abs(y2) > 59999:
            print("SKIPPED")
            continue

        assert len(entry.data.polys) == 1
        raw_vertices = []
        for v in entry.data.polys[0].points:
            raw_vertices.append((v.x, v.y))
        vertices = numpy.array(raw_vertices)
        c = [0.2, 0.7, 0.6]

        patch = Polygon(vertices, linewidth=1, edgecolor=c, facecolor=(c[0], c[1], c[2], 0.1))
        plt.gca().add_patch(patch)
        plt.text((x1 + x2) / 2, (y1 + y2) / 2, entry.name[17:], color=c, ha='center', size='x-small')
        handles.append(patch)

    # plt.legend(handles=handles, prop={'size': 6})
    plt.plot()


if __name__ == '__main__':
    main(Path("E:/DreadExtract"), "s010_cave")
