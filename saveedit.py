from pathlib import Path
from mercury_engine_data_structures.formats.bmssv import Bmssv
from mercury_engine_data_structures.game_check import Game

samus = Path("C:/Users/dunca/AppData/Roaming/Ryujinx/bis/user/save/0000000000000001/0/profile0/samus.bmssv")
common = Path("C:/Users/dunca/AppData/Roaming/Ryujinx/bis/user/save/0000000000000001/0/profile0/common.bmssv")

save = Bmssv.parse(samus.read_bytes(), Game.DREAD)
save2 = Bmssv.parse(common.read_bytes(), Game.DREAD)

visibility = {
    "@type": u'minimapGrid::TMinimapVisMap',
    83: u'1@17o3@2 1o7@2o7@610 ',
}
save.raw.Root.hashSections.s020_magma.dctProps.MINIMAP_VISIBILITY = visibility

icons = save2.raw.Root.hashSections.MINIMAP.dctProps["MINIMAP:GlobalIcons"]
for scenario in ["s010_cave", "s020_magma", "s030_baselab", "s040_aqua", "s050_forest", "s060_quarantine", "s070_basesanc", "s080_shipyard", "s090_skybase"]:
    if scenario in icons:
        continue
    icons[scenario] = []

samus.write_bytes(save.build())
common.write_bytes(save2.build())
