import contextlib

import construct
import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import dread_types
from mercury_engine_data_structures.formats.bmsad import ActorDefFunc, Bmsad

expected_dread_failures = {
    "actors/props/pf_mushr_fr/charclasses/pf_mushr_fr.bmsad",
}
expected_sr_failures = set()

sr_missing = [
    "actors/items/itemsphere_springball/charclasses/itemsphere_springball.bmsad",
    "actors/items/life/charclasses/life.bmsad",
    "actors/items/lifebig/charclasses/lifebig.bmsad",
    "actors/items/powerup_spinattack/charclasses/powerup_spinattack.bmsad",
    "actors/props/doorchargeclosed/charclasses/doorchargeclosed.bmsad",
    "actors/props/doorcreatureleft/charclasses/doorcreatureleft.bmsad",
    "actors/props/doorcreatureright/charclasses/doorcreatureright.bmsad",
    "actors/props/grapplemovable4x1/charclasses/grapplemovable4x1.bmsad",
    "actors/props/heatzone/charclasses/heatzone.bmsad",
    "actors/props/poisonzone/charclasses/poisonzone.bmsad",
    "actors/props/unlockarea/charclasses/unlockarea.bmsad",
    "actors/props/waterzone/charclasses/waterzone.bmsad",
    "actors/spawnpoints/spawnpointfleechswarm/charclasses/spawnpointfleechswarm.bmsad",
    "actors/weapons/energywave/charclasses/energywave.bmsad",
    "cutscenes/area2cam/takes/01/actors/samus/samus.bmsad",
    "cutscenes/area3cam/takes/01/actors/samus/samus.bmsad",
    "cutscenes/brokenchozostatue/takes/01/actors/samus/samus.bmsad",
    "cutscenes/brokenchozostatue/takes/02/actors/samus/samus.bmsad",
    "cutscenes/elevator/takes/01/actors/baby/baby.bmsad",
    "cutscenes/elevator/takes/01/actors/elevator/elevator.bmsad",
    "cutscenes/elevator/takes/01/actors/samus/samus.bmsad",
    "cutscenes/elevator/takes/02/actors/baby/baby.bmsad",
    "cutscenes/elevator/takes/02/actors/elevator/elevator.bmsad",
    "cutscenes/elevator/takes/02/actors/samus/samus.bmsad",
    "cutscenes/elevator/takes/03/actors/baby/baby.bmsad",
    "cutscenes/elevator/takes/03/actors/elevator/elevator.bmsad",
    "cutscenes/elevator/takes/03/actors/samus/samus.bmsad",
    "cutscenes/elevator/takes/04/actors/baby/baby.bmsad",
    "cutscenes/elevator/takes/04/actors/elevator/elevator.bmsad",
    "cutscenes/elevator/takes/04/actors/samus/samus.bmsad",
    "cutscenes/energyshield/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/energyshield/takes/01/actors/samus/samus.bmsad",
    "cutscenes/energyshield/takes/01/actors/statue/statue.bmsad",
    "cutscenes/energywave/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/energywave/takes/01/actors/samus/samus.bmsad",
    "cutscenes/energywave/takes/01/actors/statue/statue.bmsad",
    "cutscenes/firstchozostatue/takes/01/actors/samus/samus.bmsad",
    "cutscenes/gravitysuit/takes/01/actors/planefade/planefade.bmsad",
    "cutscenes/gravitysuit/takes/01/actors/samusvaria/samusvaria.bmsad",
    "cutscenes/gravitysuit/takes/02/actors/planefade/planefade.bmsad",
    "cutscenes/gravitysuit/takes/02/actors/samus/samus.bmsad",
    "cutscenes/gravitysuit/takes/03/actors/samus/samus.bmsad",
    "cutscenes/gravitysuit/takes/04/actors/samus/samus.bmsad",
    "cutscenes/gravitysuit/takes/05/actors/samus/samus.bmsad",
    "cutscenes/introalpha/takes/01/actors/metroid/metroid.bmsad",
    "cutscenes/introalpha/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introalpha/takes/02/actors/samus/samus.bmsad",
    "cutscenes/introalpha/takes/03/actors/alpha/alpha.bmsad",
    "cutscenes/introalpha/takes/03/actors/larvacocoon/larvacocoon.bmsad",
    "cutscenes/introalpha/takes/03/actors/samus/samus.bmsad",
    "cutscenes/introdnastatue/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introgamma/takes/01/actors/alphacocoon/alphacocoon.bmsad",
    "cutscenes/introgamma/takes/01/actors/gamma/gamma.bmsad",
    "cutscenes/introgamma/takes/01/actors/gammalight/gammalight.bmsad",
    "cutscenes/introgamma/takes/01/actors/samus/samus.bmsad",
    "cutscenes/intromanicminerbotarea3/takes/01/actors/demolish/demolish.bmsad",
    "cutscenes/intromanicminerbotarea3/takes/01/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/intromanicminerbotarea3/takes/01/actors/samus/samus.bmsad",
    "cutscenes/intromanicminerbotchase/takes/01/actors/manicminerbothidden/manicminerbothidden.bmsad",
    "cutscenes/intromanicminerbotchase/takes/01/actors/samus/samus.bmsad",
    "cutscenes/intromanicminerbotchase/takes/01/actors/wall/wall.bmsad",
    "cutscenes/intromanicminerbotchaseph/takes/01/actors/manicminerbothidden/manicminerbothidden.bmsad",
    "cutscenes/intromanicminerbotchaseph/takes/01/actors/samus/samus.bmsad",
    "cutscenes/intrometroidboss/takes/01/actors/metroidboss/metroidboss.bmsad",
    "cutscenes/intrometroidboss/takes/01/actors/samus/samus.bmsad",
    "cutscenes/intrometroidlarvasurface/takes/01/actors/hornoad/hornoad.bmsad",
    "cutscenes/intrometroidlarvasurface/takes/01/actors/metroid/metroid.bmsad",
    "cutscenes/intrometroidlarvasurface/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introomega/takes/10/actors/omega/omega.bmsad",
    "cutscenes/introomega/takes/10/actors/samus/samus.bmsad",
    "cutscenes/introomega/takes/10/actors/zetacocoon/zetacocoon.bmsad",
    "cutscenes/introqueen/takes/01/actors/background/background.bmsad",
    "cutscenes/introqueen/takes/01/actors/queen/queen.bmsad",
    "cutscenes/introqueen/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introqueen/takes/02/actors/background/background.bmsad",
    "cutscenes/introqueen/takes/02/actors/queen/queen.bmsad",
    "cutscenes/introqueen/takes/02/actors/samus/samus.bmsad",
    "cutscenes/introqueen/takes/03/actors/queen/queen.bmsad",
    "cutscenes/introqueen/takes/03/actors/samus/samus.bmsad",
    "cutscenes/introspenergystatue/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introteleporter/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introteleporterarea01/takes/01/actors/platform/platform.bmsad",
    "cutscenes/introteleporterarea01/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introteleporterarea01/takes/01/actors/teleporter/teleporter.bmsad",
    "cutscenes/introteleporterarea01/takes/02/actors/platform/platform.bmsad",
    "cutscenes/introteleporterarea01/takes/02/actors/samus/samus.bmsad",
    "cutscenes/introteleporterarea01/takes/02/actors/teleporter/teleporter.bmsad",
    "cutscenes/introteleporterarea01/takes/03/actors/platform/platform.bmsad",
    "cutscenes/introteleporterarea01/takes/03/actors/samus/samus.bmsad",
    "cutscenes/introteleporterarea01/takes/03/actors/teleporter/teleporter.bmsad",
    "cutscenes/introzeta/takes/01/actors/gammacocoon/gammacocoon.bmsad",
    "cutscenes/introzeta/takes/01/actors/samus/samus.bmsad",
    "cutscenes/introzeta/takes/02/actors/samus/samus.bmsad",
    "cutscenes/introzeta/takes/02/actors/zeta/zeta.bmsad",
    "cutscenes/manicminerbotchaseend/takes/01/actors/itemspacejump/itemspacejump.bmsad",
    "cutscenes/manicminerbotchaseend/takes/01/actors/manicminerbothidden/manicminerbothidden.bmsad",
    "cutscenes/manicminerbotchaseend/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/manicminerbotchaseend/takes/01/actors/mouthrocks/mouthrocks.bmsad",
    "cutscenes/manicminerbotchaseend/takes/01/actors/wall/wall.bmsad",
    "cutscenes/manicminerbotdeath/takes/01/actors/itemsphere/itemsphere.bmsad",
    "cutscenes/manicminerbotdeath/takes/01/actors/manicbrokenface/manicbrokenface.bmsad",
    "cutscenes/manicminerbotdeath/takes/01/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/manicminerbotdeath/takes/01/actors/samus/samus.bmsad",
    "cutscenes/manicminerbotdeath/takes/01/actors/wall/wall.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/01/actors/manicdoors/manicdoors.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/01/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/01/actors/robotsmallworking01/robotsmallworking01.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/01/actors/robotsmallworking02/robotsmallworking02.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/01/actors/robotsmallworking03/robotsmallworking03.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/01/actors/samus/samus.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/02/actors/manicvisor/manicvisor.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/02/actors/samus/samus.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/03/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/03/actors/samus/samus.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/04/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/05/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/manicminerbotfinalbattle/takes/05/actors/samus/samus.bmsad",
    "cutscenes/manicminerbotstealorb/takes/01/actors/manicminerbot/manicminerbot.bmsad",
    "cutscenes/manicminerbotstealorb/takes/01/actors/samus/samus.bmsad",
    "cutscenes/manicminerbotstealorb/takes/01/actors/sand/sand.bmsad",
    "cutscenes/manicminerbotstealorb/takes/01/actors/statueorb/statueorb.bmsad",
    "cutscenes/meleetuto/takes/01/actors/gullugg/gullugg.bmsad",
    "cutscenes/meleetuto/takes/01/actors/samus/samus.bmsad",
    "cutscenes/meleetuto/takes/02/actors/gullugg/gullugg.bmsad",
    "cutscenes/meleetuto/takes/02/actors/samus/samus.bmsad",
    "cutscenes/meleetuto/takes/03/actors/gullugg/gullugg.bmsad",
    "cutscenes/meleetuto/takes/03/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/01/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/01/actors/hatchlingeggbroken/hatchlingeggbroken.bmsad",
    "cutscenes/metroidhatchlingintro/takes/01/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/20/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/20/actors/background/background.bmsad",
    "cutscenes/metroidhatchlingintro/takes/20/actors/hatchlingeggbroken/hatchlingeggbroken.bmsad",
    "cutscenes/metroidhatchlingintro/takes/20/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/25/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/25/actors/hatchlingeggbroken/hatchlingeggbroken.bmsad",
    "cutscenes/metroidhatchlingintro/takes/25/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/30/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/30/actors/background/background.bmsad",
    "cutscenes/metroidhatchlingintro/takes/30/actors/hatchlingeggbroken/hatchlingeggbroken.bmsad",
    "cutscenes/metroidhatchlingintro/takes/30/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/40/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/40/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/40/actors/samushd/samushd.bmsad",
    "cutscenes/metroidhatchlingintro/takes/40/actors/samusnoskin/samusnoskin.bmsad",
    "cutscenes/metroidhatchlingintro/takes/50/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/50/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/50/actors/samusvisor/samusvisor.bmsad",
    "cutscenes/metroidhatchlingintro/takes/60/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/60/actors/samus/samus.bmsad",
    "cutscenes/metroidhatchlingintro/takes/60/actors/samushd/samushd.bmsad",
    "cutscenes/metroidhatchlingintro/takes/70/actors/babyhatchling/babyhatchling.bmsad",
    "cutscenes/metroidhatchlingintro/takes/70/actors/babyhatchlingsmall/babyhatchlingsmall.bmsad",
    "cutscenes/metroidhatchlingintro/takes/70/actors/samus/samus.bmsad",
    "cutscenes/metroidqueendeath/takes/01/actors/background/background.bmsad",
    "cutscenes/metroidqueendeath/takes/01/actors/background2/background2.bmsad",
    "cutscenes/metroidqueendeath/takes/01/actors/background3/background3.bmsad",
    "cutscenes/metroidqueendeath/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/metroidqueendeath/takes/01/actors/queen/queen.bmsad",
    "cutscenes/metroidqueendeath/takes/01/actors/samus/samus.bmsad",
    "cutscenes/metroidqueendeathpowerbomb/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/metroidqueendeathpowerbomb/takes/01/actors/queen/queen.bmsad",
    "cutscenes/metroidqueendeathpowerbomb/takes/01/actors/samus/samus.bmsad",
    "cutscenes/metroidqueenspit/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/metroidqueenspit/takes/01/actors/queen/queen.bmsad",
    "cutscenes/metroidqueenspitpowerbomb/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/metroidqueenspitpowerbomb/takes/01/actors/queen/queen.bmsad",
    "cutscenes/phasedisplacement/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/phasedisplacement/takes/01/actors/samus/samus.bmsad",
    "cutscenes/phasedisplacement/takes/01/actors/statue/statue.bmsad",
    "cutscenes/planetarrival/takes/10/actors/planet/planet.bmsad",
    "cutscenes/planetarrival/takes/10/actors/shipsmall/shipsmall.bmsad",
    "cutscenes/planetarrival/takes/20/actors/cloudssurface/cloudssurface.bmsad",
    "cutscenes/planetarrival/takes/20/actors/shipcutscene/shipcutscene.bmsad",
    "cutscenes/planetarrival/takes/30/actors/shipcutscene/shipcutscene.bmsad",
    "cutscenes/planetarrival/takes/31/actors/samus/samus.bmsad",
    "cutscenes/postcredits/takes/10/actors/hornoad/hornoad.bmsad",
    "cutscenes/postcredits/takes/10/actors/hornoadmimic/hornoadmimic.bmsad",
    "cutscenes/postcredits/takes/10/actors/plants/plants.bmsad",
    "cutscenes/postcredits/takes/10/actors/ridleyhand/ridleyhand.bmsad",
    "cutscenes/postcredits/takes/10/actors/xparasite/xparasite.bmsad",
    "cutscenes/ridley1/takes/10/actors/baby/baby.bmsad",
    "cutscenes/ridley1/takes/10/actors/gunship/gunship.bmsad",
    "cutscenes/ridley1/takes/10/actors/ridleyfloor/ridleyfloor.bmsad",
    "cutscenes/ridley1/takes/10/actors/samus/samus.bmsad",
    "cutscenes/ridley1/takes/10/actors/surfaceplatform/surfaceplatform.bmsad",
    "cutscenes/ridley1/takes/20/actors/baby/baby.bmsad",
    "cutscenes/ridley1/takes/20/actors/rays/rays.bmsad",
    "cutscenes/ridley1/takes/20/actors/ridleystormcs1/ridleystormcs1.bmsad",
    "cutscenes/ridley1/takes/20/actors/samus/samus.bmsad",
    "cutscenes/ridley1/takes/30/actors/baby/baby.bmsad",
    "cutscenes/ridley1/takes/30/actors/gunship/gunship.bmsad",
    "cutscenes/ridley1/takes/30/actors/ridleyfloor/ridleyfloor.bmsad",
    "cutscenes/ridley1/takes/30/actors/samus/samus.bmsad",
    "cutscenes/ridley1/takes/30/actors/surfaceplatform/surfaceplatform.bmsad",
    "cutscenes/ridley1/takes/40/actors/baby/baby.bmsad",
    "cutscenes/ridley1/takes/40/actors/gunship/gunship.bmsad",
    "cutscenes/ridley1/takes/40/actors/rays/rays.bmsad",
    "cutscenes/ridley1/takes/40/actors/ridley/ridley.bmsad",
    "cutscenes/ridley1/takes/50/actors/samus/samus.bmsad",
    "cutscenes/ridley1/takes/60/actors/baby/baby.bmsad",
    "cutscenes/ridley1/takes/60/actors/gunship/gunship.bmsad",
    "cutscenes/ridley1/takes/60/actors/hurricane/hurricane.bmsad",
    "cutscenes/ridley1/takes/60/actors/ridley/ridley.bmsad",
    "cutscenes/ridley1/takes/60/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/10/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/10/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/10/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/100/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/100/actors/rockswall/rockswall.bmsad",
    "cutscenes/ridley2/takes/110/actors/babysmall/babysmall.bmsad",
    "cutscenes/ridley2/takes/110/actors/gunship/gunship.bmsad",
    "cutscenes/ridley2/takes/110/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/115/actors/babysmall/babysmall.bmsad",
    "cutscenes/ridley2/takes/115/actors/gunship/gunship.bmsad",
    "cutscenes/ridley2/takes/115/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/115/actors/rocks/rocks.bmsad",
    "cutscenes/ridley2/takes/115/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/120/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/120/actors/gunship/gunship.bmsad",
    "cutscenes/ridley2/takes/120/actors/ridleyhead/ridleyhead.bmsad",
    "cutscenes/ridley2/takes/120/actors/rocks/rocks.bmsad",
    "cutscenes/ridley2/takes/120/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/130/actors/babysmall/babysmall.bmsad",
    "cutscenes/ridley2/takes/130/actors/gunship/gunship.bmsad",
    "cutscenes/ridley2/takes/130/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/130/actors/rocks/rocks.bmsad",
    "cutscenes/ridley2/takes/130/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/140/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/150/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/150/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/20/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/20/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/20/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/30/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/30/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/30/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/40/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/50/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/50/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/50/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/60/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/70/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/70/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/80/actors/baby/baby.bmsad",
    "cutscenes/ridley2/takes/80/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/80/actors/samus/samus.bmsad",
    "cutscenes/ridley2/takes/90/actors/ridley/ridley.bmsad",
    "cutscenes/ridley2/takes/90/actors/rockswall/rockswall.bmsad",
    "cutscenes/ridley3/takes/10/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/100/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/100/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/100/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/100/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/110/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/110/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/110/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/110/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/120/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/120/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/140/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/140/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/140/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/140/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/20/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/20/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/20/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/20/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/30/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/30/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/40/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/40/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/50/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/50/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/50/actors/rays/rays.bmsad",
    "cutscenes/ridley3/takes/50/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/50/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/60/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/60/actors/ridleyhand/ridleyhand.bmsad",
    "cutscenes/ridley3/takes/60/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/70/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/70/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/70/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/70/actors/samus/samus.bmsad",
    "cutscenes/ridley3/takes/80/actors/baby/baby.bmsad",
    "cutscenes/ridley3/takes/80/actors/gunship/gunship.bmsad",
    "cutscenes/ridley3/takes/80/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/90/actors/ridley/ridley.bmsad",
    "cutscenes/ridley3/takes/90/actors/ridleyhand/ridleyhand.bmsad",
    "cutscenes/ridley3/takes/90/actors/samus/samus.bmsad",
    "cutscenes/ridley4/takes/10/actors/ridley/ridley.bmsad",
    "cutscenes/ridley4/takes/10/actors/samus/samus.bmsad",
    "cutscenes/ridley4/takes/20/actors/baby/baby.bmsad",
    "cutscenes/ridley4/takes/20/actors/ridley/ridley.bmsad",
    "cutscenes/ridley4/takes/20/actors/samus/samus.bmsad",
    "cutscenes/ridley4/takes/20/actors/ship/ship.bmsad",
    "cutscenes/ridley4/takes/30/actors/baby/baby.bmsad",
    "cutscenes/ridley4/takes/30/actors/ridley/ridley.bmsad",
    "cutscenes/ridley4/takes/30/actors/samus/samus.bmsad",
    "cutscenes/ridley4/takes/30/actors/ship/ship.bmsad",
    "cutscenes/ridley4/takes/40/actors/baby/baby.bmsad",
    "cutscenes/ridley4/takes/40/actors/ridley/ridley.bmsad",
    "cutscenes/ridley4/takes/40/actors/samus/samus.bmsad",
    "cutscenes/ridley4/takes/40/actors/ship/ship.bmsad",
    "cutscenes/ridley4/takes/50/actors/ship/ship.bmsad",
    "cutscenes/ridley4/takes/60/actors/baby/baby.bmsad",
    "cutscenes/ridley4/takes/60/actors/planet/planet.bmsad",
    "cutscenes/ridley4/takes/60/actors/samus/samus.bmsad",
    "cutscenes/ridley4/takes/60/actors/shipinterior/shipinterior.bmsad",
    "cutscenes/ridley4/takes/70/actors/planet/planet.bmsad",
    "cutscenes/ridley4/takes/70/actors/shipsmall/shipsmall.bmsad",
    "cutscenes/ridleydrained/takes/01/actors/baby/baby.bmsad",
    "cutscenes/ridleydrained/takes/01/actors/ridley/ridley.bmsad",
    "cutscenes/ridleydrained/takes/01/actors/samus/samus.bmsad",
    "cutscenes/ridleydrained/takes/02/actors/baby/baby.bmsad",
    "cutscenes/ridleydrained/takes/02/actors/ridley/ridley.bmsad",
    "cutscenes/ridleydrained/takes/02/actors/samus/samus.bmsad",
    "cutscenes/ridleydrained/takes/03/actors/baby/baby.bmsad",
    "cutscenes/ridleydrained/takes/03/actors/ridley/ridley.bmsad",
    "cutscenes/ridleydrained/takes/03/actors/samus/samus.bmsad",
    "cutscenes/ridleydrained/takes/04/actors/baby/baby.bmsad",
    "cutscenes/ridleydrained/takes/04/actors/ridley/ridley.bmsad",
    "cutscenes/ridleydrained/takes/04/actors/samus/samus.bmsad",
    "cutscenes/scaningpulse/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/scaningpulse/takes/01/actors/samus/samus.bmsad",
    "cutscenes/scaningpulse/takes/01/actors/statue/statue.bmsad",
    "cutscenes/teleporter/takes/01/actors/baby/baby.bmsad",
    "cutscenes/teleporter/takes/01/actors/samus/samus.bmsad",
    "cutscenes/teleporter/takes/01/actors/teleporter/teleporter.bmsad",
    "cutscenes/tunel/takes/01/actors/morphball/morphball.bmsad",
    "cutscenes/variasuit/takes/01/actors/planefade/planefade.bmsad",
    "cutscenes/variasuit/takes/01/actors/samuspower/samuspower.bmsad",
    "cutscenes/variasuit/takes/02/actors/planefade/planefade.bmsad",
    "cutscenes/variasuit/takes/02/actors/samus/samus.bmsad",
    "cutscenes/variasuit/takes/03/actors/samus/samus.bmsad",
    "cutscenes/variasuit/takes/04/actors/samus/samus.bmsad",
    "cutscenes/variasuit/takes/05/actors/samus/samus.bmsad",
]


@pytest.mark.parametrize("bmsad_path", dread_data.all_files_ending_with(".bmsad"))
def test_compare_dread_all(dread_tree_100, bmsad_path):
    if bmsad_path in expected_dread_failures:
        expectation = pytest.raises(construct.ConstructError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(Bmsad, dread_tree_100, bmsad_path)


@pytest.mark.parametrize("bmsad_path", samus_returns_data.all_files_ending_with(".bmsad", sr_missing))
def test_compare_sr_all(samus_returns_tree, bmsad_path):
    parse_build_compare_editor(Bmsad, samus_returns_tree, bmsad_path)


def test_api_dread_actordef(dread_tree_100):
    bmsad = dread_tree_100.get_parsed_asset(
        "actors/logic/breakablehint/charclasses/breakablehint.bmsad", type_hint=Bmsad
    )

    fakename = "foo"

    assert bmsad.name == "breakablehint"
    bmsad.name = fakename
    assert bmsad.name == fakename

    with pytest.raises(AttributeError):
        bmsad.model_name = fakename
    with pytest.raises(AttributeError):
        assert bmsad.model_name == fakename

    assert bmsad.sub_actors == []
    bmsad.sub_actors = [fakename, fakename]
    assert bmsad.sub_actors == [fakename, fakename]

    assert bmsad.action_sets == []
    with pytest.raises(AttributeError):
        bmsad.action_sets = []

    assert bmsad.action_set_refs == []
    bmsad.action_set_refs = [fakename]
    assert bmsad.action_set_refs == [fakename]

    assert bmsad.sound_fx == []
    bmsad.sound_fx = [(fakename, 0)]
    assert bmsad.sound_fx == [(fakename, 0)]

    # make sure it builds
    bmsad.build()


def test_api_dread_charclass(dread_tree_100):
    bmsad = dread_tree_100.get_parsed_asset("actors/props/doorheat/charclasses/doorheat.bmsad", type_hint=Bmsad)

    fakename = "foo"

    assert bmsad.name == "doorheat"

    assert bmsad.model_name == "actors/props/doorheat/models/doorheat.bcmdl"
    bmsad.model_name = fakename
    assert bmsad.model_name == fakename

    assert len(bmsad.action_sets) == 1
    assert bmsad.action_set_refs == ["actors/props/doorheat/charclasses/doorheat.bmsas"]

    assert bmsad.sound_fx == [
        ("props/heatdoor/hdoor_close_02.wav", 1),
        ("props/heatdoor/hdoor_open_02.wav", 1),
        ("props/heatdoor/hdoor_close_01.wav", 1),
        ("props/heatdoor/hdoor_init.wav", 1),
        ("props/heatdoor/hdoor_open_01.wav", 1),
    ]

    navmesh = bmsad.components["NAVMESHITEM"]

    # type
    assert navmesh.type == "CNavMeshItemComponent"
    assert navmesh.get_component_type() == "CCharClassNavMeshItemComponent"
    navmesh.type = "CPowerBombBlockLifeComponent"
    assert navmesh.type == "CPowerBombBlockLifeComponent"
    assert navmesh.get_component_type() == "CCharClassLifeComponent"
    navmesh.type = "CNavMeshItemComponent"

    # extra_fields
    assert navmesh.fields.sInitialStage == "closed"
    navmesh.fields.sInitialStage = "opened"
    assert navmesh.fields.sInitialStage == "opened"

    # fields
    assert navmesh.fields.eType == dread_types.ENavMeshItemType.Dynamic

    with pytest.raises(TypeError):
        navmesh.fields.eType = fakename

    navmesh.fields.eType = None
    assert navmesh.raw.fields is None

    navmesh.fields.eType = dread_types.ENavMeshItemType.Destructible
    assert navmesh.raw.fields is not None
    assert navmesh.fields.eType == dread_types.ENavMeshItemType.Destructible

    with pytest.raises(AttributeError):
        navmesh.fields.oThisIsNotARealField = fakename

    # functions
    funcs = list(navmesh.functions)
    assert [func.name for func in funcs] == ["CreateStage", "AddStageCollider", "CreateStage"]
    newfunc = ActorDefFunc.new("CreateStage")
    newfunc.set_param("Stage", "in-between")
    funcs.append(newfunc)
    navmesh.functions = funcs

    assert navmesh.functions[-1] == newfunc

    # dependencies
    assert navmesh.dependencies is None

    # make sure it builds
    bmsad.build()


def test_api_sr(samus_returns_tree: FileTreeEditor):
    bmsad = samus_returns_tree.get_parsed_asset(
        "actors/characters/alpha/charclasses/alpha.bmsad",
        type_hint=Bmsad,
    )

    fakename = "foo"

    assert bmsad.name == "alpha"
    bmsad.name = fakename
    assert bmsad.name == fakename

    assert bmsad.model_name == "actors/characters/alpha/models/alpha.bcmdl"
    bmsad.model_name = fakename
    assert bmsad.model_name == fakename

    assert bmsad.sub_actors == [
        "alphaelectricmine",
        "adn",
        "ice_casquery",
        "alphagiantelectricmine",
    ]
    bmsad.sub_actors = [fakename, fakename]
    assert bmsad.sub_actors == [fakename, fakename]

    assert len(bmsad.action_sets) == 1

    with pytest.raises(AttributeError):
        assert bmsad.action_set_refs == []
    with pytest.raises(AttributeError):
        bmsad.action_set_refs = []

    assert len(bmsad.sound_fx) == 39
    bmsad.sound_fx = []
    assert bmsad.raw.sound_fx is None
    bmsad.sound_fx = [(fakename, 0)]
    assert bmsad.sound_fx == [(fakename, 0)]

    # components
    modelupdater = bmsad.components["MODELUPDATER"]
    modelupdater.functions[1].set_param(1, "foo")

    assert modelupdater.fields.vInitPosWorldOffset == [0.0, 0.0, 0.0]
    modelupdater.fields.vInitPosWorldOffset = [1.0, 2.0, 3.0]
    assert modelupdater.fields.vInitPosWorldOffset == [1.0, 2.0, 3.0]
    with pytest.raises(TypeError):
        modelupdater.fields.vInitPosWorldOffset = [1, True, False]
    with pytest.raises(ValueError):
        modelupdater.fields.vInitPosWorldOffset = [0.0, 0.0]
    with pytest.raises(TypeError):
        modelupdater.fields.vInitPosWorldOffset = {"foo": "bar"}

    # make sure it builds
    bmsad.build()
