all_levels = [
    "s000_surface",
    "s010_area1",
    "s020_area2",
    "s025_area2b",
    "s028_area2c",
    "s030_area3",
    "s033_area3b",
    "s036_area3c",
    "s040_area4",
    "s050_area5",
    "s060_area6",
    "s065_area6b",
    "s067_area6c",
    "s070_area7",
    "s090_area9",
    "s100_area10",
    "s110_surfaceb",
    "s901_alpha",
    "s903_zeta",
    "s904_omega",
    "s910_gym",
]
extensions = [".bmsld", ".bmscd", ".bmscc", "_auto.lua", "_auto.lc", ".lua", ".lc", ".bmsld", ".bmsbk", ".bmssd",
              ".bmsnd", ".bgph", ".bmsel", ".bmsnav"]


def build(major, lvl):
    for f in extensions:
        yield f"maps/levels/{major}/{lvl}/{lvl}{f}"


result = []

if __name__ == '__main__':
    for s in all_levels:
        result.extend(build("c10_samus", s))
    result.extend(build("c50_gui", "s000_mainmenu"))
    result.extend(build("c50_gui", "s010_cockpit"))
    result.extend(build("c50_gui", "s020_credits"))

    print("\n".join(result))
