# Mercury Engine Data Structures
Construct type definitions for Mercury Engine

| Format    | Samus Returns (Read) | Samus Returns (Write) | Dread (Read) | Dread (Write) | Purpose     |
|-----------|----------------------|-----------------------|--------------|---------------|-------------|
| BAPD      | Missing              | Missing               | &check;      | &check;       | Audio Preset (positional audio data) |
| BCCAM     | &cross;              | &cross;               | &cross;      | &cross;       | Camera Animation (used exclusively for cutscene takes) |
| BCLGT     | &cross;              | &cross;               | Missing      | Missing       | Lighting (?) |
| BCMDL     | &cross;              | &cross;               | &check;      | &cross;       | 3D Models	  |
| BCPTL     | &cross;              | &cross;               | &cross;      | &cross;       | Particle Effect |
| BCSKLA    | &check;              | &check;               | &check;      | &check;       | Skeleton Animation |
| BCTEX     | &cross;              | &cross;               | &check;      | &cross;       | Texture File |
| BCURV     | Missing              | Missing               | &cross;      | &cross;       | CURV (?) |
| BCUT      | &cross;              | &cross;               | Missing      | Missing       |	Related to cutscene files |
| BCWAV     | &cross;              | &cross;               | Missing      | Missing       | Cafe/Citra Wave (common AAL audio format) |
| BFGRP     | Missing              | Missing               | &cross;      | &cross;       | Sound WaveGroup (common AAL audio format) |
| BFONT     | &cross;              | &cross;               | &cross;      | &cross;       | Font File |
| BFSAR     | Missing              | Missing               | &cross;      | &cross;       | FSAR (?) |
| BFSTM     | Missing              | Missing               | &cross;      | &cross;       | Common Switch audio format |
| BGSNDS    | Missing              | Missing               | &check;      | &check;       | BackGround Sounds (?) |
| BLDEF     | Missing              | Missing               | &check;      | &check;       | Actor Lighting Definition |
| BLSND     | &check;              | &check;               | &check;      | &check;       | Sounds (?) |	
| BLUT      | Missing              | Missing               | &check;      | &check;       | LookUp Table (used for ADAM animation) |
| BMBLS     | Missing              | Missing               | &check;      | &check;       | Blend Space |
| BMDEFS    | &check;              | &check;               | &check;      | &check;       | Music Track Definitions & Properties	|
| BMMAP     | Missing              | Missing               | &check;      | &check;       | MiniMap |
| BMMDEF    | Missing              | Missing               | &check;      | &check;       | MiniMap Definitions (?) |
| BMSAD     | &check;              | &check;               | &check;      | &check;       | Actor Definitions	| 
| BMSAS     | Missing              | Missing               | &check;      | &check;       | Action Sets |
| BMSAT     | &cross;              | &cross;               | &check;      | &check;       | Animation Tree |
| BMSBK     | &check;              | &check;               | Missing      | Missing       | Blocks, per Scenario |
| BMSCC     | &check;              | &check;               | &check;      | &check;       | Collision Cameras	|
| BMSCD     | &check;              | &check;               | &check;      | &check;       | Collision Data / Geometry |
| BMSCP     | Missing              | Missing               | &check;      | &check;       | GUI Composition |
| BMSCU     | &cross;              | &cross;               | &check;      | &check;       | Cutscene Files |
| BMSEM     | &check;              | &check;               | Missing      | Missing       | Environment Music |
| BMSES     | &check;              | &check;               | Missing      | Missing       | Environment Sound |
| BMSEV     | &cross;              | &cross;               | Missing      | Missing       | Environment Visuals (fx) |
| BMSLD     | &check;              | &check;               | Missing      | Missing       | Samus Returns scenario entity data |
| BMSLGROUP | Missing              | Missing               | &check;      | &check;       | SmartLink Group |
| BMSLINK   | Missing              | Missing               | &check;      | &check;       | SmartLink (actor-specific navmesh paths) |
| BMSMD     | &check;              | &check;               | Missing      | Missing       | Menu Data (?)	|
| BMSMSD    | &check;              | &check;               | Missing      | Missing       | Map Screen Data (?)	|
| BMSNAV    | &check;              | &check;               | &check;      | &check;       | Navigation Meshes	|
| BMSND     | &cross;              | &cross;               | Missing      | Missing       | Sound (?)   |
| BMSSA     | &cross;              | &cross;               | Missing      | Missing       | SSA (?)			|
| BMSSD     | &cross;              | &cross;               | &check;      | &check;       | Static Scenario Data (background dressing) |	
| BMSSH     | Missing              | Missing               | &check;      | &check;       | GUI Shape |
| BMSSK     | Missing              | Missing               | &check;      | &check;       | GUI Skin |
| BMSSS     | Missing              | Missing               | &check;      | &check;       | GUI SpriteSheet |
| BMSSTOC   | Missing              | Missing               | &cross;      | &cross;       | Sound Table of Contents (links BFSAR sfx to BFGRP files) |
| BMTRE     | &cross;              | &cross;               | &check;      | &check;       | Behavior Tree; entitity AI)|
| BMTUN     | &check;              | &check;               | Missing      | Missing       | Tunables; exposed variables	|
| BNVIB     | Missing              | Missing               | &check;      | &check;       | Vibration Data |
| BPSI      | &check;              | &check;               | &check;      | &check;       | PackSet; dev leftovers |
| BPTDAT    | Missing              | Missing               | &check;      | &check;       | PlayThrough Data |
| BPTDEF    | Missing              | Missing               | &check;      | &check;       | PlayThrough Def |
| BREM      | Missing              | Missing               | &check;      | &check;       | Environmental Music Presets |
| BRES      | Missing              | Missing               | &check;      | &check;       | Environmental Sound Presets |
| BREV      | Missing              | Missing               | &check;      | &check;       | Environmental Visual Presets |
| BRFLD     | Missing              | Missing               | &check;      | &check;       | Dread Scenario Entity Data |
| BRSA      | Missing              | Missing               | &check;      | &check;       | SubArea Setups |
| BRSPD     | Missing              | Missing               | &check;      | &check;       | Shot Audio Presets |
| BSHDAT    | &cross;              | &cross;               | &cross;      | &cross;       | Shader Data	|
| BSMAT     | Missing              | Missing               | &check;      | &check;       | Mesh Material |	
| BTUNDA    | Missing              | Missing               | &check;      | &check;       | Tunable Data |
| BUCT      | &check;              | &check;               | &check;      | &check;       | Font Glyph Data (?) |
| INI       | Missing              | Missing               | &check;      | &check;       | Standard INI |
| LC        | &check;              | &check;               | &check;      | &check;       | Lua Bytecode |
| PKG       | &check;              | &check;               | &check;      | &check;       | Packaged Files |
| TOC       | &check;              | &check;               | &check;      | &check;       | Table of Contents |
| TXT       | &check;              | &check;               | &check;      | &check;       | UTF-16 Text File (?) |
| WEBM      | Missing              | Missing               | &cross;      | &cross;       | Standard WEBM |


## Example Usage

```python
# TODO
```

## Colors for Text

Metroid Dread uses the following annotations in text to change color:

| Code | Color       |              |
|------|-------------|--------------|
| {c0} | White       | (Default)    |
| {c1} | Yellow      |              |
| {c2} | Red         |              |
| {c3} | Pink        |              |
| {c4} | Green       |              |
| {c5} | Blue        |              |
| {c6} | UI Active   | (Light blue) |
| {c7} | UI Inactive | (Dim blue)   |
