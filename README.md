# Mercury Engine Data Structures
Construct type definitions for Mercury Engine

| Format    | Samus Returns (Read) | Samus Returns (Write) | Dread (Read) | Dread (Write) | Purpose     |
|-----------|----------------------|-----------------------|--------------|---------------|-------------|
| BAPD      | Missing              | Missing               | &check;      | &check;       |                         |
| BCCAM     | &cross;              | &cross;               | &cross;      | &cross;       | Camera Objects |
| BCLGT     | &cross;              | &cross;               | Missing      | Missing       | Lighting (?) |
| BCMDL     | &cross;              | &cross;               | &check;      | &cross;       | 3D Models	  |
| BCPTL     | &cross;              | &cross;               | &cross;      | &cross;       | PTL (?)     |
| BCSKLA    | &check;              | &check;               | &check;      | &check;       | Skeleton Animation |
| BCTEX     | &cross;              | &cross;               | &check;      | &cross;       | Texture File |
| BCURV     | Missing              | Missing               | &cross;      | &cross;       |             |
| BCUT      | &cross;              | &cross;               | Missing      | Missing       |	UT (?)      |
| BCWAV     | &cross;              | &cross;               | Missing      | Missing       | Audio File	|
| BFGRP     | Missing              | Missing               | &cross;      | &cross;       |							|
| BFONT     | &cross;              | &cross;               | &cross;      | &cross;       | Font File		|
| BFSAR     | Missing              | Missing               | &cross;      | &cross;       |							|
| BFSTM     | Missing              | Missing               | &cross;      | &cross;       |							|
| BGSNDS    | Missing              | Missing               | &check;      | &check;       |							|
| BLDEF     | Missing              | Missing               | &check;      | &check;       |							|
| BLSND     | &check;              | &check;               | &check;      | &check;       | Sound				|	
| BLUT      | Missing              | Missing               | &check;      | &check;       |							|
| BMBLS     | Missing              | Missing               | &check;      | &check;       |							|
| BMDEFS    | &check;              | &check;               | &check;      | &check;       | Music Track Definitions & Properties	|
| BMMAP     | Missing              | Missing               | &check;      | &check;       |							|
| BMMDEF    | Missing              | Missing               | &check;      | &check;       |							|
| BMSAD     | &check;              | &check;               | &check;      | &check;       | Actor Definitions	| 
| BMSAS     | Missing              | Missing               | &check;      | &check;       | 						|
| BMSAT     | &cross;              | &cross;               | &check;      | &check;       | AT (?)			|
| BMSBK     | &check;              | &check;               | Missing      | Missing       | Blocks (?)	|
| BMSCC     | &check;              | &check;               | &check;      | &check;       | Collision Cameras	|
| BMSCD     | &check;              | &check;               | &check;      | &check;       | Collision Data, Geometry |
| BMSCP     | Missing              | Missing               | &check;      | &check;       |							|
| BMSCU     | &cross;              | &cross;               | &check;      | &check;       | CU (?)			|
| BMSEM     | &check;              | &check;               | Missing      | Missing       | Environment Data |
| BMSES     | &check;              | &check;               | Missing      | Missing       | Environment Data |
| BMSEV     | &cross;              | &cross;               | Missing      | Missing       | EV (?)			|
| BMSLD     | &check;              | &check;               | Missing      | Missing       | Level Data	|
| BMSLGROUP | Missing              | Missing               | &check;      | &check;       |							|
| BMSLINK   | Missing              | Missing               | &check;      | &check;       |							|
| BMSMD     | &check;              | &check;               | Missing      | Missing       | Menu Data (?)	|
| BMSMSD    | &check;              | &check;               | Missing      | Missing       | Map Screen Data (?)	|
| BMSNAV    | &check;              | &check;               | &check;      | &check;       | Navigation Meshes	|
| BMSND     | &cross;              | &cross;               | Missing      | Missing       | Sound (?)   |
| BMSSA     | &cross;              | &cross;               | Missing      | Missing       | SSA (?)			|
| BMSSD     | &cross;              | &cross;               | &check;      | &check;       | SSD (?)			|	
| BMSSH     | Missing              | Missing               | &check;      | &check;       |							|
| BMSSK     | Missing              | Missing               | &check;      | &check;       |							|
| BMSSS     | Missing              | Missing               | &check;      | &check;       |							|
| BMSSTOC   | Missing              | Missing               | &cross;      | &cross;       |							|
| BMTRE     | &cross;              | &cross;               | &check;      | &check;       | TRE (?)			|
| BMTUN     | &check;              | &check;               | Missing      | Missing       | Tunables; exposed variables	|
| BNVIB     | Missing              | Missing               | &check;      | &check;       |							|
| BPSI      | &check;              | &check;               | &check;      | &check;       | Packset; dev leftovers |
| BPTDAT    | Missing              | Missing               | &check;      | &check;       |							|
| BPTDEF    | Missing              | Missing               | &check;      | &check;       |							|
| BREM      | Missing              | Missing               | &check;      | &check;       |							|
| BRES      | Missing              | Missing               | &check;      | &check;       |							|
| BREV      | Missing              | Missing               | &check;      | &check;       |							|
| BRFLD     | Missing              | Missing               | &check;      | &check;       |							|
| BRSA      | Missing              | Missing               | &check;      | &check;       |							|
| BRSPD     | Missing              | Missing               | &check;      | &check;       |							|
| BSHDAT    | &cross;              | &cross;               | &cross;      | &cross;       | Shader Data	|
| BSMAT     | Missing              | Missing               | &check;      | &check;       |							|	
| BTUNDA    | Missing              | Missing               | &check;      | &check;       |							|
| BUCT      | &check;              | &check;               | &check;      | &check;       | Font File (?) |
| INI       | Missing              | Missing               | &check;      | &check;       |							|
| LC        | &check;              | &check;               | &check;      | &check;       | Lua Script	|
| PKG       | &check;              | &check;               | &check;      | &check;       | Packaged Files |
| TOC       | &check;              | &check;               | &check;      | &check;       | Table of Contents |
| TXT       | &check;              | &check;               | &check;      | &check;       | Text File	  |
| WEBM      | Missing              | Missing               | &cross;      | &cross;       |							|


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
