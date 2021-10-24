import functools
import json
from pathlib import Path
from typing import Dict, Optional


@functools.lru_cache()
def all_asset_id_to_name() -> Dict[int, str]:
    path = Path(__file__).parent.joinpath("resource_names.json")
    with path.open() as names_file:
        names: Dict[str, int] = json.load(names_file)

    return {
        asset_id: name
        for name, asset_id in names.items()
    }


def name_for_asset_id(asset_id: int) -> Optional[str]:
    return all_asset_id_to_name().get(asset_id)
