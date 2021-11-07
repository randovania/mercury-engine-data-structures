import functools
import json
from pathlib import Path
from typing import Dict


@functools.lru_cache()
def get() -> Dict[str, str]:
    path = Path(__file__).parent.joinpath("dread_types.json")
    with path.open() as f:
        return json.load(f)
