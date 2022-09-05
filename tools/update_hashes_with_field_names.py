import json
import typing
from pathlib import Path

from mercury_engine_data_structures import crc


def main():
    types_file = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "dread_types.json")
    properties_file = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "dread_property_names.json")

    with types_file.open() as f:
        all_types: dict[str, dict[str, typing.Any]] = json.load(f)

    with properties_file.open() as f:
        known_hashes: dict[str, int] = json.load(f)

    for type_name, type_data in all_types.items():
        for field in type_data["fields"].keys():
            if field not in known_hashes:
                known_hashes[field] = crc.crc64(field)

    with properties_file.open("w") as f:
        json.dump({
            key: known_hashes[key]
            for key in sorted(known_hashes.keys())
        }, f, indent=4)


if __name__ == '__main__':
    main()
