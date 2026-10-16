from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from mercury_engine_data_structures.cli import add_game_argument, dump_to
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import ALL_FORMATS
from mercury_engine_data_structures.romfs import ExtractedRomFs


def create_parser():
    parser = argparse.ArgumentParser()

    add_game_argument(parser)
    parser.add_argument("dump_dir", type=Path, help="Path to the dir we are dumping data to")
    parser.add_argument("input_dir", type=Path, help="Path to the game's ROM")

    return parser


def main():
    logging.basicConfig(level=logging.INFO)
    args = create_parser().parse_args()

    input_dir = args.input_dir
    dump_dir = args.dump_dir
    game = args.game

    editor = FileTreeEditor(ExtractedRomFs(input_dir), target_game=game)

    for asset_name in game.known_hashes_table.keys():
        ext = os.path.splitext(asset_name)[1][1:].upper()
        if ext in ALL_FORMATS and editor.does_asset_exists(asset_name):
            asset = editor.get_parsed_asset(asset_name)
            out = dump_dir.joinpath(asset_name + ".json")
            out.parent.mkdir(parents=True, exist_ok=True)
            dump_to(out, asset.raw)


if __name__ == "__main__":
    main()
