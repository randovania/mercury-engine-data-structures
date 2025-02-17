from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import logging
import typing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from mercury_engine_data_structures import formats
from mercury_engine_data_structures.construct_extensions.json import convert_to_raw_python
from mercury_engine_data_structures.file_tree_editor import FileTreeEditor, OutputFormat
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.romfs import ExtractedRomFs


def game_argument_type(s: str) -> Game:
    try:
        return Game(int(s))
    except ValueError:
        # not a number, look by name
        for g in Game:
            g = typing.cast(Game, g)
            if g.name.lower() == s.lower():
                return g
        raise ValueError(f"No enum named {s} found")


def add_game_argument(parser: argparse.ArgumentParser, name="--game"):
    choices = []
    for g in Game:
        g = typing.cast(Game, g)
        choices.append(g.value)
        choices.append(g.name)

    parser.add_argument(name, help="The game of the file", type=game_argument_type, choices=list(Game), required=True)


def create_parser():
    parser = argparse.ArgumentParser()

    subparser = parser.add_subparsers(dest="command", required=True)

    decode = subparser.add_parser("decode")
    add_game_argument(decode)
    decode.add_argument("--format", help="Hint the format of the file. Defaults to extension.")
    decode.add_argument("--re-encode", help="Re-encode afterwards and compares to the original.", action="store_true")
    decode.add_argument("--dump-to", help="Write to the given path a json encoded contents of the file", type=Path)
    decode.add_argument("input_path", type=Path, help="Path to the file")

    decode_from_pkg = subparser.add_parser("decode-from-pkg")
    add_game_argument(decode_from_pkg)
    decode_from_pkg.add_argument("--root", type=Path, required=True, help="Path to the PKG files")
    decode_from_pkg.add_argument("asset_name", type=str, help="Asset name to print")

    replace_pkg_file = subparser.add_parser("replace-in-pkg")
    add_game_argument(replace_pkg_file)
    replace_pkg_file.add_argument("--pkg-input", type=Path, required=True, help="Path to the PKG file")
    replace_pkg_file.add_argument("--pkg-output", type=Path, required=True, help="Path to where write the updated PKG")
    replace_pkg_file.add_argument("--asset-id", type=int, required=True, help="Asset id to replace")
    replace_pkg_file.add_argument("asset_path", type=Path, help="Path to the updated asset")

    find_pkg = subparser.add_parser("find-pkg-for")
    add_game_argument(find_pkg)
    find_pkg.add_argument("--root", type=Path, required=True, help="Path to the PKG files")
    group = find_pkg.add_mutually_exclusive_group(required=True)
    group.add_argument("--asset-name", type=str, help="Asset name to find")
    group.add_argument("--asset-id", type=int, help="Asset id to find")

    compare = subparser.add_parser("compare-files")
    add_game_argument(compare)
    compare.add_argument("--format", help="Hint the format of the file", required=True)
    compare.add_argument("--limit", help="Limit the number of files to test", type=int)
    compare.add_argument("input_path", type=Path, help="Path to the directory to glob")

    extract_files_parser = subparser.add_parser("extract-files")
    add_game_argument(extract_files_parser)
    extract_files_parser.add_argument(
        "--quiet", action="store_true", default=False, help="Don't print files as they're extracted"
    )
    extract_files_parser.add_argument("root", type=Path, help="Path to the PKG files")
    extract_files_parser.add_argument("output", type=Path, help="Path to where to place output files")

    replace_files_parser = subparser.add_parser(
        "replace-files", help="Adds files to all pkgs in a folder. The results are written to a different path"
    )
    add_game_argument(replace_files_parser)
    replace_files_parser.add_argument("root", type=Path, help="Path to the PKG files to read from")
    replace_files_parser.add_argument("new_files", type=Path, help="Path to where the new files are located")
    replace_files_parser.add_argument("output", type=Path, help="Path to where to place modified pkgs")

    return parser


def dump_to(path: Path, decoded):
    def default(o):
        if callable(o):
            o = o()
        if isinstance(o, bytes):
            return len(o)

        raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

    with path.open("w") as f:
        x = convert_to_raw_python(decoded)
        f.write(json.JSONEncoder(indent=4, default=default).encode(x))


def do_decode(args):
    input_path: Path = args.input_path
    file_format = args.format
    game: Game = args.game
    re_encode = args.re_encode

    if file_format is None:
        file_format = input_path.suffix[1:]

    resource_class = formats.format_for(file_format)

    raw = input_path.read_bytes()
    decoded_resource = resource_class.parse(raw, target_game=game)

    if args.dump_to:
        dump_to(args.dump_to, decoded_resource.raw)
    else:
        print(decoded_resource.raw)

    if re_encode:
        encoded = decoded_resource.build()
        if raw != encoded:
            print(f"{input_path}: Results differ (len(raw): {len(raw)}; len(encoded): {len(encoded)})")


def do_decode_from_pkg(args):
    root: Path = args.root
    asset_name: str = args.asset_name

    pkg_editor = FileTreeEditor(ExtractedRomFs(root), args.game)
    asset = pkg_editor.get_parsed_asset(asset_name)
    print(asset.raw)


def replace_in_pkg(args):
    game: Game = args.game
    input_pkg: Path = args.pkg_input
    output_pkg: Path = args.pkg_output
    asset_id: int = args.asset_id
    asset_path: Path = args.asset_path

    logging.info("Reading %s", input_pkg)
    input_bytes = input_pkg.read_bytes()

    logging.info("Parsing...")
    pkg = formats.Pkg.parse(input_bytes, target_game=game)

    logging.info("Reading %s", asset_path)
    new_file = asset_path.read_bytes()

    logging.info("Replacing asset in pkg")
    pkg.replace_asset(asset_id, new_file)

    logging.info("Building new pkg")
    encoded = pkg.build()

    logging.info("Writing new pkg to %s", output_pkg)
    output_pkg.parent.mkdir(parents=True, exist_ok=True)
    output_pkg.write_bytes(encoded)

    logging.info("Done")


def find_pkg_for(args):
    root: Path = args.root
    asset_id: int = args.asset_id
    asset_name: str = args.asset_name

    pkg_editor = FileTreeEditor(ExtractedRomFs(root), args.game)
    if asset_id is not None:
        items = list(pkg_editor.find_pkgs(asset_id))
    else:
        items = list(pkg_editor.find_pkgs(asset_name))

    print(f"> Pkgs for {asset_id} / {asset_name}:")
    for it in items:
        print(it)


def decode_encode_compare_file(file_path: Path, game: Game, file_format: str):
    resource_class = formats.format_for(file_format)

    try:
        raw = file_path.read_bytes()
        resource = resource_class.parse(raw, target_game=game)
        encoded = resource.build()

        if raw != encoded and raw.rstrip(b"\xff") != encoded:
            return f"{file_path}: Results differ (len(raw): {len(raw)}; len(encoded): {len(encoded)})"
        return None

    except Exception as e:
        return f"{file_path}: Received error - {e}"


async def compare_all_files_in_path(args):
    input_path: Path = args.input_path
    file_format: str = args.format
    game: Game = args.game
    limit: int | None = args.limit

    def apply_limit(it):
        if limit is None:
            return it
        else:
            return itertools.islice(it, limit)

    loop = asyncio.get_running_loop()

    try:
        import tqdm
    except ImportError:
        tqdm = None

    errors = []

    with ProcessPoolExecutor(max_workers=1) as executor:
        files = apply_limit(input_path.rglob(f"*.{file_format.upper()}"))
        if tqdm is not None:
            files = tqdm.tqdm(files, unit=" file")

        results = [loop.run_in_executor(executor, decode_encode_compare_file, f, game, file_format) for f in files]
        as_completed = asyncio.as_completed(results)
        if tqdm is not None:
            as_completed = tqdm.tqdm(as_completed, total=len(results), unit=" file")

        for c in as_completed:
            message = await c
            if message:
                if tqdm is not None:
                    errors.append(message)
                    as_completed.set_postfix_str(f"{len(errors)} errors")
                else:
                    print(message)
            raise SystemExit

    if errors:
        print(f"{len(errors)} errors:")
        for m in errors:
            print(m)


def extract_files(args: argparse.Namespace) -> None:
    root: Path = args.root
    output_root: Path = args.output

    pkg_editor = FileTreeEditor(ExtractedRomFs(root), args.game)

    output_root.mkdir(parents=True, exist_ok=True)
    for file_name in pkg_editor.all_asset_names():
        if not args.quiet:
            print(file_name)
        out_path = output_root.joinpath(file_name)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(pkg_editor.get_raw_asset(file_name))


def replace_files(args: argparse.Namespace) -> None:
    root: Path = args.root
    new_files: Path = args.new_files
    output: Path = args.output

    pkg_editor = FileTreeEditor(ExtractedRomFs(root), args.game)

    for file_name in new_files.rglob("*"):
        if file_name.is_file():
            pkg_editor.replace_asset(file_name.relative_to(new_files).as_posix(), file_name.read_bytes())

    pkg_editor.save_modifications(output, OutputFormat.PKG)


def main():
    logging.basicConfig(level=logging.INFO)
    args = create_parser().parse_args()

    if args.command == "decode":
        do_decode(args)
    elif args.command == "decode-from-pkg":
        do_decode_from_pkg(args)
    elif args.command == "replace-in-pkg":
        replace_in_pkg(args)
    elif args.command == "find-pkg-for":
        find_pkg_for(args)
    elif args.command == "compare-files":
        asyncio.run(compare_all_files_in_path(args))
    elif args.command == "extract-files":
        extract_files(args)
    elif args.command == "replace-files":
        replace_files(args)
    else:
        raise ValueError(f"Unknown command: {args.command}")
