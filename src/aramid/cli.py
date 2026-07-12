import argparse, sys
from aramid import __version__

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aramid")
    p.add_argument("--version", action="store_true")
    p.add_argument("command", nargs="?")
    return p

def main(argv: list[str] | None = None) -> int:
    args, _ = build_parser().parse_known_args(argv)
    if args.version:
        print(f"aramid {__version__}")
        return 0
    print("aramid: no command", file=sys.stderr)
    return 3
