"""Command-line entry point for the implemented analysis stages."""

import argparse
import json
from pathlib import Path
import sys

from bpa.artifacts import write_json
from bpa.loader import ELFLoadError, load_elf


def main() -> int:
    parser = argparse.ArgumentParser(description="ELF loading, control-flow analysis and VEX facts")
    parser.add_argument("binary", type=Path, help="Path to an ELF file")
    parser.add_argument("-o", "--output", type=Path, help="M1: JSON file; M2/M3: output directory")
    parser.add_argument("--stage", choices=("m1", "m2", "m3"), default="m1", help="Run through this stage")
    parser.add_argument("--m1", type=Path, help="M2/M3: consume an existing M1 binary.json")
    parser.add_argument("--m2", type=Path, help="M3: consume M2 cfg.json and sibling functions.json; requires --m1")
    parser.add_argument("--mapped-base", type=lambda value: int(value, 0),
                        help="Override the mapped base for a position-independent ELF")
    args = parser.parse_args()
    if args.stage in ("m2", "m3") and args.output is None:
        parser.error(f"--stage {args.stage} requires --output with a directory")
    if args.stage == "m1" and args.m1 is not None:
        parser.error("--m1 is only used with --stage m2 or m3")
    if args.m2 is not None and (args.stage != "m3" or args.m1 is None):
        parser.error("--m2 requires --stage m3 and --m1")
    try:
        if args.stage == "m3":
            from bpa.pipeline import run_m3

            result = run_m3(args.binary, args.output, m1_path=args.m1, m2_path=args.m2,
                            mapped_base=args.mapped_base)
            print(json.dumps(dict(output=str(args.output / "m3"), **result.metadata,
                                  counts={name: len(rows) for name, rows in result.rows.items()}), indent=2))
            return 0 if result.metadata["status"] == "complete" else 2
        if args.stage == "m2":
            from bpa.pipeline import run_m2

            result = run_m2(args.binary, args.output, m1_path=args.m1, mapped_base=args.mapped_base)
            print(json.dumps(dict(output=str(args.output), **result.cfg_document()["statistics"]), indent=2))
            return 0
        info = load_elf(args.binary, mapped_base=args.mapped_base)
        document = json.dumps(info.to_dict(), indent=2, ensure_ascii=False) + "\n"
        if args.output:
            write_json(args.output, info.to_dict(), binary=args.binary)
            print(f"Saved: {args.output}")
        else:
            print(document, end="")
    except (ELFLoadError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
