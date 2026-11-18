"""Minimal M1 command-line entry point."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from bpa.loader import ELFLoadError, load_elf


def main() -> int:
    parser = argparse.ArgumentParser(description="Load ELF metadata, symbols, imports and relocations")
    parser.add_argument("binary", type=Path, help="Path to an ELF file")
    parser.add_argument("-o", "--output", type=Path, help="Write metadata as JSON")
    parser.add_argument("--mapped-base", type=lambda value: int(value, 0),
                        help="Override the mapped base for a position-independent ELF")
    args = parser.parse_args()
    try:
        info = load_elf(args.binary, mapped_base=args.mapped_base)
        document = json.dumps(info.to_dict(), indent=2, ensure_ascii=False) + "\n"
        if args.output:
            if args.output.resolve() == args.binary.resolve() or (
                args.output.exists() and args.output.samefile(args.binary)
            ):
                raise ValueError("Output must not overwrite the input ELF")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.output.parent,
                                                 prefix=".binary-", suffix=".json", delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(document)
                os.replace(temporary, args.output)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            print(f"Saved: {args.output}")
        else:
            print(document, end="")
    except (ELFLoadError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
