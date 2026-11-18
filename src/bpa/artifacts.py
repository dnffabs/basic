"""Publish JSON artifacts without replacing the input ELF."""

import json
import os
from pathlib import Path
import tempfile


def write_json(path: str | Path, document: dict, *, binary: str | Path) -> None:
    output, source = Path(path), Path(binary)
    if output.resolve() == source.resolve() or (output.exists() and output.samefile(source)):
        raise ValueError("Output must not overwrite the input ELF")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent,
                                         prefix=".artifact-", suffix=".json", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
