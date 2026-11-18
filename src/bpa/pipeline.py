"""Stage orchestration; analysis modules return data rather than write files."""

from dataclasses import replace
import json
from pathlib import Path

from bpa.artifacts import write_json
from bpa.cfg import build_cfg
from bpa.loader import load_elf
from bpa.model import BinaryInfo


def run_m2(binary: str | Path, output: str | Path, *, m1_path: str | Path | None = None,
           mapped_base: int | None = None):
    binary, output = Path(binary).resolve(), Path(output)
    if m1_path is None:
        info = load_elf(binary, mapped_base=mapped_base)
    else:
        info = BinaryInfo.from_dict(json.loads(Path(m1_path).read_text()))
        if mapped_base is not None and mapped_base != info.mapped_base:
            raise ValueError("mapped_base conflicts with the M1 artifact")
        # The input may have moved; build_cfg verifies its exact SHA256.
        info = replace(info, path=str(binary))
    result = build_cfg(info)
    m1_output = output / "m1/binary.json"
    if m1_path is None or Path(m1_path).resolve() != m1_output.resolve():
        write_json(m1_output, info.to_dict(), binary=binary)
    write_json(output / "m2/functions.json", result.functions_document(), binary=binary)
    write_json(output / "m2/cfg.json", result.cfg_document(), binary=binary)
    return result
