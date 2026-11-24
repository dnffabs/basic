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


def run_m3(binary: str | Path, output: str | Path, *, m1_path: str | Path | None = None,
           m2_path: str | Path | None = None, mapped_base: int | None = None):
    """Run through M3, or consume existing M1/M2 artifacts without rerunning CFGFast."""
    import hashlib

    from bpa.vex import write_facts
    from bpa.vex.extractor import extract_vex

    binary, output = Path(binary).resolve(), Path(output)
    if m2_path is None:
        cfg = run_m2(binary, output, m1_path=m1_path, mapped_base=mapped_base).cfg_document()
        info = BinaryInfo.from_dict(json.loads((output / "m1/binary.json").read_text()))
    else:
        if m1_path is None:
            raise ValueError("Consuming --m2 requires --m1 binary.json")
        info = replace(BinaryInfo.from_dict(json.loads(Path(m1_path).read_text())), path=str(binary))
        if mapped_base is not None and mapped_base != info.mapped_base:
            raise ValueError("mapped_base conflicts with the M1 artifact")
        cfg = json.loads(Path(m2_path).read_text())
        functions = json.loads(Path(m2_path).with_name("functions.json").read_text())
        for key in ("schema_version", "stage", "address_space", "binary_sha256", "arch", "bits", "entry", "backend", "backend_version", "options"):
            if functions.get(key) != cfg.get(key):
                raise ValueError(f"M2 functions/cfg metadata differ: {key}")
        if functions.get("kind") != "functions":
            raise ValueError("Expected M2 functions.json")
        entries = {f["entry"] for f in functions["functions"]}
        if any(owner not in entries for b in cfg["blocks"] for owner in b["function_entries"]):
            raise ValueError("M2 block has an unknown function owner")
        # Validate and extract before publishing copies of supplied documents.
        result = extract_vex(info, cfg)
        for target, document, source in (
                (output / "m1/binary.json", info.to_dict(), m1_path),
                (output / "m2/cfg.json", cfg, m2_path),
                (output / "m2/functions.json", functions, Path(m2_path).with_name("functions.json"))):
            if target.resolve() != Path(source).resolve():
                write_json(target, document, binary=binary)
    if m2_path is None:
        result = extract_vex(info, cfg)
    inputs = [output / "m1/binary.json", output / "m2/cfg.json", output / "m2/functions.json"]
    result.metadata["inputs"] = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in inputs}
    write_facts(result, output / "m3", protected=[binary, *inputs,
                *([Path(m1_path), Path(m2_path), Path(m2_path).with_name("functions.json")] if m2_path else [])])
    return result
