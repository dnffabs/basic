"""Compare M1 artifacts with independent BPA-X loader/helper exports.

Uses an existing BPA-X-compatible Python environment; never runs CFG/points-to
analysis, rebuilds inputs, or changes the reference repository.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys

from bpa.loader import open_elf


ROOT = Path(__file__).resolve().parents[1]

# Executed by the reference interpreter, without importing any bpa modules.
REFERENCE_EXPORT = '''
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import angr
import cle
from elftools.elf.elffile import ELFFile

binary, output, bpax = map(Path, sys.argv[1:])
project = angr.Project(str(binary), auto_load_libs=False)
obj = project.loader.main_object
with binary.open("rb") as stream:
    elf = ELFFile(stream)
    header = dict(elf_type=elf["e_type"], machine=elf["e_machine"],
                  bits=elf.elfclass, endianness="little" if elf.little_endian else "big",
                  entry=elf["e_entry"])
    segments = [dict(s.header) for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    sections = [dict(name=s.name, header=dict(s.header)) for s in elf.iter_sections()]
symbols = [dict(name=s.name, type=s.type.name, size=s.size, is_function=s.is_function,
                is_import=s.is_import, is_export=s.is_export, is_weak=s.is_weak,
                section=s.section, linked_addr=s.linked_addr, rebased_addr=s.rebased_addr)
           for s in obj.symbols if s.name]
def resolution(relocation):
    target = relocation.resolvedby
    return dict(resolved=relocation.resolved,
                target_mapped_address=target.rebased_addr if target is not None else None,
                target_is_extern=bool(target is not None and target.is_extern))
imports = [dict(name=name, is_weak=r.symbol.is_weak, linked_addr=r.linked_addr,
                rebased_addr=r.rebased_addr, **resolution(r)) for name,r in sorted(obj.imports.items())]
relocations = [dict(type=type(r).__name__, linked_addr=r.linked_addr, rebased_addr=r.rebased_addr,
                    symbol=r.symbol.name if r.symbol is not None else None, **resolution(r))
               for r in obj.relocs]
memory = []
(output / "memory").mkdir(exist_ok=True)
for index, segment in enumerate(segments):
    address = segment["p_vaddr"] + obj.mapped_base - obj.linked_base
    data = project.loader.memory.load(address, segment["p_memsz"])
    assert len(data) == segment["p_memsz"]
    filename = "memory/segment_%d.bin" % index
    (output / filename).write_bytes(data)
    memory.append(dict(mapped_address=address, size=len(data),
                       sha256=hashlib.sha256(data).hexdigest(), file=filename))
spec = importlib.util.spec_from_file_location("bpax_utils", bpax/"vex_fact_gen/utils/utils.py")
utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utils)
regions = utils.get_instr_regions(str(binary))
document = dict(path=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                file_size=binary.stat().st_size, header=header, segments=segments, sections=sections,
                arch=project.arch.name, linked_base=obj.linked_base, mapped_base=obj.mapped_base,
                mapped_entry=project.entry, cle_version=cle.__version__, angr_version=angr.__version__,
                symbols=symbols, imports=imports, dependencies=obj.deps, plt=obj.plt,
                relocations=relocations, memory=memory, instruction_regions=regions)
(output/"loader.json").write_text(json.dumps(document,indent=2)+"\\n")
'''


def save(path, document):
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def fact_rows(path):
    return [line.split() for line in path.read_text().splitlines() if line.strip()]


def compare(binary, destination, bpax, reference_python, candidates, random_selection):
    ours_dir, reference_dir = destination / "ours", destination / "bpax"
    for directory in (ours_dir, reference_dir, reference_dir / "facts", ours_dir / "memory"):
        directory.mkdir(parents=True, exist_ok=True)
    # Generate the public CLI artifact, then reopen for memory observations.
    subprocess.run([sys.executable, "-m", "bpa", str(binary), "-o", str(ours_dir / "binary.json")],
                   cwd=ROOT, check=True)
    ours = json.loads((ours_dir / "binary.json").read_text())
    loaded = open_elf(binary)
    if loaded.info.sha256 != ours["sha256"]:
        raise RuntimeError("Input changed while generating M1 observations")
    exporter = reference_dir / "export_loader.py"
    exporter.write_text(REFERENCE_EXPORT)
    env = dict(os.environ)
    # BPA-X's helpers invoke GNU readelf by name. Use the existing local tree.
    toolchain = Path("/home/qc/.local/opt/gcc/usr")
    env["PATH"] = str(toolchain / "bin") + os.pathsep + env.get("PATH", "")
    env["LD_LIBRARY_PATH"] = str(toolchain / "lib/x86_64-linux-gnu") + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    commands = [[str(reference_python), str(exporter), str(binary), str(reference_dir), str(bpax)]]
    for script in ("readelf-txt-section.py", "readelf-global-rgn.py"):
        commands.append([str(reference_python), str(bpax / "utils" / script), str(binary), str(reference_dir / "facts")])
    commands.append([str(reference_python), str(bpax / "utils/get_global_rgn_data.py"),
                     str(binary), ours["arch"], str(reference_dir / "facts")])
    for index, command in enumerate(commands):
        result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True)
        (reference_dir / f"command_{index}.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"Reference export failed; see {reference_dir / f'command_{index}.log'}")
    reference = json.loads((reference_dir / "loader.json").read_text())
    checks = []

    def check(name, actual, expected):
        equal = actual == expected
        row = {"name": name, "equal": equal}
        if not equal:
            row.update(actual=actual, expected=expected)
        checks.append(row)

    check("input_identity", {k: ours[k] for k in ("path", "sha256", "file_size")},
          {k: reference[k] for k in ("path", "sha256", "file_size")})
    check("elf_header", {k: ours[k] for k in reference["header"]}, reference["header"])
    for field in ("arch", "linked_base", "mapped_base", "mapped_entry", "dependencies"):
        check(field, ours[field], reference[field])
    check("loader_version", ours["loader_version"], reference["cle_version"])
    check("load_bias", ours["load_bias"], reference["mapped_base"] - reference["linked_base"])
    expected_segments = [dict(offset=s["p_offset"], virtual_address=s["p_vaddr"], file_size=s["p_filesz"],
                              memory_size=s["p_memsz"], readable=bool(s["p_flags"] & 4),
                              writable=bool(s["p_flags"] & 2), executable=bool(s["p_flags"] & 1))
                         for s in reference["segments"]]
    check("segments", ours["segments"], expected_segments)
    expected_sections = []
    for section in reference["sections"]:
        s = section["header"]
        expected_sections.append(dict(name=section["name"], type=s["sh_type"], virtual_address=s["sh_addr"],
                                      offset=s["sh_offset"], size=s["sh_size"], allocated=bool(s["sh_flags"] & 2),
                                      writable=bool(s["sh_flags"] & 1), executable=bool(s["sh_flags"] & 4)))
    check("sections", ours["sections"], expected_sections)
    expected_symbols = []
    for s in reference["symbols"]:
        index = s["section"]
        addressable = (not s["is_import"] and index is not None and 0 <= index < len(expected_sections)
                       and expected_sections[index]["allocated"] and s["type"] != "TYPE_TLS_OBJECT")
        row = {k: s[k] for k in ("name", "type", "size", "is_function", "is_import", "is_export", "is_weak")}
        row.update(elf_address=s["linked_addr"] if addressable else None,
                   mapped_address=s["rebased_addr"] if addressable else None)
        expected_symbols.append(row)
    expected_symbols.sort(key=lambda s: (s["name"], s["elf_address"] is None, s["elf_address"] or 0, s["type"]))
    check("symbols", ours["symbols"], expected_symbols)
    expected_imports = []
    for r in reference["imports"]:
        row = {k: r[k] for k in ("name", "is_weak", "resolved", "target_mapped_address", "target_is_extern")}
        row.update(slot_elf_address=r["linked_addr"], slot_mapped_address=r["rebased_addr"])
        expected_imports.append(row)
    check("imports", ours["imports"], expected_imports)
    expected_relocations = []
    for r in reference["relocations"]:
        row = {k: r[k] for k in ("type", "symbol", "resolved", "target_mapped_address", "target_is_extern")}
        row.update(elf_address=r["linked_addr"], mapped_address=r["rebased_addr"])
        expected_relocations.append(row)
    check("relocations", ours["relocations"], expected_relocations)
    expected_plt = [dict(name=name, elf_address=address - ours["load_bias"], mapped_address=address)
                    for name, address in sorted(reference["plt"].items())]
    check("plt", ours["plt"], expected_plt)
    check("executable_regions", [[r["start"], r["end"]] for r in ours["executable_regions"]],
          reference["instruction_regions"])
    facts = reference_dir / "facts"
    expected_globals = [[name, int(start), int(end) + 1] for name, start, end in fact_rows(facts / "global_rgn.facts")]
    check("global_regions", [[r["name"], r["start"], r["end"]] for r in ours["global_regions"]], expected_globals)
    section_ranges = {s["name"]: [s["virtual_address"], s["virtual_address"] + s["size"]] for s in ours["sections"]}
    check("text_region", section_ranges[".text"], list(map(int, fact_rows(facts / "txt_section.facts")[0])))
    check("plt_regions", [section_ranges[n] for n in (".plt", ".plt.sec", ".plt.got") if n in section_ranges],
          [list(map(int, row)) for row in fact_rows(facts / "plt_section.facts")])
    memory = []
    for index, segment in enumerate(ours["segments"]):
        address = segment["virtual_address"] + ours["load_bias"]
        raw = loaded.read_memory(address, segment["memory_size"])
        filename = f"memory/segment_{index}.bin"
        (ours_dir / filename).write_bytes(raw)
        memory.append(dict(mapped_address=address, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), file=filename))
        check(f"memory_segment_{index}", raw.hex(), (reference_dir / filename).read_bytes().hex())
    save(ours_dir / "memory.json", memory)
    # Compare the original BPA-X helper's raw .data/.rodata facts, not relocated memory.
    raw_file = binary.read_bytes()
    if hashlib.sha256(raw_file).hexdigest() != ours["sha256"]:
        raise RuntimeError("Input changed before raw global data comparison")
    words = []
    word_size = ours["bits"] // 8
    for name in (".data", ".rodata"):
        section = next(s for s in ours["sections"] if s["name"] == name)
        raw = raw_file[section["offset"]:section["offset"] + section["size"]]
        for offset in range(0, len(raw) - word_size + 1, word_size):
            words.append([section["virtual_address"] + offset, int.from_bytes(raw[offset:offset + word_size], ours["endianness"])])
    (ours_dir / "global_rgn_data.facts").write_text("".join(f"{a}\t{v}\n" for a,v in words))
    check("raw_global_words", words, [list(map(int, row)) for row in fact_rows(facts / "global_rgn_data.facts")])
    report = dict(binary=str(binary), sha256=ours["sha256"], random_selection=random_selection,
                  candidates=[str(p) for p in candidates], reference_commands=commands,
                  reference_scope="BPA-X angr.Project loader and original region/data helpers; no CFG or points-to solver",
                  normalizations=["BPA-X global_rgn.facts inclusive end converted to exclusive end",
                                  "CLE symbol addresses normalized to M1's defined main-image address contract"],
                  counts={name: len(ours[name]) for name in ("segments", "sections", "symbols", "imports", "plt", "relocations")},
                  raw_global_words=len(words), checks=checks,
                  status="passed" if all(c["equal"] for c in checks) else "failed")
    save(destination / "comparison.json", report)
    print(json.dumps({"binary": binary.name, "status": report["status"],
                      "checks": len(checks), "passed": sum(c["equal"] for c in checks),
                      "counts": report["counts"], "report": str(destination / "comparison.json")}, indent=2))
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="Use this sample instead of selecting one randomly")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bpax-root", type=Path, default=Path("/home/qc/Desktop/rebuild/bpa_x"))
    parser.add_argument("--reference-python", type=Path,
                        default=Path("/home/qc/Desktop/binwork/mywork/BPA/.venv/bin/python"))
    args = parser.parse_args()
    candidates = sorted(p.resolve() for p in (ROOT / "tests/fixtures/binaries/bzip2").rglob("bzip2_*") if p.is_file())
    if args.binary is None and not candidates:
        parser.error("No bzip2 samples found under tests/fixtures/binaries/bzip2")
    binary = args.binary.resolve() if args.binary else random.SystemRandom().choice(candidates)
    destination = (args.output or ROOT / "outputs/m1_compare" / binary.name).resolve()
    print(f"Selected: {binary}", flush=True)
    return compare(binary, destination, args.bpax_root.resolve(), args.reference_python,
                   candidates, args.binary is None)


if __name__ == "__main__":
    raise SystemExit(main())
