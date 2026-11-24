"""Compare M2 functions, blocks, and edges with BPA-X CFGFast facts.

The reference side runs BPA-X's own fact generation and function pre-processing;
it does not run the points-to solver. M2 is built in-process with build_cfg().
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from bpa.cfg import build_cfg
from bpa.loader import load_elf


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BPAX_ROOT = Path("/home/qc/Desktop/rebuild/bpa_x")
DEFAULT_REFERENCE_PYTHON = Path("/home/qc/Desktop/binwork/mywork/BPA/.venv/bin/python")
DEFAULT_SOUFFLE = Path("/home/qc/Desktop/binwork/tools/bin/souffle")
DEFAULT_READELF_BIN = Path("/home/qc/Desktop/binwork/bpa-x/.venv/bin")


def run(command, cwd=None, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("command failed: %s\n%s%s"
                           % (" ".join(map(str, command)), result.stdout, result.stderr))
    return result


def fact_rows(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line.strip()]


def generate_facts(binary, arch, work, bpax, reference_python, souffle, readelf_bin, facts_dir=None):
    """Run BPA-X's fact generation plus func-bound-merge and user_defined filter."""
    env = dict(os.environ)
    env["PATH"] = str(readelf_bin) + os.pathsep + env.get("PATH", "")
    if facts_dir is None:
        facts = work / "facts"
        facts.mkdir(parents=True, exist_ok=True)
        run([str(reference_python), str(bpax / "vex_fact_gen/gen_facts.py"),
             str(binary), arch, str(facts)],
            cwd=bpax / "vex_fact_gen", env=env)
        run([str(reference_python), str(bpax / "utils/readelf-txt-section.py"),
             str(binary), str(facts)], env=env)
    else:
        facts = Path(facts_dir)
    merged = work / "merged"
    user = work / "user"
    merged.mkdir(parents=True, exist_ok=True)
    user.mkdir(parents=True, exist_ok=True)
    shutil.copy(facts / "txt_section.facts", merged / "txt_section.facts")
    preprocess = bpax / "logic/souffle/pre-process"
    run([str(souffle), "--fact-dir=" + str(facts), "--output-dir=" + str(merged),
         "--macro=" + arch, "func-bound-merge.dl"], cwd=preprocess)
    merged_txt = merged / "txt_section.facts"
    user_txt = user / "txt_section.facts"
    shutil.copy(merged_txt, user_txt)
    run([str(souffle), "--fact-dir=" + str(merged), "--output-dir=" + str(user),
         "--macro=" + arch, "user_defined_addr_func.dl"], cwd=preprocess)
    return facts, merged / "addr_func.facts", user / "user_defined_addr_func.facts"


def block_rows(result):
    rows = set()
    for block in result.blocks:
        last = block.instructions[-1].address if block.instructions else block.address
        rows.add((block.address, last))
    return rows


def edge_rows(result):
    """Normalize M2 edges to BPA-X's (src last instruction, dst first instruction)."""
    blocks = {block.address: block for block in result.blocks}
    rows = set()
    for edge in result.edges:
        source = blocks.get(edge.source)
        target = blocks.get(edge.target)
        if source is None or target is None or not source.instructions or not target.instructions:
            continue
        rows.add((source.instructions[-1].address, target.instructions[0].address))
    return rows


def compare(binary, arch, destination, work, bpax, reference_python, souffle, readelf_bin,
            facts_dir=None):
    facts, _merged_func, user_func = generate_facts(
        binary, arch, work, bpax, reference_python, souffle, readelf_bin, facts_dir)
    result = build_cfg(load_elf(binary))

    reference_functions = {}
    for name, lower, upper in fact_rows(user_func):
        reference_functions[int(lower)] = (name, int(upper))
    ours = {function.entry: function for function in result.functions}

    function_diffs = []
    for entry, (name, upper) in reference_functions.items():
        function = ours.get(entry)
        if function is None:
            function_diffs.append(dict(kind="missing", entry=entry, name=name))
            continue
        if function.name != name:
            function_diffs.append(dict(kind="name", entry=entry, expected=name, actual=function.name))
        if not function.code_ranges or function.code_ranges[0][0] != entry \
                or function.code_ranges[-1][1] != upper:
            function_diffs.append(dict(kind="range", entry=entry, name=name, expected_upper=upper,
                                       actual=[list(row) for row in function.code_ranges]))
    for entry, function in ours.items():
        if entry not in reference_functions:
            function_diffs.append(dict(kind="extra", entry=entry, name=function.name))

    reference_blocks = {(int(start), int(last))
                        for start, last in fact_rows(facts / "bb_addr_bound.facts")}
    our_blocks = block_rows(result)
    block_diffs = dict(only_ours=[list(row) for row in sorted(our_blocks - reference_blocks)],
                       only_reference=[list(row) for row in sorted(reference_blocks - our_blocks)])

    reference_edges = {(int(src), int(dst)) for src, dst in fact_rows(facts / "edge.facts")}
    our_edges = edge_rows(result)
    blocks = {block.address: block for block in result.blocks}
    fake_returns = set()
    for edge in result.edges:
        if edge.kind != "fake_return":
            continue
        source = blocks.get(edge.source)
        target = blocks.get(edge.target)
        if source and target and source.instructions and target.instructions:
            fake_returns.add((source.instructions[-1].address, target.instructions[0].address))
    our_edges_without_fake = our_edges - fake_returns
    edge_diffs = dict(only_ours=[list(row) for row in sorted(our_edges_without_fake - reference_edges)],
                      only_reference=[list(row) for row in sorted(reference_edges - our_edges_without_fake)],
                      fake_return_edges=len(fake_returns))

    checks = {
        "functions": not function_diffs,
        "blocks": not any(block_diffs.values()),
        "edges_excluding_fake_return": not edge_diffs["only_ours"] and not edge_diffs["only_reference"],
    }
    report = dict(
        binary=str(binary),
        sha256=result.binary_sha256,
        arch=arch,
        reference_scope="BPA-X CFGFast fact generation, func-bound-merge and "
                        "user_defined_addr_func; no points-to solver",
        normalizations=[
            "functions compared by entry, name, and BPA-X next-entry upper bound",
            "blocks compared as (start, last instruction address)",
            "edges compared as (source last instruction, target first instruction)",
            "M2 fake_return (assumed-return) edges excluded; BPA-X edge.facts omits them",
            "edges to non-block/external targets and unresolved targets are excluded",
        ],
        counts=dict(functions=len(ours), reference_functions=len(reference_functions),
                    blocks=len(our_blocks), reference_blocks=len(reference_blocks),
                    edges=len(our_edges_without_fake), reference_edges=len(reference_edges),
                    fake_return_edges=len(fake_returns)),
        checks=checks,
        function_differences=function_diffs,
        block_differences=block_diffs,
        edge_differences=edge_diffs,
        status="passed" if all(checks.values()) else "failed",
    )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(binary=binary.name, status=report["status"],
                          counts=report["counts"], checks=checks,
                          report=str(destination / "comparison.json")), indent=2))
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--arch", choices=("AMD64", "X86"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--work-dir", type=Path,
                        help="Keep generated facts here (default: outputs/m2_compare/<name>/work)")
    parser.add_argument("--facts-dir", type=Path,
                        help="Reuse existing BPA-X facts instead of running gen_facts.py")
    parser.add_argument("--bpax-root", type=Path, default=DEFAULT_BPAX_ROOT)
    parser.add_argument("--reference-python", type=Path, default=DEFAULT_REFERENCE_PYTHON)
    parser.add_argument("--souffle", type=Path, default=DEFAULT_SOUFFLE)
    parser.add_argument("--readelf-bin", type=Path, default=DEFAULT_READELF_BIN)
    args = parser.parse_args()
    binary = args.binary.resolve()
    arch = args.arch or ("AMD64" if load_elf(binary).bits == 64 else "X86")
    destination = (args.output or ROOT / "outputs/m2_compare" / binary.name).resolve()
    work = (args.work_dir or destination / "work").resolve()
    work.mkdir(parents=True, exist_ok=True)
    return compare(binary, arch, destination, work, args.bpax_root.resolve(),
                   args.reference_python, args.souffle, args.readelf_bin,
                   args.facts_dir)


if __name__ == "__main__":
    raise SystemExit(main())