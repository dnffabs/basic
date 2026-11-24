"""Compare independent BPA-X normal/normal outputs using boundaries, not assigned IDs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from compare_m2_bpax import DEFAULT_BPAX_ROOT, DEFAULT_REFERENCE_PYTHON, DEFAULT_READELF_BIN


def reference(binary, arch, work, bpax, python, souffle, readelf_bin):
    facts = work / "facts"
    facts.mkdir()
    env = dict(os.environ, PATH=str(readelf_bin) + os.pathsep + os.environ["PATH"])

    def run(*args, cwd=work):
        proc = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
        if proc.returncode:
            raise RuntimeError(f"{args}: {proc.stdout}{proc.stderr}")

    def rule(name):
        run(souffle, "-j", "1", "-F", facts, "-D", facts, "--macro=" + arch,
            bpax / "logic/souffle" / (name + ".dl"))

    def helper(name, *args):
        run(python, bpax / "utils" / (name + ".py"), *args)

    run(python, "gen_facts.py", binary, arch, facts, cwd=bpax / "vex_fact_gen")
    helper("readelf-txt-section", binary, facts)
    helper("readelf-global-rgn", binary, facts)
    for name in ("func-bound-merge", "user_defined_addr_func", "reverse-tail-call-opt",
                 "remove-exit-inter-succ", "filter-instr", "addr_func_instr"):
        rule("pre-process/" + name)
    helper("get_global_rgn_data", binary, arch, facts)
    rule("pre-process/AT_func")
    rule("pre-process/remove-unreachable-func")
    helper("get_push_instr_addr", binary, facts)
    helper("get_func_arg_pass_instr_addr", binary, arch, facts)
    rule("mem-alloc/preprocess")
    helper("stack-analysis-preprocess", facts, binary)
    for name in ("sblk_dwarf_func", "sblk_dwarf_var"):
        (facts / (name + ".facts")).touch()
    for name in ("local-mem-block", "global-mem-block", "heap-mem-block"):
        rule("mem-alloc/" + name)
    helper("mloc-gen", facts, "normal")
    rule("mem-alloc/postprocess")
    return facts


def semantic_keys(directory):
    def rows(name):
        return [line.split("\t") for line in (directory / (name + ".facts")).read_text().splitlines()]
    stack_blocks = {r[0]: tuple(map(int, r[1:])) for r in rows("mloc_sblk")}
    return {
        "stack_evidence": {(int(site), int(order), int(fn), int(off))
                           for site, order, _, fn, off in rows("local_block_boundary")},
        "stack_temporary_blocks": {(tmp, *stack_blocks[bid]) for tmp, bid in rows("tmp_reg_sblk_id")},
        "stack_boundaries": {(int(r[3]), int(r[4])) for r in rows("local_block_boundary")},
        "global_candidates": {(int(r[0]), int(r[1])) for r in rows("global_chunk_boundary")},
        "global_boundaries": {(int(r[0]), int(r[1])) for r in rows("global_block_boundary")},
        "stack": set(stack_blocks.values()),
        "global": {tuple(map(int, r[1:])) for r in rows("mloc_gblk")},
        "heap": {(int(r[1]),) for r in rows("mloc_hblk")},
    }


if __name__ == "__main__":
    from bpa.memory import run_m4

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--m3", type=Path, help="Reuse our prior M3 output; reference extraction always runs independently")
    parser.add_argument("--bpax-root", type=Path, default=DEFAULT_BPAX_ROOT)
    parser.add_argument("--reference-python", type=Path, default=DEFAULT_REFERENCE_PYTHON)
    parser.add_argument("--readelf-bin", type=Path, default=DEFAULT_READELF_BIN)
    parser.add_argument("--souffle", default="souffle")
    args = parser.parse_args()
    binary, root = args.binary.resolve(), args.output.resolve()
    result = run_m4(binary, root, m3_path=args.m3, souffle=args.souffle)
    if result["load_bias"]:
        parser.error("Independent BPA-X front end requires matching mapped and ELF VAs for this comparison")
    with tempfile.TemporaryDirectory(dir=root) as tmp:
        ref = reference(binary, result["arch"], Path(tmp), args.bpax_root.resolve(), args.reference_python.absolute(),
                        args.souffle, args.readelf_bin.resolve())
        ours = semantic_keys(root / "m4" / result["facts_dir"])
        theirs = semantic_keys(ref)
    diff = {k: dict(count=len(ours[k]), reference_count=len(theirs[k]),
                    only_ours=sorted(ours[k]-theirs[k]), only_reference=sorted(theirs[k]-ours[k]))
            for k in ours}
    passed = all(ours[k] == theirs[k] for k in ours)
    report = dict(binary_sha256=result["binary_sha256"], passed=passed, checks=diff)
    (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(binary.name, "passed" if passed else "differences", root / "comparison.json")
    raise SystemExit(0 if passed else 1)
