"""Explicitly rebuild the fixed ELF fixtures with the local GCC."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent
BASE_FLAGS = ["-g", "-O0", "-mno-avx", "-mno-sse", "-fno-pie",
              "-fno-stack-protector", "-no-pie"]
ARCH_FLAGS = {64: ["-m64"], 32: ["-m32", "-march=i386"]}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"),
                        help="Local GCC executable (default: CC or gcc)")
    args = parser.parse_args()
    compiler = shutil.which(args.cc)
    if compiler is None:
        parser.error(f"GCC executable not found: {args.cc}")
    compiler = str(Path(compiler).absolute())
    version = subprocess.check_output([compiler, "--version"], text=True).splitlines()[0]
    (ROOT / "binaries").mkdir(exist_ok=True)
    entries = []
    source = Path("sources") / "test.c"
    for bits, arch_flags in ARCH_FLAGS.items():
        identifier = f"test_{bits}"
        binary = Path("binaries") / identifier
        command = [compiler, *arch_flags, *BASE_FLAGS, "-o", str(binary), str(source)]
        subprocess.run(command, cwd=ROOT, check=True)
        entries.append({
            "id": identifier, "source": source.as_posix(), "binary": binary.as_posix(),
            "source_sha256": digest(ROOT / source), "sha256": digest(ROOT / binary),
            "command": command, "command_cwd": "tests/fixtures",
            "expected": {
                "bits": bits,
                "machine": "EM_X86_64" if bits == 64 else "EM_386",
                "elf_type": "ET_EXEC",
                "endianness": "little", "has_debug_info": True,
                "has_symtab": True, "exit_code": 0,
                "stdout": "bpa-test: 13 5 8 9\n",
            },
        })
        print(f"Built {binary}", flush=True)
    manifest = {"schema_version": 1, "compiler": {"path": compiler, "version": version},
                "samples": entries}
    temporary = ROOT / "manifest.json.tmp"
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(ROOT / "manifest.json")
    print(f"Saved manifest.json ({len(entries)} binaries)")


if __name__ == "__main__":
    main()
