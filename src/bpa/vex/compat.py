"""Optional BPA-X projection from raw facts; never changes the raw extraction.

This adapter reproduces BPA-X's register filtering and condition omission only
in the projected view. It does not run BPA-X or its points-to solver.
"""

import argparse
import json
from pathlib import Path
import re

import archinfo

from .facts import escape, read_facts, _check_output


REGISTERS = frozenset("eax ecx edx ebx esi edi ebp esp rax rcx rdx rbx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split())
BINOP_DL = dict(Add="+", Sub="-", Mul="*", DivU="/", DivS="/", Or="bor", And="band",
                Xor="bxor", Shl="bshl", Shr="bshru", Sar="bshr", CmpEQ="=", CmpNE="!=", CmpLT="<", CmpLE="<=")


def short_binop(opcode):
    """The scalar integer mapping used by BPA-X's operators.json (not full VEX)."""
    op = opcode.removeprefix("Iop_")
    match = re.fullmatch(r"(Add|Sub|Mul|Or|And|Xor|Shl|Shr|Sar|CmpEQ|CmpNE)(8|16|32|64)", op)
    if match:
        return match[1], int(match[2])
    match = re.fullmatch(r"(?:Mull[SU])(8|16|32|64)", op)
    if match:
        return "Mul", int(match[1])
    match = re.fullmatch(r"Div([US])(32|64)", op)
    if match:
        return "Div" + match[1], int(match[2])
    match = re.fullmatch(r"CasCmp(EQ|NE)(8|16|32|64)", op)
    if match:
        return "Cmp" + match[1], int(match[2])
    match = re.fullmatch(r"ExpCmpNE(8|16|32|64)", op)
    if match:
        return "CmpNE", int(match[1])
    match = re.fullmatch(r"Cmp(LT|LE)(32|64)[US]", op)
    if match:
        return "Cmp" + match[1], int(match[2])
    match = re.fullmatch(r"(8|16|32)HLto(16|32|64)", op)
    if match and int(match[2]) == 2 * int(match[1]):
        return "Concat", int(match[2])
    match = re.fullmatch(r"DivMod([US])(64|128)to(32|64)", op)
    if match:
        return "DivMod" + match[1], 128 if op == "DivModS64to64" else int(match[2])
    return "Unsupported", 0


class Projection:
    def __init__(self, raw):
        raw.validate()
        self.raw = raw
        self.rows = {name: [] for name in (
            "get_loc_vex_exp", "get_tmp_reg_vex_exp", "get_mem_vex_exp", "imm_vex_exp",
            "unop_vex_exp", "binop_vex_exp", "if_vex_exp", "set_loc_vex", "set_tmp_reg_vex",
            "set_mem_vex", "imark_vex", "instr_vex", "binop_dl_exp", "unop_dl_exp",
            "cast_s_dl_exp", "cast_u_dl_exp", "expression_origin", "statement_origin", "generated_expression")}
        self.expressions = {r[0]: r for r in raw.rows["expression"]}
        self.constants = {r[0]: r[1:] for r in raw.rows["constant"]}
        self.reads = {r[0]: r[1:] for r in raw.rows["register_read"]}
        self.temps = {r[0]: r[1:] for r in raw.rows["temporary_read"]}
        self.loads = {r[0]: r[1:] for r in raw.rows["load"]}
        self.ops = dict(raw.rows["operation"])
        self.args = {}
        for eid, index, argument in raw.rows["operand"]:
            self.args.setdefault(eid, {})[index] = argument
        self.arch = archinfo.arch_from_id(raw.metadata["arch"])
        self.cache, self.const_ids = {}, {}
        self.next_id = max([0, *self.expressions, *(r[0] for r in raw.rows["statement"])]) + 1

    def add(self, name, *row):
        self.rows[name].append(tuple(row))

    def fresh(self):
        eid = self.next_id
        self.next_id += 1
        return eid

    def reg_name(self, offset):
        # Deliberately match BPA-X's offset-only name lookup in this projection.
        return self.arch.translate_register_name(offset)

    def expr(self, eid):
        if eid in self.cache:
            return self.cache[eid]
        value = None
        if eid in self.constants:
            bits, hexadecimal = self.constants[eid]
            key = bits, int(hexadecimal, 16)
            if bits <= 64:
                value = self.const_ids.get(key)
                if value is None:
                    value = self.const_ids[key] = eid
                    self.add("imm_vex_exp", eid, bits, key[1])
        elif eid in self.reads:
            offset, _ = self.reads[eid]
            name = self.reg_name(offset)
            if name in REGISTERS:
                self.add("get_loc_vex_exp", eid, name)
                value = eid
        elif eid in self.temps:
            block, index = self.temps[eid]
            self.add("get_tmp_reg_vex_exp", eid, self.expressions[eid][2], f"{block}_{index}")
            value = eid
        elif eid in self.loads:
            address, bits, _ = self.loads[eid]
            argument = self.expr(address)
            if argument is not None:
                self.add("get_mem_vex_exp", eid, bits, argument)
                value = eid
        elif eid in self.ops:
            op = self.ops[eid]
            arguments = self.args.get(eid, {})
            tag = self.expressions[eid][3]
            if op == "ITE":
                yes, no = self.expr(arguments[1]), self.expr(arguments[2])
                if yes is not None or no is not None:
                    self.add("if_vex_exp", eid, 0, yes or 0, no or 0)
                    value = eid
            elif tag in ("Iex_Unop", "Iex_Binop"):
                operands = [self.expr(arguments[index]) for index in sorted(arguments)]
                if all(arg is not None for arg in operands):
                    if tag == "Iex_Unop":
                        self.add("unop_vex_exp", eid, op.removeprefix("Iop_"), operands[0])
                    else:
                        short, bits = short_binop(op)
                        self.add("binop_vex_exp", eid, bits, short, *operands)
                    value = eid
        self.cache[eid] = value
        if value is not None:
            self.add("expression_origin", value, eid)
        return value

    def project(self):
        raw = self.raw.rows
        temp_writes = {r[0]: r[1:] for r in raw["temporary_write"]}
        reg_writes = {r[0]: r[1:] for r in raw["register_write"]}
        stores = {r[0]: r[1:] for r in raw["store"]}
        sizes = {(r[0], r[1]): r[2] for r in raw["instruction"]}
        temp_bits = {(r[0], r[1]): r[2] for r in raw["temporary"]}
        previous_order, previous_block = 1, None
        for sid, block, _, instruction, order, tag in raw["statement"]:
            if block != previous_block:
                previous_order, previous_block = 1, block
            if tag == "Terminator":
                continue
            self.add("statement_origin", instruction, order, sid)
            if tag == "Ist_IMark":
                self.add("imark_vex", instruction, sizes[(block, instruction)], 0)
                self.add("instr_vex", instruction, previous_order)
                previous_order = 1
                continue
            self.add("instr_vex", instruction, order)
            previous_order = order + 1
            if sid in temp_writes:
                bb, index, rhs = temp_writes[sid]
                value = self.expr(rhs)
                if value is not None:
                    self.add("set_tmp_reg_vex", instruction, order, temp_bits[(bb, index)], value, f"{bb}_{index}")
            elif sid in reg_writes:
                offset, bits, rhs = reg_writes[sid]
                value = self.expr(rhs)
                name = self.reg_name(offset)
                if name in REGISTERS and value is not None:
                    self.add("set_loc_vex", instruction, order, bits, value, name)
            elif sid in stores:
                address, rhs, bits, _ = stores[sid]
                value, pointer = self.expr(rhs), self.expr(address)
                if value is not None and pointer is not None:
                    self.add("set_mem_vex", instruction, order, bits, value, pointer)
        self.derive_operations()
        return self.rows

    def derive_operations(self):
        constants = {}
        for eid, bits, value in self.rows["imm_vex_exp"]:
            if bits == 32 and value in (1, 8, 16, 32, 64, 128):
                constants.setdefault(value, eid)
        for bits in (1, 8, 16, 32, 64, 128):
            if bits not in constants:
                constants[bits] = self.fresh()
                self.add("imm_vex_exp", constants[bits], 32, bits)
                self.add("generated_expression", constants[bits], "bit_width_constant")
        unsigned = {"8Uto16", "8Uto32", "8Uto64", "16Uto32", "16Uto64", "32Uto64",
                    "16to8", "32to8", "32to16", "64to8", "64to16", "64to32", "128to64",
                    "32to1", "64to1", "1Uto8", "1Uto32", "1Uto64"}
        signed = {"8Sto16", "8Sto32", "8Sto64", "16Sto32", "16Sto64", "32Sto64", "1Sto8", "1Sto16", "1Sto32", "1Sto64"}
        high = {"16HIto8", "32HIto16", "64HIto32", "128HIto64"}
        for eid, op, argument in self.rows["unop_vex_exp"]:
            if re.fullmatch(r"Not(1|8|16|32|64)", op):
                self.add("unop_dl_exp", eid, int(op[3:]), "bnot", argument)
            elif op in unsigned | signed | high:
                src, dst = map(int, re.fullmatch(r"(\d+)\D*to(\d+)", op).groups())
                if op in high:
                    temporary = self.fresh()
                    self.add("binop_dl_exp", temporary, src, "bshru", argument, constants[dst])
                    self.add("expression_origin", temporary, eid)
                    argument = temporary
                self.add("cast_s_dl_exp" if op in signed else "cast_u_dl_exp", eid, src, dst, argument)
        for eid, bits, op, left, right in self.rows["binop_vex_exp"]:
            if op in BINOP_DL:
                self.add("binop_dl_exp", eid, bits, BINOP_DL[op], left, right)
            elif op in ("DivModU", "DivModS", "Concat"):
                a, b, c = self.fresh(), self.fresh(), self.fresh()
                for temporary in (a, b, c):
                    self.add("expression_origin", temporary, eid)
                half = bits // 2
                if op == "Concat":
                    self.add("cast_u_dl_exp", a, half, bits, left)
                    self.add("binop_dl_exp", b, bits, "bshl", a, constants[half])
                    self.add("cast_u_dl_exp", c, half, bits, right)
                    self.add("binop_dl_exp", eid, bits, "bor", b, c)
                else:
                    self.add("binop_dl_exp", a, half, "/", left, right)
                    self.add("binop_dl_exp", b, half, "%", left, right)
                    self.add("binop_dl_exp", c, bits, "bshl", b, constants[half])
                    self.add("binop_dl_exp", eid, bits, "bor", c, a)


def write_projection(raw, directory, *, protected=()):
    if raw.metadata.get("status") != "complete":
        raise ValueError("Cannot project an incomplete M3 extraction")
    rows = Projection(raw).project()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name in [*(f"{name}.facts" for name in rows), "projection.json"]:
        _check_output(directory / name, protected)
    for name, values in rows.items():
        (directory / f"{name}.facts").write_text("".join("\t".join(escape(v) for v in row) + "\n" for row in values))
    (directory / "projection.json").write_text(json.dumps(dict(
        schema="bpa.m3.bpax-projection.v1", address_space="elf-va",
        binary_sha256=raw.metadata["binary_sha256"], counts={name: len(values) for name, values in rows.items()},
        scope="instruction value relations and converted operations; not a complete BPA-X pipeline input",
        approximations=["BPA-X register whitelist and offset-only names", "ITE condition omitted in this view only",
                        "Exit/guarded accesses/helpers unmodeled as in BPA-X", "signed/unsigned division and comparisons use BPA-X mapping",
                        "constants over 64 bits omitted; original bitvectors remain in raw facts"]), indent=2) + "\n")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("m3", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() == args.m3.resolve():
        parser.error("Projection output must differ from the raw M3 directory")
    protected = list(args.m3.iterdir())
    raw = read_facts(args.m3)
    write_projection(raw, args.output, protected=protected + [raw.metadata["binary_path"]])
    print(f"Saved BPA-X projection: {args.output}")


if __name__ == "__main__":
    main()
