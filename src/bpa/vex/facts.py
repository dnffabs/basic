"""Versioned, typed M3 relations; no angr objects cross this interface."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile


SCHEMA_ID = "bpa.m3.v1"

# unsigned is a Souffle unsigned 64-bit integer; bitvector constants use symbols.
FIELDS = {
    "block": "address:u size:u lifted_size:u jumpkind:s",
    "block_function": "block:u function:u",
    "instruction": "block:u address:u size:u mnemonic:s operands:s",
    "statement": "id:u block:u position:u instruction:u order:u tag:s",
    "expression": "id:u statement:u bits:u tag:s",
    "temporary": "block:u index:u bits:u",
    "temporary_read": "expression:u block:u index:u",
    "temporary_write": "statement:u block:u index:u value:u",
    "constant": "expression:u bits:u value_hex:s",
    "register": "offset:u bits:u name:s",
    "register_read": "expression:u offset:u bits:u",
    "register_write": "statement:u offset:u bits:u value:u",
    "operation": "expression:u opcode:s",
    "operand": "expression:u index:u value:u",
    "load": "expression:u address:u bits:u endness:s",
    "store": "statement:u address:u value:u bits:u endness:s",
    "guarded_load": "statement:u block:u temporary:u address:u alternate:u guard:u bits:u result_bits:u conversion:s endness:s",
    "guarded_store": "statement:u address:u value:u guard:u bits:u endness:s",
    "branch": "statement:u guard:u target:u jumpkind:s",
    "block_exit": "block:u statement:u target:u jumpkind:s",
    "control_transfer": "block:u instruction:u kind:s indirect:u status:s",
    "continuation": "instruction:u target:u",
    "known_target": "instruction:u target:u",
    "external_target": "instruction:u name:s",
    "transfer_statement": "statement:u instruction:u kind:s",
    "cfg_edge": "source:u target:u kind:s provenance:s",
    "cfg_external_edge": "source:u symbol:s kind:s provenance:s",
    "initial_memory": "address:u size:u bytes_hex:s",
    "unmodeled_expression": "expression:u tag:s text:s",
    "unmodeled_statement": "statement:u tag:s text:s",
    "diagnostic": "severity:s code:s block:u instruction:u position:u detail:s",
}
SCHEMAS = {name: tuple(tuple(field.split(":")) for field in fields.split())
           for name, fields in FIELDS.items()}

# Relation, columns, referenced relation, referenced columns.
REFERENCES = [
    ("block_function", (0,), "block", (0,)),
    ("instruction", (0,), "block", (0,)),
    ("statement", (1,), "block", (0,)),
    ("statement", (1, 3), "instruction", (0, 1)),
    ("expression", (1,), "statement", (0,)),
    ("temporary", (0,), "block", (0,)),
    ("temporary_read", (1, 2), "temporary", (0, 1)),
    ("temporary_write", (1, 2), "temporary", (0, 1)),
    ("guarded_load", (1, 2), "temporary", (0, 1)),
    ("register_read", (1, 2), "register", (0, 1)),
    ("register_write", (1, 2), "register", (0, 1)),
    ("block_exit", (0,), "block", (0,)),
    ("control_transfer", (0, 1), "instruction", (0, 1)),
    ("transfer_statement", (1,), "control_transfer", (1,)),
    ("continuation", (0,), "control_transfer", (1,)),
    ("known_target", (0,), "control_transfer", (1,)),
    ("external_target", (0,), "control_transfer", (1,)),
    ("cfg_edge", (0,), "block", (0,)),
    ("cfg_edge", (1,), "block", (0,)),
    ("cfg_external_edge", (0,), "block", (0,)),
]
EXPRESSION_COLUMNS = {
    "temporary_read": (0,), "temporary_write": (3,), "constant": (0,),
    "register_read": (0,), "register_write": (3,), "operation": (0,),
    "operand": (0, 2), "load": (0, 1), "store": (1, 2),
    "guarded_load": (3, 4, 5), "guarded_store": (1, 2, 3),
    "branch": (1, 2), "block_exit": (2,), "unmodeled_expression": (0,),
}
STATEMENT_RELATIONS = ("temporary_write", "register_write", "store", "guarded_load",
                       "guarded_store", "branch", "transfer_statement", "unmodeled_statement")
REFERENCES += [(name, (column,), "expression", (0,))
               for name, columns in EXPRESSION_COLUMNS.items() for column in columns]
REFERENCES += [(name, (0,), "statement", (0,)) for name in STATEMENT_RELATIONS]
REFERENCES += [("block_exit", (1,), "statement", (0,))]
KEYS = {"block": (0,), "instruction": (0, 1), "statement": (0,), "expression": (0,),
        "temporary": (0, 1), "register": (0, 1), "constant": (0,), "operation": (0,),
        "operand": (0, 1), "block_exit": (0,)}


def schema_document():
    return dict(id=SCHEMA_ID, address_space="elf-va",
                constants="raw unsigned bitvectors, fixed-width hexadecimal symbols; never rebased",
                initial_memory="CLE relocated bytes at ELF VA locations; embedded pointers may be mapped VA",
                registers="VEX guest-state byte offset and access width; name is auxiliary",
                ids="positive, disjoint statement/expression IDs; temporaries are (block, index)",
                encoding=r"UTF-8 TSV; symbols escape backslash, tab, newline, carriage return as \\, \t, \n, \r",
                relations={name: [dict(name=field, type="unsigned" if ty == "u" else "symbol")
                                  for field, ty in columns] for name, columns in SCHEMAS.items()},
                unique_keys=KEYS, foreign_keys=REFERENCES)


def declarations():
    return "\n".join(
        f".decl {name}({', '.join(field + ': ' + ('unsigned' if ty == 'u' else 'symbol') for field, ty in columns)})\n"
        f'.input {name}(IO=file, filename="{name}.facts", delimiter="\\t")'
        for name, columns in SCHEMAS.items()) + "\n"


def escape(value):
    return str(value).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def unescape(value):
    result, index = [], 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            index += 1
            if index == len(value) or value[index] not in "\\tnr":
                raise ValueError("Invalid M3 symbol escape")
            char = {"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}[value[index]]
        result.append(char)
        index += 1
    return "".join(result)


@dataclass
class FactResult:
    metadata: dict
    rows: dict

    @classmethod
    def empty(cls, metadata=None):
        return cls(dict(metadata or {}), {name: [] for name in SCHEMAS})

    def add(self, name, *values):
        self.rows[name].append(tuple(values))

    def validate(self):
        if set(self.rows) != set(SCHEMAS):
            raise ValueError("M3 relation set does not match schema")
        for name, columns in SCHEMAS.items():
            for row in self.rows[name]:
                if len(row) != len(columns):
                    raise ValueError(f"Wrong field count in {name}: {row}")
                for value, (field, ty) in zip(row, columns):
                    if (ty == "u" and (type(value) is not int or not 0 <= value < 2**64)) or (
                            ty == "s" and not isinstance(value, str)):
                        raise ValueError(f"Invalid {name}.{field}: {value!r}")
        for name, columns in KEYS.items():
            keys = [tuple(row[c] for c in columns) for row in self.rows[name]]
            if len(set(keys)) != len(keys):
                raise ValueError(f"Duplicate key in {name}")
        indexes = {}
        for name, columns, target, target_columns in REFERENCES:
            key = (target, target_columns)
            if key not in indexes:
                indexes[key] = {tuple(row[c] for c in target_columns) for row in self.rows[target]}
            if any(tuple(row[c] for c in columns) not in indexes[key] for row in self.rows[name]):
                raise ValueError(f"Dangling {name} reference to {target}")
        statements = {row[0] for row in self.rows["statement"]}
        expressions = {row[0] for row in self.rows["expression"]}
        if 0 in statements | expressions or statements & expressions:
            raise ValueError("Statement/expression IDs must be positive and disjoint")
        statement_rows = {row[0]: row for row in self.rows["statement"]}
        expression_rows = {row[0]: row for row in self.rows["expression"]}
        temporary_bits = {(block, index): bits for block, index, bits in self.rows["temporary"]}
        for eid, block, index in self.rows["temporary_read"]:
            row = expression_rows[eid]
            if statement_rows[row[1]][1] != block or row[2] != temporary_bits[(block, index)]:
                raise ValueError("Temporary read scope/width mismatch")
        for sid, block, index, value in self.rows["temporary_write"]:
            if statement_rows[sid][1] != block or expression_rows[value][2] != temporary_bits[(block, index)]:
                raise ValueError("Temporary write scope/width mismatch")
        for eid, _, bits in self.rows["register_read"]:
            if expression_rows[eid][2] != bits:
                raise ValueError("Register read width mismatch")
        for _, _, bits, value in self.rows["register_write"]:
            if expression_rows[value][2] != bits:
                raise ValueError("Register write width mismatch")
        for eid, _, bits, endness in self.rows["load"]:
            if expression_rows[eid][2] != bits or endness not in ("Iend_LE", "Iend_BE"):
                raise ValueError("Invalid load width/endness")
        for _, _, value, bits, endness in self.rows["store"]:
            if expression_rows[value][2] != bits or endness not in ("Iend_LE", "Iend_BE"):
                raise ValueError("Invalid store width/endness")
        for _, bits, _ in self.rows["constant"]:
            if bits == 0:
                raise ValueError("Constant width must be positive")
        for _, bits, value in self.rows["constant"]:
            if bits == 0 or not value.startswith("0x") or len(value) != 2 + (bits + 3) // 4 or not 0 <= int(value, 16) < 2**bits:
                raise ValueError("Invalid constant bitvector")
        for _, size, value in self.rows["initial_memory"]:
            if len(bytes.fromhex(value)) != size:
                raise ValueError("Invalid initial memory chunk")


def _check_output(path, protected):
    for source in protected:
        source = Path(source)
        if path.resolve() == source.resolve() or (path.exists() and source.exists() and path.samefile(source)):
            raise ValueError(f"Output must not overwrite input: {path}")


def write_facts(result: FactResult, directory: str | Path, *, protected=()):
    """Stage files first; publish the checksum manifest last so readers detect mixed generations."""
    result.validate()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    names = [f"{name}.facts" for name in SCHEMAS] + ["schema.json", "schema.dl", "manifest.json"]
    for name in names:
        _check_output(directory / name, protected)
    with tempfile.TemporaryDirectory(prefix=".m3-", dir=directory.parent) as temporary:
        staged = Path(temporary)
        for name, rows in result.rows.items():
            with (staged / f"{name}.facts").open("w", encoding="utf-8") as stream:
                for row in rows:
                    stream.write("\t".join(escape(value) for value in row) + "\n")
        (staged / "schema.json").write_text(json.dumps(schema_document(), indent=2) + "\n")
        (staged / "schema.dl").write_text(declarations())
        manifest = dict(result.metadata, schema=SCHEMA_ID, stage="M3", address_space="elf-va",
                        counts={name: len(rows) for name, rows in result.rows.items()},
                        files={name: hashlib.sha256((staged / name).read_bytes()).hexdigest()
                               for name in names if name != "manifest.json"})
        (staged / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for name in names:
            os.replace(staged / name, directory / name)
    return manifest


def read_facts(directory: str | Path) -> FactResult:
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA_ID or manifest.get("address_space") != "elf-va":
        raise ValueError("Expected M3 schema bpa.m3.v1 with ELF VA addresses")
    expected = {f"{name}.facts" for name in SCHEMAS} | {"schema.json", "schema.dl"}
    if set(manifest["files"]) != expected:
        raise ValueError("M3 manifest file set does not match schema")
    result = FactResult.empty(manifest)
    for filename, digest in manifest["files"].items():
        if hashlib.sha256((directory / filename).read_bytes()).hexdigest() != digest:
            raise ValueError(f"M3 checksum mismatch: {filename}")
    for name, columns in SCHEMAS.items():
        for line in (directory / f"{name}.facts").read_text().splitlines():
            cells = line.split("\t")
            if len(cells) != len(columns):
                raise ValueError(f"Wrong field count in {name}")
            result.add(name, *(int(cell) if ty == "u" else unescape(cell)
                               for cell, (_, ty) in zip(cells, columns)))
        if len(result.rows[name]) != manifest["counts"][name]:
            raise ValueError(f"M3 count mismatch: {name}")
    result.validate()
    return result
