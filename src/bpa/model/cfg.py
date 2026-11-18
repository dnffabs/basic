"""M2 records use ELF VAs and contain no angr objects."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    mnemonic: str
    operands: str


@dataclass(frozen=True)
class BasicBlock:
    address: int
    size: int
    function_entries: tuple[int, ...]
    instructions: tuple[Instruction, ...]
    jumpkind: str


@dataclass(frozen=True)
class Edge:
    source: int
    target: int | None
    kind: str
    jumpkind: str
    provenance: str
    external_symbol: str | None = None


@dataclass(frozen=True)
class Transfer:
    address: int
    block: int
    function_entries: tuple[int, ...]
    kind: str
    indirect: bool
    direct_target: int | None
    targets: tuple[int, ...]
    external_targets: tuple[str, ...]
    continuation: int | None
    status: str
    target_source: str


@dataclass(frozen=True)
class ATEvidence:
    source: str
    address: int


@dataclass(frozen=True)
class Function:
    entry: int
    name: str
    aliases: tuple[str, ...]
    source: str
    symbol_end: int | None
    blocks: tuple[int, ...]
    code_ranges: tuple[tuple[int, int], ...]
    is_plt: bool
    address_taken: bool
    at_evidence: tuple[ATEvidence, ...]


@dataclass(frozen=True)
class CFGResult:
    binary_path: str
    binary_sha256: str
    arch: str
    bits: int
    entry: int
    backend_version: str
    options: dict
    functions: tuple[Function, ...]
    blocks: tuple[BasicBlock, ...]
    edges: tuple[Edge, ...]
    transfers: tuple[Transfer, ...]
    diagnostics: tuple[str, ...]

    def _metadata(self) -> dict:
        return dict(schema_version=1, stage="M2", address_space="elf-va",
                    binary_path=self.binary_path, binary_sha256=self.binary_sha256,
                    arch=self.arch, bits=self.bits, entry=self.entry,
                    backend="angr.CFGFast", backend_version=self.backend_version,
                    options=self.options)

    def functions_document(self) -> dict:
        return dict(self._metadata(), kind="functions",
                    functions=[asdict(f) for f in self.functions])

    def cfg_document(self) -> dict:
        return dict(self._metadata(), kind="cfg",
                    blocks=[asdict(b) for b in self.blocks],
                    edges=[asdict(e) for e in self.edges],
                    transfers=[asdict(t) for t in self.transfers],
                    unresolved_transfers=[t.address for t in self.transfers if t.status == "unresolved"],
                    diagnostics=list(self.diagnostics),
                    statistics=dict(functions=len(self.functions), blocks=len(self.blocks),
                                    edges=len(self.edges), calls=sum(t.kind == "call" for t in self.transfers),
                                    indirect_calls=sum(t.kind == "call" and t.indirect for t in self.transfers),
                                    unresolved_indirect_calls=sum(t.kind == "call" and t.status == "unresolved" for t in self.transfers),
                                    at_functions=sum(f.address_taken for f in self.functions)))
