"""Serializable ELF and loader observations shared with subsequent stages."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Segment:
    """A PT_LOAD mapping. Addresses are ELF virtual addresses."""

    offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    readable: bool
    writable: bool
    executable: bool


@dataclass(frozen=True)
class Section:
    name: str
    type: str
    virtual_address: int
    offset: int
    size: int
    allocated: bool
    writable: bool
    executable: bool


@dataclass(frozen=True)
class Symbol:
    name: str
    type: str
    size: int
    is_function: bool
    is_import: bool
    is_export: bool
    is_weak: bool
    elf_address: int | None
    mapped_address: int | None


@dataclass(frozen=True)
class Import:
    name: str
    is_weak: bool
    slot_elf_address: int
    slot_mapped_address: int
    resolved: bool
    target_mapped_address: int | None
    target_is_extern: bool


@dataclass(frozen=True)
class Relocation:
    type: str
    elf_address: int
    mapped_address: int
    symbol: str | None
    resolved: bool
    target_mapped_address: int | None
    target_is_extern: bool


@dataclass(frozen=True)
class PltEntry:
    name: str
    elf_address: int
    mapped_address: int


@dataclass(frozen=True)
class AddressRange:
    name: str
    start: int
    end: int


@dataclass(frozen=True)
class BinaryInfo:
    path: str
    sha256: str
    file_size: int
    elf_type: str
    machine: str
    bits: int
    endianness: str
    entry: int
    segments: tuple[Segment, ...]
    sections: tuple[Section, ...]
    linked_base: int
    mapped_base: int
    mapped_entry: int
    arch: str
    loader_backend: str
    loader_version: str
    auto_load_libs: bool
    dependencies: tuple[str, ...]
    symbols: tuple[Symbol, ...]
    imports: tuple[Import, ...]
    relocations: tuple[Relocation, ...]
    plt: tuple[PltEntry, ...]
    executable_regions: tuple[AddressRange, ...]
    global_regions: tuple[AddressRange, ...]
    schema_version: int = 2
    address_space: str = "elf-va"

    @property
    def load_bias(self) -> int:
        return self.mapped_base - self.linked_base

    def to_dict(self) -> dict:
        result = asdict(self)
        result["load_bias"] = self.load_bias
        return result

    @classmethod
    def from_dict(cls, document: dict) -> "BinaryInfo":
        """Restore schema 2 observations without importing CLE or pyelftools."""
        if document.get("schema_version") != 2 or document.get("address_space") != "elf-va":
            raise ValueError("Expected binary.json schema_version=2, address_space=elf-va")
        data = dict(document)
        bias = data.pop("load_bias")
        for field, record in (("segments", Segment), ("sections", Section),
                              ("symbols", Symbol), ("imports", Import),
                              ("relocations", Relocation), ("plt", PltEntry),
                              ("executable_regions", AddressRange), ("global_regions", AddressRange)):
            data[field] = tuple(record(**row) for row in data[field])
        data["dependencies"] = tuple(data["dependencies"])
        info = cls(**data)
        if bias != info.load_bias:
            raise ValueError("Inconsistent load_bias in binary.json")
        return info
