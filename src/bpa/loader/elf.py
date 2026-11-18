"""ELF metadata and CLE loading, without CFG or VEX fact generation."""

import hashlib
from io import BytesIO
from pathlib import Path

import cle
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from bpa.model import AddressRange, BinaryInfo, Import, PltEntry, Relocation, Section, Segment, Symbol


class ELFLoadError(ValueError):
    """The input cannot be parsed or loaded as a supported ELF."""


class LoadedBinary:
    """Loader observations and relocated virtual memory behind a small interface.

    Metadata uses original ELF VAs unless a field explicitly says mapped.
    read_memory() uses mapped VAs, including synthetic CLE extern addresses.
    The backend is private; callers exchange BinaryInfo or binary.json.
    """

    def __init__(self, info: BinaryInfo, loader):
        self.info = info
        self._loader = loader

    def to_mapped(self, elf_address: int) -> int:
        return elf_address + self.info.load_bias

    def to_elf(self, mapped_address: int) -> int:
        """Convert a main-object address; do not use this for extern targets."""
        return mapped_address - self.info.load_bias

    def read_memory(self, mapped_address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("Memory read size must be nonnegative")
        if size == 0:
            return b""
        try:
            data = self._loader.memory.load(mapped_address, size)
        except KeyError as error:
            raise ValueError(f"Unmapped memory read at {mapped_address:#x}, size={size}") from error
        if len(data) != size:
            raise ValueError(f"Incomplete memory read at {mapped_address:#x}, size={size}")
        return data


def _metadata(data: bytes):
    elf = ELFFile(BytesIO(data))
    segments = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        offset, file_size, memory_size = segment["p_offset"], segment["p_filesz"], segment["p_memsz"]
        if file_size > memory_size or (file_size and offset + file_size > len(data)):
            raise ELFLoadError("Invalid PT_LOAD file or memory size")
        flags = segment["p_flags"]
        segments.append(Segment(offset, segment["p_vaddr"], file_size, memory_size,
                                bool(flags & 4), bool(flags & 2), bool(flags & 1)))
    sections = []
    for section in elf.iter_sections():
        # NOBITS occupies memory only; NULL may carry extended ELF counts.
        if section["sh_type"] not in ("SHT_NOBITS", "SHT_NULL") and section["sh_size"]:
            if section["sh_offset"] + section["sh_size"] > len(data):
                raise ELFLoadError(f"Section {section.name!r} extends beyond the ELF file")
        flags = section["sh_flags"]
        sections.append(Section(section.name, str(section["sh_type"]), section["sh_addr"],
                                section["sh_offset"], section["sh_size"], bool(flags & 2),
                                bool(flags & 1), bool(flags & 4)))
    if elf["e_type"] not in ("ET_EXEC", "ET_DYN"):
        raise ELFLoadError("M1 loading supports ET_EXEC and ET_DYN ELF files")
    if not segments:
        raise ELFLoadError("ELF has no PT_LOAD mappings")
    return elf, tuple(segments), tuple(sections)


def open_elf(path: str | Path, *, mapped_base: int | None = None) -> LoadedBinary:
    """Load the main ELF with BPA-X's CLE policy: auto_load_libs=False.

    CLE performs supported relocations and supplies zero-initialized BSS.
    Unloaded imports may resolve to synthetic externs, not real library code.
    mapped_base may override the default for position-independent inputs.
    """
    binary = Path(path).resolve()
    data = binary.read_bytes()
    try:
        elf, segments, sections = _metadata(data)
        if mapped_base is not None and (mapped_base < 0 or elf["e_type"] != "ET_DYN"):
            raise ELFLoadError("mapped_base must be nonnegative and is only supported for ET_DYN")
        options = {} if mapped_base is None else {"base_addr": mapped_base}
        # Parse and load the same byte snapshot so the hash describes both.
        loader = cle.Loader(BytesIO(data), auto_load_libs=False, main_opts=options)
        obj = loader.main_object
        symbols = []
        for symbol in obj.symbols:
            if not symbol.name:
                continue
            # Undefined, absolute and TLS values are not ordinary image VAs.
            section_index = symbol.section
            addressable = (not symbol.is_import and section_index is not None
                           and 0 <= section_index < len(sections) and sections[section_index].allocated
                           and symbol.type.name != "TYPE_TLS_OBJECT")
            symbols.append(Symbol(
                name=symbol.name, type=symbol.type.name, size=symbol.size,
                is_function=symbol.is_function, is_import=symbol.is_import,
                is_export=symbol.is_export, is_weak=symbol.is_weak,
                elf_address=symbol.linked_addr if addressable else None,
                mapped_address=symbol.rebased_addr if addressable else None,
            ))
        symbols.sort(key=lambda s: (s.name, s.elf_address is None, s.elf_address or 0, s.type))
        imports = []
        for name, relocation in sorted(obj.imports.items()):
            target = relocation.resolvedby
            imports.append(Import(
                name=name, is_weak=relocation.symbol.is_weak,
                slot_elf_address=relocation.linked_addr, slot_mapped_address=relocation.rebased_addr,
                resolved=relocation.resolved,
                target_mapped_address=target.rebased_addr if target is not None else None,
                target_is_extern=bool(target is not None and target.is_extern),
            ))
        relocations = []
        for relocation in obj.relocs:
            target = relocation.resolvedby
            relocations.append(Relocation(
                type=type(relocation).__name__, elf_address=relocation.linked_addr,
                mapped_address=relocation.rebased_addr,
                symbol=relocation.symbol.name if relocation.symbol is not None else None,
                resolved=relocation.resolved,
                target_mapped_address=target.rebased_addr if target is not None else None,
                target_is_extern=bool(target is not None and target.is_extern),
            ))
        plt = tuple(PltEntry(name, address - (obj.mapped_base - obj.linked_base), address)
                    for name, address in sorted(obj.plt.items()))
        executable = tuple(AddressRange(s.name, s.virtual_address, s.virtual_address + s.size)
                           for s in sections if s.executable and s.size)
        if not executable:
            executable = tuple(AddressRange("PT_LOAD", s.virtual_address, s.virtual_address + s.memory_size)
                               for s in segments if s.executable and s.memory_size)
        globals_ = tuple(AddressRange(s.name, s.virtual_address, s.virtual_address + s.size)
                         for s in sections if s.allocated and s.size
                         and s.name.startswith((".data", ".bss", ".rodata")))
        info = BinaryInfo(
            path=str(binary), sha256=hashlib.sha256(data).hexdigest(), file_size=len(data),
            elf_type=str(elf["e_type"]), machine=str(elf["e_machine"]), bits=elf.elfclass,
            endianness="little" if elf.little_endian else "big", entry=elf["e_entry"],
            segments=segments, sections=sections, linked_base=obj.linked_base,
            mapped_base=obj.mapped_base, mapped_entry=obj.entry, arch=obj.arch.name,
            loader_backend="cle", loader_version=cle.__version__, auto_load_libs=False,
            dependencies=tuple(obj.deps), symbols=tuple(symbols), imports=tuple(imports),
            relocations=tuple(relocations), plt=plt, executable_regions=executable,
            global_regions=globals_,
        )
        return LoadedBinary(info, loader)
    except (ELFError, cle.CLEError) as error:
        raise ELFLoadError(f"Invalid or unsupported ELF: {error}") from error


def load_elf(path: str | Path, *, mapped_base: int | None = None) -> BinaryInfo:
    """Return serializable observations; use open_elf() for memory access."""
    return open_elf(path, mapped_base=mapped_base).info
