# BPA 基础实现

当前实现 M1：ELF 加载、基础信息、符号、导入与依赖、重定位、PLT 和虚拟内存读取。

加载器使用与本机 BPA-X 一致的 CLE 9.2.173，设置 `auto_load_libs=False`，执行 CLE 支持的重定位，不加载依赖库的真实代码。尚未构建 CFG 或生成 VEX facts。

## 运行

```bash
uv sync --locked
bash tests/fixtures/build.sh
PYTHONPATH=src uv run python -m bpa tests/fixtures/binaries/test_64
```

将中间结果保存为 JSON：

```bash
PYTHONPATH=src uv run python -m bpa tests/fixtures/binaries/test_64 \
  -o outputs/test_64/m1/binary.json
```

读取真实 bzip2 样本：

```bash
PYTHONPATH=src uv run --locked python -m bpa \
  tests/fixtures/binaries/bzip2/x64/bzip2_64_O2 \
  -o outputs/bzip2_64_O2/m1/binary.json
```

`binary.json` 使用 schema 2：

| 信息 | 字段 |
| --- | --- |
| 输入身份 | `path`、`sha256`、`file_size` |
| 格式和架构 | `elf_type`、`machine`、`arch`、`bits`、`endianness` |
| 地址转换 | `entry`、`mapped_entry`、`linked_base`、`mapped_base`、`load_bias` |
| 加载段及节区 | `segments`、`sections`，包含文件偏移、地址、大小和标志 |
| 区域 | `executable_regions`、`global_regions` |
| 符号 | `symbols`：名称、大小、类型、导入/导出/弱符号标志、原始/映射地址 |
| 链接信息 | `dependencies`、`imports`、`plt`、`relocations` |
| 加载策略 | `loader_backend`、`loader_version`、`auto_load_libs` |

地址在 JSON 中保存为整数。`address_space: elf-va` 表示段、节区、区域及 `entry` 使用原始 ELF 虚拟地址；字段名包含 `mapped` 的地址使用 CLE 映射地址。对主 ELF 有 `mapped_address = elf_address + load_bias`。所有区域采用左闭右开区间。

对于 PIE，CLE 默认选择映射基址，也可通过 `--mapped-base 0x600000` 指定；该参数仅接受 ET_DYN。只支持带 PT_LOAD 的 ET_EXEC/ET_DYN，ET_REL 不属于本阶段的可执行文件加载范围。

未定义、绝对值或 TLS 符号不伪装成普通映射地址。`imports.target_is_extern` 和 `relocations.target_is_extern` 标记 CLE 分配的外部占位地址，它不是已加载库函数的真实地址；未解决的弱导入可能没有目标。重定位列表反映 CLE 识别的记录，不代表任意未知 ELF 重定位均被支持。符号缺失不会因为缺少 `.symtab` 或 DWARF 而拒绝加载。

区域范围与本机 BPA-X 的提取口径保持对应：可执行节区（无节区时回退到可执行 PT_LOAD），以及 `.data*`、`.bss*`、`.rodata*` 全局区域。它们不是 M4 的对象内存块。

## 模块接口

```python
from bpa.loader import load_elf, open_elf
from bpa.model import BinaryInfo

info = load_elf("tests/fixtures/binaries/test_64")
print(info.machine, info.bits, hex(info.entry))
document = info.to_dict()
restored = BinaryInfo.from_dict(document)

loaded = open_elf("tests/fixtures/binaries/test_64")
address = loaded.to_mapped(loaded.info.entry)
instruction_bytes = loaded.read_memory(address, 16)
```

- `src/bpa/loader/elf.py`：元信息检查与 CLE 加载；`load_elf()` 返回可序列化模型，`open_elf()` 还提供内存读取及主 ELF 地址转换。文件读取失败抛出 `OSError`，解析/加载失败抛出 `ELFLoadError`，非法内存读取抛出 `ValueError`。
- `src/bpa/model/binary.py`：独立数据模型，不依赖 pyelftools、CLE 或 angr，支持 JSON 字典往返。
- `src/bpa/__main__.py`：命令行输入及 JSON 输出。

`read_memory()` 读取重定位后的映射内存，包含 BSS 初始零值；它不会执行程序，也不会产生运行后的全局变量值。转换 `to_elf()` 只适用于主 ELF，不能用于外部占位地址。内存本身不嵌入 JSON；后续阶段需要字节时重新打开同一个 SHA256 的 ELF，并使用记录的加载策略和映射基址。旧 schema 1 输出需要重新生成。

## 基本验证

固定测试集使用 `tests/fixtures/binaries/`；二进制、外部样本软链接及生成的 `manifest.json` 不纳入 Git。首次使用或需要重建时执行 `bash tests/fixtures/build.sh`，日常测试不重编译。源码、GCC 编译选项和清单说明见 [tests/README.md](tests/README.md)。

```bash
PYTHONPATH=src uv run python -m unittest discover -s tests -v
```

M1 阶段已完成。实现过程、产物契约、验证记录及复现命令统一整理在 [docs/M1.md](docs/M1.md)。历史运行产物已清理，需要时可重新生成。
