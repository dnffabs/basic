# BPA 基础实现

当前实现 M1 和 M2：M1 负责 ELF 加载、基础信息、符号、导入与依赖、重定位、PLT 和虚拟内存读取；M2 在 M1 的 `BinaryInfo` 上识别函数并构建初始控制流图。

加载器使用与本机 BPA-X 一致的 CLE 9.2.173，设置 `auto_load_libs=False`，执行 CLE 支持的重定位，不加载依赖库的真实代码。M2 使用 angr 9.2.173 的 `CFGFast` 恢复函数、基本块、机器指令和初始边。尚未生成 VEX facts、对象内存块或指针分析结果。

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

M2 的 `-o` 是任务目录，一次生成 M1 输入记录和两个 M2 产物：

```bash
PYTHONPATH=src uv run --locked python -m bpa \
  tests/fixtures/binaries/test_64 --stage m2 -o outputs/test_64
```

复用已有 M1 产物时不会重跑 M1，但仍会校验输入 ELF 的 SHA256 和加载契约：

```bash
PYTHONPATH=src uv run --locked python -m bpa \
  tests/fixtures/binaries/test_64 --stage m2 \
  --m1 outputs/test_64/m1/binary.json -o outputs/test_64
```

`--stage` 默认为 `m1`，此时 `-o` 仍表示单个 JSON 文件；`--m1` 只能与 `--stage m2` 一起使用。

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

## M2 产物与约定

M2 产物写入任务目录：

```text
outputs/<样本名>/
├── m1/binary.json
└── m2/
    ├── functions.json
    └── cfg.json
```

两个 M2 文件使用 schema 1 和 `address_space: elf-va`，绑定 ELF 的 `binary_sha256`、架构/位宽、`backend_version` 与 CFGFast 选项。`functions.json` 记录经 BPA-X 口径过滤后的用户函数：`sub_*` 伪函数先并入前一个函数，PLT、编译器内置函数和 `.text` 外函数不导出；字段包括入口、名称、来源（`elf-symbol`/`cfgfast`）、符号结束地址、归属块、恢复代码区间及 AT 证据。`cfg.json` 仍记录 CFGFast 恢复的全部基本块与机器指令、边、逐块转移、未解析间接转移、诊断和统计。

主要约定：

- 函数代码范围只来自恢复并归属的块，不假定函数连续，也不用下一个函数入口推算边界；归属不明的块保留在图中并在 `diagnostics` 记录。
- `fake_return`/`assumed-return` 只是调用续点假设；`return`/`cfgfast-return` 是 `CFGFast` 推断，二者都不是已完成的过程间指针求解。
- 间接目标恢复时保留来源（含跳转表）；未恢复时保留 `unresolved`，未知的 `UnresolvableCallTarget` 占位节点不导出为真实目标。完整间接调用目标求解不属于 M2。
- AT 候选来自非直接 CALL/JMP 指令的立即数、可恢复的 LEA 地址和全局初始机器字，只保留命中已恢复函数入口的证据；候选不等同于入口可达或完整指针分析。
- 函数清单按 BPA-X 的用户函数口径导出：`sub_*` 并入前一个函数，PLT、编译器内置函数和 `.text` 外函数被排除；代码范围结束地址对齐到下一个非 `sub_*` 函数入口。`cfg.json` 的块/边统计仍包含这些代码，失去函数所有者的块保留在图中并在 `diagnostics` 记录。
- 当前只在两个固定小样本和 6 个 bzip2 样本上验证过。函数、基本块和边均与 BPA-X 的 CFGFast facts/预处理结果逐项一致（边对照排除 M2 独有的 `fake_return` 假设边）；尚未对大型程序、PIE 或 stripped 样本做验收。

详细字段、边类型和测试结果见 [docs/M2.md](docs/M2.md)。

## 模块接口

```python
from bpa.loader import load_elf, open_elf
from bpa.cfg import build_cfg
from bpa.model import BinaryInfo

info = load_elf("tests/fixtures/binaries/test_64")
print(info.machine, info.bits, hex(info.entry))
document = info.to_dict()
restored = BinaryInfo.from_dict(document)

loaded = open_elf("tests/fixtures/binaries/test_64")
address = loaded.to_mapped(loaded.info.entry)
instruction_bytes = loaded.read_memory(address, 16)

result = build_cfg(info)
functions = result.functions_document()
cfg = result.cfg_document()
```

- `src/bpa/loader/elf.py`：元信息检查与 CLE 加载；`load_elf()` 返回可序列化模型，`open_elf()` 还提供内存读取及主 ELF 地址转换。文件读取失败抛出 `OSError`，解析/加载失败抛出 `ELFLoadError`，非法内存读取抛出 `ValueError`。
- `src/bpa/model/binary.py`：独立数据模型，不依赖 pyelftools、CLE 或 angr，支持 JSON 字典往返。
- `src/bpa/cfg/builder.py`：`build_cfg(info)` 校验 M1 契约、重建私有 angr 项目并恢复函数/块/边/转移；失败抛出 `CFGError`。
- `src/bpa/model/cfg.py`：M2 独立数据模型及 `functions.json`/`cfg.json` 文档生成。
- `src/bpa/pipeline.py`：`run_m2(binary, output, m1_path=None, mapped_base=None)` 编排 M1→M2 并写入任务目录。
- `src/bpa/artifacts.py`：原子 JSON 写入与输入 ELF 覆盖保护。
- `src/bpa/__main__.py`：`m1`/`m2` 命令行入口及 JSON 输出。

`read_memory()` 读取重定位后的映射内存，包含 BSS 初始零值；它不会执行程序，也不会产生运行后的全局变量值。转换 `to_elf()` 只适用于主 ELF，不能用于外部占位地址。内存本身不嵌入 JSON；后续阶段需要字节时重新打开同一个 SHA256 的 ELF，并使用记录的加载策略和映射基址。旧 schema 1 输出需要重新生成。

## 基本验证

固定测试集使用 `tests/fixtures/binaries/`；二进制、外部样本软链接及生成的 `manifest.json` 不纳入 Git。首次使用或需要重建时执行 `bash tests/fixtures/build.sh`，日常测试不重编译。源码、GCC 编译选项和清单说明见 [tests/README.md](tests/README.md)。

```bash
PYTHONPATH=src uv run --locked python -m unittest discover -s tests -v
```

目前共 20 项自动测试：M1 原有 11 项，M2 9 项。M2 测试只使用现有 `test_64`/`test_32`，覆盖函数与代码范围、BPA-X 用户函数过滤、图与指令完整性、独立线性反汇编调用清单、未解析间接调用与续点、AT 证据、M1 身份校验、导出确定性及 CLI 复用 M1。6 个 bzip2 样本的函数、基本块和边已与 BPA-X 逐项对照一致；对照脚本见 [tests/compare_m2_bpax.py](tests/compare_m2_bpax.py)。

M1 与 M2 均已完成本地实现和固定样本测试。实现过程、产物契约、验证记录及复现命令分别整理在 [docs/M1.md](docs/M1.md) 和 [docs/M2.md](docs/M2.md)。M2 的 bzip2 对照只覆盖函数入口/名称和导出代码范围；尚未在大型程序、PIE 或 stripped 样本上验收。历史运行产物已清理，需要时可重新生成。
