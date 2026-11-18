# 固定二进制测试集

Git 只保存源码、编译脚本、测试代码和说明；`fixtures/binaries/`（含软链接）、生成的 `fixtures/manifest.json` 和 `outputs/` 均被忽略。首次检出后先执行下面的编译命令，生成本地测试输入。

```text
tests/
├── test_loader.py
├── test_loader_extended.py
├── test_cfg.py
├── compare_m1_bpax.py
└── fixtures/
    ├── sources/test.c  # 唯一的 C 测试程序
    ├── binaries/
    │   ├── test_64     # 64 位 ELF
    │   └── test_32     # 32 位 ELF
    ├── build.sh        # 编译入口
    ├── build.py        # 本地 GCC 编译与清单生成
    └── manifest.json   # 实际编译器、命令、哈希、基础预期
```

## 编译

在项目根目录执行：

```bash
bash tests/fixtures/build.sh
```

默认直接使用 PATH 中的 `gcc`，也可通过 `CC` 或 `--cc` 指定 GCC 路径。不固定为论文使用的 GCC 9.2，不下载编译器。编译 32 位样本需要本地 GCC 的 multilib 与 32 位 C 库支持。

基础编译选项沿用本地 BPA-X 示例，并显式指定 64 位：

```text
AMD64: -m64 -g -O0 -mno-avx -mno-sse -fno-pie -fno-stack-protector -no-pie
X86:   -m32 -march=i386 -g -O0 -mno-avx -mno-sse -fno-pie -fno-stack-protector -no-pie
```

只使用一个 `test.c`，分别生成 `test_64` 和 `test_32`，两个版本都带调试信息、采用 `-O0` 和非 PIE。程序包含全局初始化数据、BSS、只读字符串、函数指针表、参数传递、栈/堆结构体和间接调用，供后续阶段复用。

两个程序的正常返回值均为 0，预期输出均为：

```text
bpa-test: 13 5 8 9
```

## 测试

```bash
PYTHONPATH=src uv run --locked python -m unittest discover -s tests -v
```

日常测试直接读取 `binaries/`，不会自动调用 GCC。只有明确修改或重建测试集时才运行 `build.sh`；重建会更新二进制和清单。清单保存源码与二进制的 SHA256，以识别样本变化；记录的是本次实际编译结果，不保证更换编译器或系统后仍得到相同字节。

目前共有 19 项自动测试：M1 原有 11 项，M2 新增 8 项。M1 覆盖基础 ELF 读取、32/64 位信息、样本完整性、原生行为、命令行输出，以及符号/导入/依赖/PLT、重定位后的导入槽、函数指针表、全局初始内容、BSS 零填充、JSON 往返；两项回归覆盖输出硬链接/符号链接保护和节区文件范围检查。

M2 的 `test_cfg.py` 直接复用 `test_64`/`test_32`，没有新增 C 程序或重新编译，覆盖：

- 函数入口、符号结束地址和恢复代码范围；
- 基本块、指令连续性与边/归属一致性；
- 按符号范围独立线性反汇编核对调用清单（`main` 为 7 个直接调用）；
- `apply`/`invoke` 的未解析间接调用及调用续点；
- AT 证据及“直接调用不算 AT”的约定；
- M1 身份、schema、入口和位宽校验；
- JSON 导出可序列化且确定；
- CLI 复用已有 M1，生成两个 M2 产物且不修改 M1 文件。

M2 产物与命令见 [docs/M2.md](../docs/M2.md)。

`binaries/bzip2` 是指向 `/home/qc/Desktop/common/binaries/bzip2` 的软链接，其中包含 32/64 位、O0/O1/O2 共 6 个真实样本；由外部目录维护，不由 build.sh 重建。可按 README 的命令分别导出 M1 结果。已完成的 M1 验证记录见 [docs/M1.md](../docs/M1.md)；历史运行产物已清理。M2 目前只在两个固定样本上验证，尚未在这些 bzip2 样本上运行或验收，也未运行完整 BPA-X 指针分析。

该软链接不提交 Git，新检出目录需要使用公共样本时创建：

```bash
ln -s /home/qc/Desktop/common/binaries/bzip2 tests/fixtures/binaries/bzip2
```

后续阶段可以复用这些 ELF，但各间接调用点的静态预期目标清单需要在实现相应阶段时补充。

## 随机 bzip2 产物对照

```bash
PYTHONPATH=src uv run --locked python tests/compare_m1_bpax.py
```

从 bzip2 链接目录随机选择一个样本，重新生成本项目的 `binary.json`、参考 angr.Project 的独立加载导出，以及 BPA-X 原有脚本的 text/PLT/global 区域和原始全局数据 facts。产物保存在 `outputs/m1_compare/<样本名>/`，`comparison.json` 列出逐项结果，差异导致非零退出。

指定样本可复现同一比较：

```bash
PYTHONPATH=src uv run --locked python tests/compare_m1_bpax.py \
  --binary tests/fixtures/binaries/bzip2/x86/bzip2_32_O1
```

默认参考源码为 `/home/qc/Desktop/rebuild/bpa_x`，参考解释器为已有的 `/home/qc/Desktop/binwork/mywork/BPA/.venv/bin/python`；可以通过 `--bpax-root` 和 `--reference-python` 修改。本脚本只比较 M1 对应信息，不运行 CFG 或最终指针分析。
