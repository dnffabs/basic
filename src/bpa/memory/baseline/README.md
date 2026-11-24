# BPA-X 分块基线

本目录随项目保存 BPA-X 提交 `0fb0a5152074495e8227f936aa694a3c83e3884e` 中默认分块所需的源码。授权见 [LICENSE.txt](LICENSE.txt)。

- `rules/` 对应原仓库的 `logic/souffle/`。保留分块规则、公共类型、寄存器定义和所需预处理规则。
- `helpers/` 中三个脚本来自原仓库的 `utils/`。两处 objdump 调用启用了退出码检查，使反汇编失败时 M4 报错。
- 调用顺序、M1–M3 输入适配和结果发布由上一级 `partition.py` 负责。测试中的独立参考运行从用户指定的原仓库重新提取 facts。
