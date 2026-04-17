# C/C++ 常规风险扫描工具

轻量级 C/C++ 静态规则扫描器，面向 `.h/.hpp/.hh/.hxx/.cpp/.cc/.cxx` 文件，按函数实现做独立检查。

当前聚焦三类风险：
- 空指针访问风险
- 数组越界访问风险
- 除 0 风险（包含近零除数风险）

详细设计见 [PROJECT_DOC.md](./PROJECT_DOC.md)。

## 快速使用
### CLI
```bash
python cpp_risk_scanner.py <文件或目录> [更多路径...]
```

常用参数：
```bash
python cpp_risk_scanner.py ./sample --json
python cpp_risk_scanner.py ./sample --declared-only
python cpp_risk_scanner.py ./sample --scan-all
```

- `--declared-only`：仅扫描与头文件声明名匹配的函数定义。
- `--scan-all`：兼容旧参数，当前默认即扫描全部函数定义。
- `--json`：输出结构化 JSON 报告。

### GUI
```bash
python cpp_risk_scanner_gui.py
```

GUI 特点：
- 上半区为结果输出区，下半区为操作区（选择目录 + 开始扫描）。
- GUI 直接调用 `cpp_risk_scanner.scan()` 并复用 `print_text_report()`，与命令行规则和输出格式保持一致。

## 输出格式
文本输出固定三段：
- `====空指针访问风险====`
- `====数组越界访问风险====`
- `====除0风险====`

每段包含总数和逐条明细（文件、接口、行号，空指针场景额外含变量名）。

JSON 输出字段：
- `scan_mode` / `scan_mode_zh`
- `scanned_files`
- `scanned_function_count`
- `interface_function_name_count`
- `summary` / `summary_zh`
- `findings`

## 适用边界
- 本工具为启发式规则引擎，不是完整编译器语义分析。
- 目标是快速发现高概率风险点，结果应结合人工复核。
- 对跨函数、跨文件、宏展开后的深层语义不做完整求解。

## 回归自测
已内置一组规则回归用例与对比脚本：
- 用例文件：`sample/regression_cases.cpp`
- 自测脚本：`selfcheck_regression.py`

运行方式：
```bash
python selfcheck_regression.py
```

脚本会按函数维度对比“预期风险类别集合”和“扫描实际结果”，输出 `PASS/FAIL`。
