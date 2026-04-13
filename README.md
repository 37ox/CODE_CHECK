# C/C++ 风险扫描工具

一个面向 `.h/.cpp` 项目的轻量级静态扫描器。

用于报告函数实现中的潜在风险：
- `null_pointer_risk`（指针判空风险）
- `out_of_bounds_risk`（访问越界风险）
- `divide_by_zero_risk`（除 0 风险）
- `small_denominator_risk`（浮点除数近零风险）

## 快速开始

```bash
python cpp_risk_scanner.py <文件或目录> [更多路径...]
```

GUI 启动：

```bash
python cpp_risk_scanner_gui.py
```

GUI 说明：
- 上区为结果输出区。
- 下区为操作区（高度较小），包含“选择文件夹”和“开始接口提取校验”两个按钮。
- 扫描逻辑与命令行保持一致，仍基于当前启发式规则。

示例：

```bash
python cpp_risk_scanner.py ./src
python cpp_risk_scanner.py ./include ./src --json
python cpp_risk_scanner.py ./src --declared-only
```

## 函数筛选方式

- 默认模式：
  - 扫描输入路径中发现到的全部函数定义（文件彼此独立，不依赖头文件声明）。
- `--declared-only` 模式：
  - 先收集头文件（`.h/.hpp/.hh/.hxx`）中的函数声明名。
  - 只扫描与这些声明名匹配的函数定义。
- `--scan-all`：
  - 兼容旧参数，当前版本默认已是扫描全部函数定义。

## 输出说明

文本模式输出：
- 扫描模式
- 扫描文件数量
- 扫描函数数量
- 风险汇总
- 带行号的风险明细

JSON 模式（`--json`）输出字段：
- `scan_mode`
- `scanned_files`
- `scanned_function_count`
- `interface_function_name_count`
- `summary`
- `findings`

## 规则要点

- 指针判空：
  - 按行检查每次解引用，不再只看第一次命中。
  - 识别 `if (p) { ... }` 的作用域，分支外使用不会被误判为“已判空”。
  - 若指针被重新赋值（特别是赋值为 `NULL/nullptr/0`），会使之前的判空保护失效，后续需重新保护。
- 越界检查：
  - 对变量索引同时检查上界和下界（如 `i < size` 且 `i >= 0`），避免只看上界导致漏检负索引。
- 除法检查：
  - 继续检查显式除 0 或缺少非零保护。
  - 对浮点除数补充近零检测：仅 `!= 0` 但缺少 `abs(den) > eps` 等保护时，报告 `small_denominator_risk`。

## 说明

- 本工具使用启发式规则，不是完整的 C++ 语法解析器。
- 目标是快速发现可疑代码，可能存在误报或漏报。
- 建议流程：
  1. 运行扫描器
  2. 人工复核结果
  3. 按项目特点补充规则
