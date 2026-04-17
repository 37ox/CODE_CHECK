#!/usr/bin/env python3
"""
Lightweight C/C++ heuristic risk scanner.

Scans .h/.hpp/.hh/.hxx and .cpp/.cc/.cxx files, then reports potential:
1) null-pointer dereference risk
2) out-of-bounds index risk
3) divide-by-zero risk
4) small-denominator risk (floating-point near-zero division)

Design goal: fast heuristic checks with clear line-level output.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple

HEADER_EXTS = {".h", ".hpp", ".hh", ".hxx"}
SOURCE_EXTS = {".cpp", ".cc", ".cxx"}
TARGET_EXTS = HEADER_EXTS | SOURCE_EXTS

CPP_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "class",
    "struct",
    "enum",
    "typedef",
    "using",
    "namespace",
    "template",
    "operator",
    "sizeof",
    "alignof",
    "new",
    "delete",
    "throw",
    "try",
    "do",
    "else",
    "case",
    "default",
    "goto",
    "break",
    "continue",
    "const",
    "constexpr",
    "volatile",
    "static",
    "extern",
    "inline",
    "virtual",
    "friend",
    "public",
    "private",
    "protected",
    "final",
    "override",
    "void",
    "int",
    "short",
    "long",
    "char",
    "float",
    "double",
    "bool",
    "signed",
    "unsigned",
    "auto",
    "decltype",
    "typename",
    "this",
    "nullptr",
    "true",
    "false",
}

NON_DECL_STMT_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "case",
    "throw",
    "sizeof",
    "delete",
    "new",
}

INDEX_ACCESS_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([^\]\n]+?)\s*\]")
SMALL_DENOMINATOR_EPS = 1e-20
INTEGER_TYPE_RE = re.compile(
    r"\b(?:"
    r"(?:un)?signed(?:\s+(?:int|long|short|char))?"
    r"|short|int|long|char"
    r"|size_t|ssize_t|ptrdiff_t"
    r"|u?int\d*_t"
    r")\b"
)
FULLWIDTH_TRANSLATION = str.maketrans(
    {
        "（": "(",
        "）": ")",
        "！": "!",
        "＝": "=",
        "＜": "<",
        "＞": ">",
        "｜": "|",
        "＆": "&",
        "，": ",",
        "　": " ",
    }
)

RISK_TYPE_ZH = {
    "null_pointer_risk": "空指针风险",
    "out_of_bounds_risk": "数组越界风险",
    "divide_by_zero_risk": "除0风险",
    "small_denominator_risk": "除0风险",
}

SCAN_MODE_ZH = {
    "all_definitions": "全量函数扫描",
    "declared_only": "仅声明接口扫描",
}


@dataclass
class FunctionInfo:
    file: str
    name: str
    base_name: str
    params_text: str
    body: str
    start_line: int


@dataclass
class Finding:
    risk_type: str
    file: str
    line: int
    function: str
    detail: str
    code: str


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    sample = data[:4096]
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return non_text / len(sample) > 0.3


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if is_probably_binary(raw):
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def collect_files(paths: Sequence[str]) -> List[Path]:
    seen: Set[Path] = set()
    output: List[Path] = []

    for raw in paths:
        p = Path(raw)
        if not p.exists():
            continue
        if p.is_file():
            if p.suffix.lower() in TARGET_EXTS:
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    output.append(rp)
            continue

        for f in p.rglob("*"):
            if f.is_file() and f.suffix.lower() in TARGET_EXTS:
                rp = f.resolve()
                if rp not in seen:
                    seen.add(rp)
                    output.append(rp)
    return sorted(output)


def mask_comments(text: str) -> str:
    out: List[str] = []
    i = 0
    n = len(text)
    state = "normal"

    while i < n:
        c = text[i]

        if state == "normal":
            if c == "/" and i + 1 < n and text[i + 1] == "/":
                out.extend([" ", " "])
                i += 2
                state = "line_comment"
                continue
            if c == "/" and i + 1 < n and text[i + 1] == "*":
                out.extend([" ", " "])
                i += 2
                state = "block_comment"
                continue
            if c == '"':
                out.append(c)
                i += 1
                state = "string"
                continue
            if c == "'":
                out.append(c)
                i += 1
                state = "char"
                continue
            out.append(c)
            i += 1
            continue

        if state == "line_comment":
            if c == "\n":
                out.append("\n")
                state = "normal"
            else:
                out.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                out.extend([" ", " "])
                i += 2
                state = "normal"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if c == "\\" and i + 1 < n:
                out.extend([text[i], text[i + 1]])
                i += 2
                continue
            out.append(c)
            i += 1
            if c == '"':
                state = "normal"
            continue

        if state == "char":
            if c == "\\" and i + 1 < n:
                out.extend([text[i], text[i + 1]])
                i += 2
                continue
            out.append(c)
            i += 1
            if c == "'":
                state = "normal"
            continue

    return "".join(out)


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    i = open_index
    n = len(text)
    state = "normal"

    while i < n:
        c = text[i]

        if state == "normal":
            if c == "/" and i + 1 < n and text[i + 1] == "/":
                state = "line_comment"
                i += 2
                continue
            if c == "/" and i + 1 < n and text[i + 1] == "*":
                state = "block_comment"
                i += 2
                continue
            if c == '"':
                state = "string"
                i += 1
                continue
            if c == "'":
                state = "char"
                i += 1
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
            continue

        if state == "line_comment":
            if c == "\n":
                state = "normal"
            i += 1
            continue

        if state == "block_comment":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                state = "normal"
                i += 2
            else:
                i += 1
            continue

        if state == "string":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                state = "normal"
            i += 1
            continue

        if state == "char":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "'":
                state = "normal"
            i += 1
            continue

    return -1


def split_params(params: str) -> List[str]:
    items: List[str] = []
    buf: List[str] = []
    p_depth = 0
    b_depth = 0
    c_depth = 0
    a_depth = 0

    for ch in params:
        if ch == "(":
            p_depth += 1
        elif ch == ")":
            p_depth = max(0, p_depth - 1)
        elif ch == "[":
            b_depth += 1
        elif ch == "]":
            b_depth = max(0, b_depth - 1)
        elif ch == "{":
            c_depth += 1
        elif ch == "}":
            c_depth = max(0, c_depth - 1)
        elif ch == "<":
            a_depth += 1
        elif ch == ">":
            a_depth = max(0, a_depth - 1)

        if ch == "," and p_depth == 0 and b_depth == 0 and c_depth == 0 and a_depth == 0:
            token = "".join(buf).strip()
            if token:
                items.append(token)
            buf = []
        else:
            buf.append(ch)

    token = "".join(buf).strip()
    if token:
        items.append(token)
    return items


def find_previous_non_space(text: str, index: int) -> int:
    i = index
    while i >= 0 and text[i].isspace():
        i -= 1
    return i


def find_matching_open_paren(masked_text: str, close_index: int) -> int:
    depth = 0
    for i in range(close_index, -1, -1):
        c = masked_text[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                return i
    return -1


def extract_pointer_params(params_text: str) -> List[str]:
    pointers: List[str] = []
    for raw in split_params(params_text):
        p = raw.split("=", 1)[0].strip()
        if not p or p == "void" or "..." in p:
            continue
        if "*" not in p:
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", p)
        if not m:
            continue
        name = m.group(1)
        if name not in CPP_KEYWORDS:
            pointers.append(name)
    return pointers


def extract_floating_params(params_text: str) -> Set[str]:
    floating: Set[str] = set()
    for raw in split_params(params_text):
        p = raw.split("=", 1)[0].strip()
        if not p or p == "void" or "..." in p:
            continue
        if not re.search(r"\b(?:float|double|long\s+double)\b", p):
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", p)
        if not m:
            continue
        name = m.group(1)
        if name not in CPP_KEYWORDS:
            floating.add(name)
    return floating


def extract_integer_params(params_text: str) -> Set[str]:
    integers: Set[str] = set()
    for raw in split_params(params_text):
        p = raw.split("=", 1)[0].strip()
        if not p or p == "void" or "..." in p:
            continue
        if "*" in p:
            continue
        if not INTEGER_TYPE_RE.search(p):
            continue
        if re.search(r"\b(?:float|double|long\s+double)\b", p):
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", p)
        if not m:
            continue
        name = m.group(1)
        if name not in CPP_KEYWORDS:
            integers.add(name)
    return integers


def extract_function_definitions(path: Path) -> List[FunctionInfo]:
    text = read_text(path)
    masked = mask_comments(text)
    out: List[FunctionInfo] = []

    i = 0
    n = len(masked)
    while i < n:
        if masked[i] != "{":
            i += 1
            continue

        open_index = i
        before_brace = find_previous_non_space(masked, open_index - 1)
        if before_brace < 0:
            i += 1
            continue

        # Need a parameter list right before "{", otherwise it cannot be a function.
        close_paren = -1
        k = before_brace
        while k >= 0:
            ch = masked[k]
            if ch == ")":
                close_paren = k
                break
            if ch in ";{}":
                break
            k -= 1
        if close_paren < 0:
            i += 1
            continue

        open_paren = find_matching_open_paren(masked, close_paren)
        if open_paren < 0:
            i += 1
            continue

        head_start = max(0, open_paren - 300)
        head = masked[head_start:open_paren]
        m = re.search(r"([A-Za-z_~]\w*(?:::[A-Za-z_~]\w*)*)\s*$", head)
        if not m:
            i += 1
            continue

        name = m.group(1)
        base_name = name.split("::")[-1]
        if base_name in CPP_KEYWORDS:
            i += 1
            continue

        name_start = head_start + m.start(1)
        prev_char_idx = find_previous_non_space(masked, name_start - 1)
        if prev_char_idx >= 0:
            prev = masked[prev_char_idx]
            if prev in {".", ","}:
                i += 1
                continue
            if prev == ">":
                if prev_char_idx > 0 and masked[prev_char_idx - 1] == "-":
                    i += 1
                    continue
            if prev == ":":
                prev2 = find_previous_non_space(masked, prev_char_idx - 1)
                if prev2 < 0 or masked[prev2] != ":":
                    i += 1
                    continue

        boundary = max(
            masked.rfind(";", 0, name_start),
            masked.rfind("}", 0, name_start),
            masked.rfind("{", 0, name_start),
        )
        prefix = masked[boundary + 1 : name_start].strip()
        if re.search(r"\b(if|for|while|switch|catch|return|sizeof|alignof)\b", prefix):
            i += 1
            continue
        assign_like = re.search(r"\b[A-Za-z_]\w*\s*=(?!=)", prefix)
        if assign_like and "operator" not in prefix:
            i += 1
            continue

        close_index = find_matching_brace(text, open_index)
        if close_index < 0:
            i += 1
            continue

        params_text = text[open_paren + 1 : close_paren]
        body = text[open_index + 1 : close_index]
        start_line = line_number(text, name_start)

        out.append(
            FunctionInfo(
                file=str(path),
                name=name,
                base_name=base_name,
                params_text=params_text,
                body=body,
                start_line=start_line,
            )
        )

        i = close_index + 1

    return out


def iter_semicolon_statements(text: str) -> Iterable[str]:
    buf: List[str] = []
    i = 0
    n = len(text)
    state = "normal"

    while i < n:
        c = text[i]
        buf.append(c)

        if state == "normal":
            if c == '"':
                state = "string"
            elif c == "'":
                state = "char"
            elif c == ";":
                stmt = "".join(buf).strip()
                if stmt:
                    yield stmt
                buf = []
        elif state == "string":
            if c == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
            elif c == '"':
                state = "normal"
        elif state == "char":
            if c == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
            elif c == "'":
                state = "normal"

        i += 1


def extract_declared_name(stmt: str) -> str:
    filtered_lines = []
    for line in stmt.splitlines():
        if line.lstrip().startswith("#"):
            continue
        filtered_lines.append(line)
    s = " ".join(" ".join(filtered_lines).split())
    if not s.endswith(";"):
        return ""
    if "(" not in s or ")" not in s:
        return ""
    if re.search(r"\b(typedef|using|namespace|template)\b", s):
        return ""
    if re.search(r"\b(if|for|while|switch|catch)\b", s):
        return ""
    if "operator" in s:
        return ""

    head = s[: s.find("(")].strip()
    if not head or "=" in head:
        return ""

    m = re.search(r"([A-Za-z_~]\w*(?:::[A-Za-z_~]\w*)*)\s*$", head)
    if not m:
        return ""

    base = m.group(1).split("::")[-1]
    if base in CPP_KEYWORDS:
        return ""
    return base


def extract_declared_interface_names(path: Path) -> Set[str]:
    text = read_text(path)
    masked = mask_comments(text)
    names: Set[str] = set()

    for stmt in iter_semicolon_statements(masked):
        name = extract_declared_name(stmt)
        if name:
            names.add(name)

    for f in extract_function_definitions(path):
        names.add(f.base_name)
    return names


def has_flow_exit_nearby(lines: Sequence[str], start: int, window: int = 3) -> bool:
    end = min(len(lines), start + window + 1)
    merged = "\n".join(lines[start:end])
    return bool(re.search(r"\b(return|continue|break|throw)\b", merged))


def normalize_condition_text(text: str) -> str:
    return text.translate(FULLWIDTH_TRANSLATION)


def strip_wrapping_parentheses(expr: str) -> str:
    s = normalize_condition_text(expr).strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        ok = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    ok = False
                    break
            if depth == 0 and i != len(s) - 1:
                ok = False
                break
        if not ok or depth != 0:
            break
        s = s[1:-1].strip()
    return s


def iter_if_conditions(line: str) -> Iterable[Tuple[str, str]]:
    norm = normalize_condition_text(line)
    i = 0
    n = len(norm)
    while i < n:
        m = re.search(r"\bif\b", norm[i:])
        if not m:
            break

        if_pos = i + m.start()
        j = if_pos + 2
        while j < n and norm[j].isspace():
            j += 1
        if j >= n or norm[j] != "(":
            i = if_pos + 2
            continue

        open_pos = j
        depth = 1
        j += 1
        while j < n and depth > 0:
            if norm[j] == "(":
                depth += 1
            elif norm[j] == ")":
                depth -= 1
            j += 1
        if depth != 0:
            break

        cond = norm[open_pos + 1 : j - 1]
        tail = norm[j:]
        yield cond, tail
        i = j


def collect_active_if_conditions(lines: Sequence[str]) -> List[List[str]]:
    active: List[Tuple[int, str]] = []
    pending: List[str] = []
    depth = 0
    out: List[List[str]] = [[] for _ in lines]

    for i, line in enumerate(lines):
        active = [(end_depth, cond) for end_depth, cond in active if depth > end_depth]
        out[i].extend([cond for _, cond in active])

        stripped = line.strip()
        if pending and stripped:
            if stripped.startswith("{"):
                for cond in pending:
                    active.append((depth, cond))
                    out[i].append(cond)
            pending = []

        for cond, tail in iter_if_conditions(line):
            if cond not in out[i]:
                out[i].append(cond)
            tail_stripped = tail.strip()
            if tail_stripped.startswith("{"):
                active.append((depth, cond))
            elif not tail_stripped:
                pending.append(cond)

        opens, closes = count_braces(line)
        depth = max(0, depth + opens - closes)

    return out


def classify_pointer_if_condition(ptr: str, cond: str) -> str:
    ptr_re = re.escape(ptr)
    s = strip_wrapping_parentheses(cond)

    null_patterns = [
        rf"!\s*\b{ptr_re}\b",
        rf"\b{ptr_re}\b\s*==\s*(?:nullptr|NULL|0)",
        rf"(?:nullptr|NULL|0)\s*==\s*\b{ptr_re}\b",
    ]
    nonnull_patterns = [
        rf"\b{ptr_re}\b\s*!=\s*(?:nullptr|NULL|0)",
        rf"(?:nullptr|NULL|0)\s*!=\s*\b{ptr_re}\b",
    ]

    if any(re.fullmatch(p, s) for p in null_patterns):
        return "null"
    if any(re.fullmatch(p, s) for p in nonnull_patterns):
        return "nonnull"

    if "||" in s:
        return ""
    if re.fullmatch(rf"\b{ptr_re}\b", s):
        return "truthy"
    if re.fullmatch(rf"\b{ptr_re}\b\s*&&.+", s):
        return "truthy"
    if re.fullmatch(rf".+&&\s*\b{ptr_re}\b", s):
        return "truthy"
    return ""


def has_null_disjunct_guard(ptr: str, cond: str) -> bool:
    ptr_re = re.escape(ptr)
    s = strip_wrapping_parentheses(cond)
    if "||" not in s:
        return False

    null_token = (
        rf"(?:!\s*\b{ptr_re}\b|"
        rf"\b{ptr_re}\b\s*==\s*(?:nullptr|NULL|0)|"
        rf"(?:nullptr|NULL|0)\s*==\s*\b{ptr_re}\b)"
    )
    return bool(re.search(null_token, s))


def count_braces(line: str) -> Tuple[int, int]:
    opens = 0
    closes = 0
    i = 0
    n = len(line)
    state = "normal"
    while i < n:
        c = line[i]
        if state == "normal":
            if c == '"':
                state = "string"
            elif c == "'":
                state = "char"
            elif c == "{":
                opens += 1
            elif c == "}":
                closes += 1
            i += 1
            continue
        if state == "string":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                state = "normal"
            i += 1
            continue
        if state == "char":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "'":
                state = "normal"
            i += 1
            continue
    return opens, closes


def pointer_assignment_kind(ptr: str, line: str) -> str:
    p_re = re.escape(ptr)
    for m in re.finditer(rf"\b{p_re}\b\s*=(?!=)", line):
        start = m.start()
        prev = line[start - 1] if start > 0 else ""
        prev2 = line[start - 2] if start > 1 else ""
        if prev in {"*", "&", "."}:
            continue
        if prev == ">" and prev2 == "-":
            continue

        assign_tail = line[m.end() :].strip()
        if re.match(r"(?:nullptr|NULL|0)\b", assign_tail):
            return "null"
        return "other"
    return ""


def has_inline_pointer_guard(ptr: str, line: str) -> bool:
    p_re = re.escape(ptr)
    return bool(re.search(rf"\b{p_re}\b\s*&&", line) or re.search(rf"&&\s*\b{p_re}\b", line))


def looks_like_integer_literal(expr: str) -> bool:
    e = expr.strip().lower()
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(u|ul|ull|l|ll)?", e))


def parse_integer_literal(expr: str) -> Optional[int]:
    e = strip_wrapping_parentheses(expr).strip().lower().replace("_", "")
    m = re.fullmatch(r"([+-]?(?:0x[0-9a-f]+|\d+))(?:u|ul|ull|l|ll)?", e)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def extract_identifiers(expr: str) -> List[str]:
    ids = re.findall(r"[A-Za-z_]\w*", expr)
    return [x for x in ids if x not in CPP_KEYWORDS]


def has_integer_index_cast(expr: str) -> bool:
    return bool(
        re.search(
            r"\bstatic_cast\s*<\s*(?:int|short|long|size_t|ssize_t|ptrdiff_t|u?int\d*_t)\s*>",
            expr,
        )
        or re.search(r"\(\s*(?:int|short|long|size_t|ssize_t|ptrdiff_t|u?int\d*_t)\s*\)", expr)
    )


def is_integer_index_expr(
    index_expr: str,
    params_text: str,
    lines: Sequence[str],
    line_no0: int,
) -> bool:
    expr = index_expr.strip()
    if not expr:
        return False

    if has_integer_index_cast(expr):
        return True

    if re.search(r"\d+\.\d*|\.\d+|\d+[eE][+-]?\d+|\b(?:float|double)\b", expr):
        return False

    ids = extract_identifiers(expr)
    if not ids:
        return looks_like_integer_literal(expr)

    integer_names = set(extract_integer_params(params_text))
    start = max(0, line_no0 - 20)
    context = "\n".join(lines[start : line_no0 + 1])

    for name in ids:
        if name in integer_names:
            continue
        n_re = re.escape(name)
        decl_patterns = [
            rf"\bfor\s*\(\s*(?:const\s+)?(?:static\s+)?(?:unsigned|signed)?\s*(?:char|short|int|long|size_t|ssize_t|ptrdiff_t|u?int\d*_t)\b[^)]*\b{n_re}\b",
            rf"\b(?:const\s+)?(?:static\s+)?(?:unsigned|signed)?\s*(?:char|short|int|long|size_t|ssize_t|ptrdiff_t|u?int\d*_t)\b[^;\n]*\b{n_re}\b",
        ]
        if any(re.search(p, context) for p in decl_patterns):
            continue
        return False

    return True


def infer_integer_symbol_literal(symbol: str, lines: Sequence[str], line_no0: int) -> Optional[int]:
    s_re = re.escape(symbol)
    value: Optional[int] = None
    assign_re = re.compile(rf"\b{s_re}\b\s*=(?!=)\s*([^,;)\s]+)")

    for i in range(0, line_no0 + 1):
        line = lines[i]
        for m in assign_re.finditer(line):
            parsed = parse_integer_literal(m.group(1))
            if parsed is not None:
                value = parsed
    return value


def is_array_declaration_occurrence(line: str, match_start: int, match_end: int) -> bool:
    """
    Heuristic: treat `name[sz]` as declaration declarator (not index access).
    Example: `Type arr[6] = {...};`
    """
    prefix = line[:match_start]
    suffix = line[match_end:]
    suffix_l = suffix.lstrip()

    if not suffix_l or not suffix_l.startswith((";", ",", "=", "{")):
        return False

    if "->" in prefix or "." in prefix:
        return False
    if re.search(r"[=()+\-/%?:]", prefix):
        return False

    words = re.findall(r"[A-Za-z_]\w*", prefix)
    if not words:
        return False
    if any(w in NON_DECL_STMT_KEYWORDS for w in words):
        return False

    return True


def infer_container_literal_size(container: str, lines: Sequence[str], line_no0: int) -> Optional[int]:
    c_re = re.escape(container)
    known_size: Optional[int] = None

    for i in range(0, line_no0 + 1):
        line = lines[i]

        m_ctor_decl = re.search(
            rf"\b(?:std::)?vector\s*<[^>]+>\s*\b{c_re}\b\s*\(\s*([^,\)\s]+)",
            line,
        )
        if m_ctor_decl:
            parsed = parse_integer_literal(m_ctor_decl.group(1))
            known_size = parsed if parsed is not None and parsed >= 0 else None

        m_ctor_assign = re.search(
            rf"\b{c_re}\b\s*=(?!=)\s*(?:std::)?vector\s*<[^>]+>\s*\(\s*([^,\)\s]+)",
            line,
        )
        if m_ctor_assign:
            parsed = parse_integer_literal(m_ctor_assign.group(1))
            known_size = parsed if parsed is not None and parsed >= 0 else None

        m_resize = re.search(rf"\b{c_re}\b\s*(?:\.|->)\s*resize\s*\(\s*([^,\)\s]+)", line)
        if m_resize:
            parsed = parse_integer_literal(m_resize.group(1))
            known_size = parsed if parsed is not None and parsed >= 0 else None

        if re.search(rf"\b{c_re}\b\s*(?:\.|->)\s*clear\s*\(\s*\)", line):
            known_size = 0

        m_c_array = re.search(
            rf"\b[A-Za-z_]\w*(?:\s*[*&])?\s+\b{c_re}\b\s*\[\s*([^\]]+)\s*\]",
            line,
        )
        if m_c_array:
            parsed = parse_integer_literal(m_c_array.group(1))
            known_size = parsed if parsed is not None and parsed >= 0 else None

    return known_size


def resolve_upper_bound_token(token: str, lines: Sequence[str], line_no0: int) -> Optional[int]:
    parsed = parse_integer_literal(token)
    if parsed is not None:
        return parsed
    if re.fullmatch(r"[A-Za-z_]\w*", token):
        return infer_integer_symbol_literal(token, lines, line_no0)
    return None


def evaluate_literal_index_against_container_size(
    index_expr: str,
    container: str,
    lines: Sequence[str],
    line_no0: int,
) -> Tuple[bool, Optional[bool], Optional[int], Optional[int]]:
    """
    Returns:
    - is_literal: whether index_expr is a parsed integer literal
    - in_bounds: for literal with known size, whether 0 <= idx < size; else None
    - literal_index: parsed integer literal value (if any)
    - known_size: inferred container size up to current line (if any)
    """
    literal_index = parse_integer_literal(index_expr)
    if literal_index is None:
        return (False, None, None, None)

    known_size = infer_container_literal_size(container, lines, line_no0)
    if known_size is None:
        return (True, None, literal_index, None)

    return (True, 0 <= literal_index < known_size, literal_index, known_size)


def has_bounds_guard(index_expr: str, container: str, lines: Sequence[str], line_no0: int) -> bool:
    ids = extract_identifiers(index_expr)
    if not ids:
        return False

    start = max(0, line_no0 - 10)
    context = "\n".join(lines[start : line_no0 + 1])
    c_re = re.escape(container)
    known_size = infer_container_literal_size(container, lines, line_no0)

    for idx in ids:
        i_re = re.escape(idx)
        upper_checks = [
            rf"\b{i_re}\b\s*<\s*\b{c_re}\b\s*(?:\.|->)\s*(?:size|length)\s*\(",
            rf"\b{c_re}\b\s*(?:\.|->)\s*(?:size|length)\s*\(\s*\)\s*>\s*\b{i_re}\b",
        ]
        lower_checks = [
            rf"\b{i_re}\b\s*>=\s*0\b",
            rf"0\s*<=\s*\b{i_re}\b",
            rf"\bfor\s*\([^;]*\b{i_re}\b\s*=\s*0\b",
        ]
        unsigned_hints = [
            rf"\b(?:size_t|uint\d*_t|unsigned(?:\s+(?:int|long|short|char))?)\b[^;\n]*\b{i_re}\b",
        ]

        lower_reject = False
        upper_reject = False
        for j in range(start, line_no0 + 1):
            line = lines[j]
            if "if" not in line:
                continue
            if not has_flow_exit_nearby(lines, j):
                continue

            if re.search(rf"\b{i_re}\b\s*<\s*0\b", line) or re.search(rf"0\s*>\s*\b{i_re}\b", line):
                lower_reject = True

            upper_reject_patterns = [
                rf"\b{i_re}\b\s*>?=\s*\b{c_re}\b\s*(?:\.|->)\s*(?:size|length)\s*\(\s*\)",
                rf"\b{c_re}\b\s*(?:\.|->)\s*(?:size|length)\s*\(\s*\)\s*<=\s*\b{i_re}\b",
                rf"\b{i_re}\b\s*>=\s*[A-Za-z_]\w*(?:Size|Count|Length|MAX|max)\b",
            ]
            if any(re.search(p, line) for p in upper_reject_patterns):
                upper_reject = True

        upper_ok = any(re.search(p, context) for p in upper_checks)
        lower_ok = any(re.search(p, context) for p in lower_checks) or any(
            re.search(p, context) for p in unsigned_hints
        )
        if upper_reject:
            upper_ok = True
        if lower_reject:
            lower_ok = True

        # Literal/symbol bound check tied to known container size.
        if known_size is not None and known_size >= 0:
            upper_from_literal_or_symbol = False
            for j in range(start, line_no0 + 1):
                line = lines[j]

                m_lt = re.search(rf"\b{i_re}\b\s*<\s*([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)", line)
                if m_lt:
                    b = resolve_upper_bound_token(m_lt.group(1), lines, j)
                    if b is not None and b <= known_size:
                        upper_from_literal_or_symbol = True

                m_gt = re.search(rf"([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)\s*>\s*\b{i_re}\b", line)
                if m_gt:
                    b = resolve_upper_bound_token(m_gt.group(1), lines, j)
                    if b is not None and b <= known_size:
                        upper_from_literal_or_symbol = True

                m_le = re.search(rf"\b{i_re}\b\s*<=\s*([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)", line)
                if m_le:
                    b = resolve_upper_bound_token(m_le.group(1), lines, j)
                    if b is not None and (b + 1) <= known_size:
                        upper_from_literal_or_symbol = True

                m_ge = re.search(rf"([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)\s*>=\s*\b{i_re}\b", line)
                if m_ge:
                    b = resolve_upper_bound_token(m_ge.group(1), lines, j)
                    if b is not None and (b + 1) <= known_size:
                        upper_from_literal_or_symbol = True

                if has_flow_exit_nearby(lines, j):
                    m_rej_ge = re.search(
                        rf"\b{i_re}\b\s*>=\s*([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)",
                        line,
                    )
                    if m_rej_ge:
                        b = resolve_upper_bound_token(m_rej_ge.group(1), lines, j)
                        if b is not None and b <= known_size:
                            upper_from_literal_or_symbol = True

                    m_rej_le = re.search(
                        rf"([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)\s*<=\s*\b{i_re}\b",
                        line,
                    )
                    if m_rej_le:
                        b = resolve_upper_bound_token(m_rej_le.group(1), lines, j)
                        if b is not None and b <= known_size:
                            upper_from_literal_or_symbol = True

                    m_rej_gt = re.search(
                        rf"\b{i_re}\b\s*>\s*([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)",
                        line,
                    )
                    if m_rej_gt:
                        b = resolve_upper_bound_token(m_rej_gt.group(1), lines, j)
                        if b is not None and (b + 1) <= known_size:
                            upper_from_literal_or_symbol = True

                    m_rej_lt = re.search(
                        rf"([A-Za-z_]\w*|[-+]?(?:0x[0-9A-Fa-f]+|\d+)[uUlL]*)\s*<\s*\b{i_re}\b",
                        line,
                    )
                    if m_rej_lt:
                        b = resolve_upper_bound_token(m_rej_lt.group(1), lines, j)
                        if b is not None and (b + 1) <= known_size:
                            upper_from_literal_or_symbol = True

            if upper_from_literal_or_symbol:
                upper_ok = True

        if upper_ok and lower_ok:
            return True
    return False


def is_zero_literal(expr: str) -> bool:
    e = expr.strip().lower()
    return bool(
        re.fullmatch(r"0+(u|ul|ull|l|ll)?", e)
        or re.fullmatch(r"0*\.0+(f|l)?", e)
    )


def parse_float_literal(expr: str) -> Optional[float]:
    e = strip_wrapping_parentheses(expr).strip().lower()
    if not e:
        return None
    if e.endswith(("f", "l")):
        e = e[:-1]
    if not re.fullmatch(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?", e):
        return None
    try:
        return float(e)
    except ValueError:
        return None


def iter_abs_threshold_comparisons(var: str, line: str) -> Iterable[Tuple[str, float]]:
    v_re = re.escape(var)
    p1 = re.compile(
        rf"(?:std::)?(?:abs|fabs)\s*\(\s*\b{v_re}\b\s*\)\s*(<=|<|>=|>)\s*([-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?[fFlL]?)"
    )
    p2 = re.compile(
        rf"([-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?[fFlL]?)\s*(<=|<|>=|>)\s*(?:std::)?(?:abs|fabs)\s*\(\s*\b{v_re}\b\s*\)"
    )

    reverse = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}

    for m in p1.finditer(line):
        threshold = parse_float_literal(m.group(2))
        if threshold is not None:
            yield m.group(1), abs(threshold)

    for m in p2.finditer(line):
        threshold = parse_float_literal(m.group(1))
        if threshold is not None:
            yield reverse[m.group(2)], abs(threshold)


def split_top_level(expr: str, token: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and expr.startswith(token, i):
            parts.append(expr[start:i].strip())
            i += len(token)
            start = i
            continue
        i += 1
    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def parse_condition_expr(expr: str):
    s = strip_wrapping_parentheses(expr)
    or_parts = split_top_level(s, "||")
    if len(or_parts) > 1:
        return ("or", [parse_condition_expr(x) for x in or_parts])

    and_parts = split_top_level(s, "&&")
    if len(and_parts) > 1:
        return ("and", [parse_condition_expr(x) for x in and_parts])

    if s.startswith("!") and not s.startswith("!="):
        return ("not", parse_condition_expr(s[1:].strip()))
    return ("atom", s)


def compact_expr_text(expr: str) -> str:
    return re.sub(r"\s+", "", strip_wrapping_parentheses(normalize_condition_text(expr)))


def parse_is_equal_call_args(expr: str) -> Optional[Tuple[str, str]]:
    s = strip_wrapping_parentheses(normalize_condition_text(expr))
    m = re.fullmatch(r"(?:[A-Za-z_]\w*::)?isEqual\s*\((.*)\)", s)
    if not m:
        return None
    parts = split_top_level(m.group(1), ",")
    if len(parts) != 2:
        return None
    return parts[0].strip(), parts[1].strip()


def expr_matches_difference(expr: str, lhs: str, rhs: str) -> bool:
    e = compact_expr_text(expr)
    l = compact_expr_text(lhs)
    r = compact_expr_text(rhs)
    if not e or not l or not r:
        return False
    return e == f"{l}-{r}" or e == f"{r}-{l}"


def atom_implies_expr_near_zero(expr: str, atom: str) -> bool:
    args = parse_is_equal_call_args(atom)
    if not args:
        return False
    lhs, rhs = args
    return expr_matches_difference(expr, lhs, rhs)


def condition_implies_expr_away_from_zero(expr: str, cond: str) -> bool:
    def implies(node) -> bool:
        kind = node[0]
        if kind == "atom":
            return False
        if kind == "not":
            child = node[1]
            return child[0] == "atom" and atom_implies_expr_near_zero(expr, child[1])
        if kind == "and":
            return any(implies(child) for child in node[1])
        if kind == "or":
            return all(implies(child) for child in node[1])
        return False

    return implies(parse_condition_expr(cond))


def interval_set_universe() -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    return [(None, False, None, False)]


def interval_set_empty() -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    return []


def interval_low_sort_key(interval: Tuple[Optional[float], bool, Optional[float], bool]) -> Tuple[float, int]:
    low, low_open, _, _ = interval
    return (float("-inf") if low is None else low, 1 if low_open else 0)


def interval_can_merge(
    left: Tuple[Optional[float], bool, Optional[float], bool],
    right: Tuple[Optional[float], bool, Optional[float], bool],
) -> bool:
    _, _, left_high, left_high_open = left
    right_low, right_low_open, _, _ = right

    if left_high is None or right_low is None:
        return True
    if right_low < left_high:
        return True
    if right_low == left_high and (not left_high_open or not right_low_open):
        return True
    return False


def merge_intervals(
    left: Tuple[Optional[float], bool, Optional[float], bool],
    right: Tuple[Optional[float], bool, Optional[float], bool],
) -> Tuple[Optional[float], bool, Optional[float], bool]:
    low, low_open, left_high, left_high_open = left
    _, _, right_high, right_high_open = right
    if left_high is None or right_high is None:
        return (low, low_open, None, False)
    if right_high > left_high:
        return (low, low_open, right_high, right_high_open)
    if right_high < left_high:
        return (low, low_open, left_high, left_high_open)
    return (low, low_open, left_high, left_high_open and right_high_open)


def normalize_interval_set(
    values: List[Tuple[Optional[float], bool, Optional[float], bool]]
) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    cleaned = [x for x in values if not interval_is_empty(x)]
    if not cleaned:
        return []
    cleaned.sort(key=interval_low_sort_key)
    out = [cleaned[0]]
    for item in cleaned[1:]:
        if interval_can_merge(out[-1], item):
            out[-1] = merge_intervals(out[-1], item)
        else:
            out.append(item)
    return out


def interval_set_union(
    a: List[Tuple[Optional[float], bool, Optional[float], bool]],
    b: List[Tuple[Optional[float], bool, Optional[float], bool]],
) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    return normalize_interval_set(a + b)


def interval_set_intersection(
    a: List[Tuple[Optional[float], bool, Optional[float], bool]],
    b: List[Tuple[Optional[float], bool, Optional[float], bool]],
) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    out: List[Tuple[Optional[float], bool, Optional[float], bool]] = []
    for x in a:
        for y in b:
            inter = intersect_intervals(x, y)
            if not interval_is_empty(inter):
                out.append(inter)
    return normalize_interval_set(out)


def interval_set_complement(
    s: List[Tuple[Optional[float], bool, Optional[float], bool]]
) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    items = normalize_interval_set(s)
    if not items:
        return interval_set_universe()

    out: List[Tuple[Optional[float], bool, Optional[float], bool]] = []
    start_low: Optional[float] = None
    start_low_open = False

    for low, low_open, high, high_open in items:
        if low is not None:
            gap = (start_low, start_low_open, low, not low_open)
            if not interval_is_empty(gap):
                out.append(gap)
        start_low = high
        start_low_open = not high_open

    if start_low is not None:
        last = (start_low, start_low_open, None, False)
        if not interval_is_empty(last):
            out.append(last)
    return normalize_interval_set(out)


def comparison_interval_set(op: str, value: float) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    if op == "<":
        return [(None, False, value, True)]
    if op == "<=":
        return [(None, False, value, False)]
    if op == ">":
        return [(value, True, None, False)]
    if op == ">=":
        return [(value, False, None, False)]
    if op == "==":
        return [(value, False, value, False)]
    if op == "!=":
        return normalize_interval_set([(None, False, value, True), (value, True, None, False)])
    return interval_set_universe()


def abs_comparison_interval_set(op: str, value: float) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    if op in {"<", "<="}:
        if value < 0:
            return interval_set_empty()
        return [(-value, op == "<", value, op == "<")]
    if op in {">", ">="}:
        if value < 0 or (value == 0 and op == ">="):
            return interval_set_universe()
        left = (None, False, -value, op == ">")
        right = (value, op == ">", None, False)
        return normalize_interval_set([left, right])
    if op == "==":
        if value < 0:
            return interval_set_empty()
        if value == 0:
            return [(0.0, False, 0.0, False)]
        return [(-value, False, -value, False), (value, False, value, False)]
    if op == "!=":
        return interval_set_complement(abs_comparison_interval_set("==", value))
    return interval_set_universe()


def atom_interval_set_for_var(
    var: str,
    atom: str,
) -> Optional[List[Tuple[Optional[float], bool, Optional[float], bool]]]:
    s = strip_wrapping_parentheses(atom)
    v_re = re.escape(var)
    num = r"[-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?[fFlL]?"
    reverse = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}

    if re.fullmatch(rf"\b{v_re}\b", s):
        return comparison_interval_set("!=", 0.0)

    is_equal_call = re.fullmatch(
        r"(?:[A-Za-z_]\w*::)?isEqual\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)",
        s,
    )
    if is_equal_call:
        lhs = strip_wrapping_parentheses(is_equal_call.group(1))
        rhs = strip_wrapping_parentheses(is_equal_call.group(2))
        if re.fullmatch(rf"\b{v_re}\b", lhs):
            v = parse_float_literal(rhs)
            if v is not None:
                eps = SMALL_DENOMINATOR_EPS
                return [(v - eps, False, v + eps, False)]
        if re.fullmatch(rf"\b{v_re}\b", rhs):
            v = parse_float_literal(lhs)
            if v is not None:
                eps = SMALL_DENOMINATOR_EPS
                return [(v - eps, False, v + eps, False)]
        return None

    abs_left = re.fullmatch(
        rf"(?:std::)?(?:abs|fabs)\s*\(\s*\b{v_re}\b\s*\)\s*(<=|>=|<|>|==|!=)\s*({num})",
        s,
    )
    if abs_left:
        value = parse_float_literal(abs_left.group(2))
        if value is None:
            return interval_set_universe()
        return abs_comparison_interval_set(abs_left.group(1), value)

    abs_right = re.fullmatch(
        rf"({num})\s*(<=|>=|<|>|==|!=)\s*(?:std::)?(?:abs|fabs)\s*\(\s*\b{v_re}\b\s*\)",
        s,
    )
    if abs_right:
        value = parse_float_literal(abs_right.group(1))
        if value is None:
            return interval_set_universe()
        return abs_comparison_interval_set(reverse[abs_right.group(2)], value)

    left = re.fullmatch(rf"\b{v_re}\b\s*(<=|>=|<|>|==|!=)\s*({num})", s)
    if left:
        value = parse_float_literal(left.group(2))
        if value is None:
            return interval_set_universe()
        return comparison_interval_set(left.group(1), value)

    right = re.fullmatch(rf"({num})\s*(<=|>=|<|>|==|!=)\s*\b{v_re}\b", s)
    if right:
        value = parse_float_literal(right.group(1))
        if value is None:
            return interval_set_universe()
        return comparison_interval_set(reverse[right.group(2)], value)

    return None


def eval_condition_interval_set(
    node,
    var: str,
    assume_true: bool,
) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    kind = node[0]
    if kind == "atom":
        atom_set = atom_interval_set_for_var(var, node[1])
        if atom_set is None:
            return interval_set_universe()
        return atom_set if assume_true else interval_set_complement(atom_set)

    if kind == "not":
        return eval_condition_interval_set(node[1], var, not assume_true)

    children = node[1]
    if kind == "and":
        if assume_true:
            out = interval_set_universe()
            for child in children:
                out = interval_set_intersection(out, eval_condition_interval_set(child, var, True))
            return out
        out = interval_set_empty()
        for child in children:
            out = interval_set_union(out, eval_condition_interval_set(child, var, False))
        return out

    if kind == "or":
        if assume_true:
            out = interval_set_empty()
            for child in children:
                out = interval_set_union(out, eval_condition_interval_set(child, var, True))
            return out
        out = interval_set_universe()
        for child in children:
            out = interval_set_intersection(out, eval_condition_interval_set(child, var, False))
        return out

    return interval_set_universe()


def condition_interval_set(
    var: str,
    condition_text: str,
    assume_true: bool,
) -> List[Tuple[Optional[float], bool, Optional[float], bool]]:
    ast = parse_condition_expr(condition_text)
    return normalize_interval_set(eval_condition_interval_set(ast, var, assume_true))


def intersect_intervals(
    a: Tuple[Optional[float], bool, Optional[float], bool],
    b: Tuple[Optional[float], bool, Optional[float], bool],
) -> Tuple[Optional[float], bool, Optional[float], bool]:
    a_low, a_low_open, a_high, a_high_open = a
    b_low, b_low_open, b_high, b_high_open = b

    if a_low is None:
        low, low_open = b_low, b_low_open
    elif b_low is None:
        low, low_open = a_low, a_low_open
    elif a_low > b_low:
        low, low_open = a_low, a_low_open
    elif b_low > a_low:
        low, low_open = b_low, b_low_open
    else:
        low, low_open = a_low, a_low_open or b_low_open

    if a_high is None:
        high, high_open = b_high, b_high_open
    elif b_high is None:
        high, high_open = a_high, a_high_open
    elif a_high < b_high:
        high, high_open = a_high, a_high_open
    elif b_high < a_high:
        high, high_open = b_high, b_high_open
    else:
        high, high_open = a_high, a_high_open or b_high_open

    return (low, low_open, high, high_open)


def interval_is_empty(interval: Tuple[Optional[float], bool, Optional[float], bool]) -> bool:
    low, low_open, high, high_open = interval
    if low is None or high is None:
        return False
    if low > high:
        return True
    if low == high and (low_open or high_open):
        return True
    return False


def interval_contains(interval: Tuple[Optional[float], bool, Optional[float], bool], value: float) -> bool:
    low, low_open, high, high_open = interval
    if low is not None:
        if value < low or (value == low and low_open):
            return False
    if high is not None:
        if value > high or (value == high and high_open):
            return False
    return True


def interval_away_from_zero(
    interval: Tuple[Optional[float], bool, Optional[float], bool],
    eps: float,
) -> bool:
    if interval_is_empty(interval):
        return True

    low, low_open, high, high_open = interval

    all_gt = False
    if low is not None:
        all_gt = low > eps or (low == eps and low_open)

    all_lt = False
    if high is not None:
        all_lt = high < -eps or (high == -eps and high_open)

    return all_gt or all_lt


def interval_set_contains_value(
    s: List[Tuple[Optional[float], bool, Optional[float], bool]],
    value: float,
) -> bool:
    return any(interval_contains(x, value) for x in s)


def interval_set_away_from_zero(
    s: List[Tuple[Optional[float], bool, Optional[float], bool]],
    eps: float,
) -> bool:
    if not s:
        return True
    near_zero = [(-eps, False, eps, False)]
    return len(interval_set_intersection(s, near_zero)) == 0


def condition_implies_nonzero(var: str, cond: str) -> bool:
    interval_set = condition_interval_set(var, cond, assume_true=True)
    return not interval_set_contains_value(interval_set, 0.0)


def condition_implies_away_from_zero(var: str, cond: str, eps: float) -> bool:
    interval_set = condition_interval_set(var, cond, assume_true=True)
    return interval_set_away_from_zero(interval_set, eps)


def has_nonzero_guard(
    var: str,
    lines: Sequence[str],
    use_line: int,
    active_conds_on_use_line: Optional[Sequence[str]] = None,
) -> bool:
    v_re = re.escape(var)
    cond_nonzero = re.compile(rf"(?:\b{v_re}\b\s*!=\s*0|0\s*!=\s*\b{v_re}\b)")
    cond_zero = re.compile(rf"(?:\b{v_re}\b\s*==\s*0|0\s*==\s*\b{v_re}\b)")
    assert_nonzero = re.compile(rf"\b(?:assert|CHECK)\s*\(\s*\b{v_re}\b(?:\s*!=\s*0)?\s*\)")
    active_cond_keys = {
        normalize_condition_text(strip_wrapping_parentheses(c)).strip()
        for c in (active_conds_on_use_line or [])
    }
    start = max(0, use_line - 10)
    for i in range(start, use_line + 1):
        line = lines[i]
        if assert_nonzero.search(line):
            return True
        if cond_nonzero.search(line):
            return True
        if cond_zero.search(line) and has_flow_exit_nearby(lines, i):
            return True
        if has_flow_exit_nearby(lines, i):
            for cond, _ in iter_if_conditions(line):
                cond_key = normalize_condition_text(strip_wrapping_parentheses(cond)).strip()
                if cond_key in active_cond_keys:
                    continue
                remain = condition_interval_set(var, cond, assume_true=False)
                if not interval_set_contains_value(remain, 0.0):
                    return True
        for op, threshold in iter_abs_threshold_comparisons(var, line):
            if threshold <= 0:
                continue
            if op in {">", ">="} and re.search(r"\b(?:assert|CHECK)\s*\(", line):
                return True
            if op in {"<", "<="} and "if" in line and has_flow_exit_nearby(lines, i):
                return True
    return False


def is_likely_floating_identifier(var: str, lines: Sequence[str], use_line: int) -> bool:
    v_re = re.escape(var)
    start = max(0, use_line - 20)
    context = "\n".join(lines[start : use_line + 1])
    return bool(re.search(rf"\b(?:float|double|long\s+double)\b[^;\n]*\b{v_re}\b", context))


def looks_like_floating_expr(expr: str) -> bool:
    e = expr.strip()
    if re.search(r"\d+\.\d*|\.\d+|\d+[eE][+-]?\d+", e):
        return True
    if re.search(r"\bstatic_cast\s*<\s*(?:float|double|long\s+double)\s*>", e):
        return True
    if re.search(r"\b(?:float|double)\s*\(", e):
        return True
    return False


def has_small_value_guard(
    var: str,
    lines: Sequence[str],
    use_line: int,
    active_conds_on_use_line: Optional[Sequence[str]] = None,
) -> bool:
    v_re = re.escape(var)
    bilateral_if = re.compile(
        rf"\bif\s*\([^)]*\b{v_re}\b\s*[<]=?\s*[^)&|]+&&[^)]*\b{v_re}\b\s*[>]=?\s*-[^)&|]+\)"
    )
    active_cond_keys = {
        normalize_condition_text(strip_wrapping_parentheses(c)).strip()
        for c in (active_conds_on_use_line or [])
    }
    start = max(0, use_line - 12)
    for i in range(start, use_line + 1):
        line = lines[i]
        if has_flow_exit_nearby(lines, i):
            for cond, _ in iter_if_conditions(line):
                cond_key = normalize_condition_text(strip_wrapping_parentheses(cond)).strip()
                if cond_key in active_cond_keys:
                    continue
                remain = condition_interval_set(var, cond, assume_true=False)
                if interval_set_away_from_zero(remain, SMALL_DENOMINATOR_EPS):
                    return True
        for op, threshold in iter_abs_threshold_comparisons(var, line):
            if threshold < SMALL_DENOMINATOR_EPS:
                continue
            if op in {">", ">="} and re.search(r"\b(?:assert|CHECK)\s*\(", line):
                return True
            if op in {"<", "<="} and "if" in line and has_flow_exit_nearby(lines, i):
                return True
        if bilateral_if.search(line) and has_flow_exit_nearby(lines, i):
            return True
    return False


def has_expr_small_value_guard(expr: str, lines: Sequence[str], use_line: int) -> bool:
    compact_expr = re.sub(r"\s+", "", expr)
    if not compact_expr:
        return False

    start = max(0, use_line - 12)
    for i in range(start, use_line + 1):
        compact_line = re.sub(r"\s+", "", lines[i])
        compact_expr_re = re.escape(compact_expr)
        num = r"([-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?[fFlL]?)"
        or_patterns = [
            rf"{compact_expr_re}<-(?:{num})\|\|{compact_expr_re}>(?:{num})",
            rf"{compact_expr_re}>(?:{num})\|\|{compact_expr_re}<-(?:{num})",
            rf"{compact_expr_re}<=-(?:{num})\|\|{compact_expr_re}>=(?:{num})",
            rf"{compact_expr_re}>=(?:{num})\|\|{compact_expr_re}<=-(?:{num})",
        ]
        for pat in or_patterns:
            m = re.search(pat, compact_line)
            if not m:
                continue
            vals = [parse_float_literal(x) for x in m.groups()]
            vv = [abs(v) for v in vals if v is not None]
            if vv and min(vv) >= SMALL_DENOMINATOR_EPS and has_flow_exit_nearby(lines, i):
                return True

        p1 = re.finditer(
            rf"(?:abs|fabs)\({re.escape(compact_expr)}\)(<=|<|>=|>)([-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?[fFlL]?)",
            compact_line,
        )
        p2 = re.finditer(
            rf"([-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?[fFlL]?)(<=|<|>=|>)(?:abs|fabs)\({re.escape(compact_expr)}\)",
            compact_line,
        )
        reverse = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}

        for m in p1:
            op = m.group(1)
            threshold = parse_float_literal(m.group(2))
            if threshold is None or abs(threshold) < SMALL_DENOMINATOR_EPS:
                continue
            if op in {">", ">="} and re.search(r"\b(?:assert|CHECK)\s*\(", lines[i]):
                return True
            if op in {"<", "<="} and has_flow_exit_nearby(lines, i):
                return True

        for m in p2:
            op = reverse[m.group(2)]
            threshold = parse_float_literal(m.group(1))
            if threshold is None or abs(threshold) < SMALL_DENOMINATOR_EPS:
                continue
            if op in {">", ">="} and re.search(r"\b(?:assert|CHECK)\s*\(", lines[i]):
                return True
            if op in {"<", "<="} and has_flow_exit_nearby(lines, i):
                return True
    return False


def is_tiny_nonzero_literal(expr: str, threshold: float = SMALL_DENOMINATOR_EPS) -> bool:
    e = expr.strip().lower()
    if not e:
        return False
    if e[-1:] in {"f", "l"}:
        e = e[:-1]
    try:
        v = float(e)
    except ValueError:
        return False
    return v != 0.0 and abs(v) < threshold


def parse_denominators(line: str) -> List[str]:
    dens: List[str] = []
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]
        if ch not in "/%":
            i += 1
            continue

        prev_ch = line[i - 1] if i > 0 else ""
        next_ch = line[i + 1] if i + 1 < n else ""
        if ch == "/" and next_ch in "/=*":
            i += 1
            continue
        if ch == "%" and next_ch == "=":
            i += 1
            continue
        if prev_ch == ":":
            i += 1
            continue

        j = i + 1
        while j < n and line[j].isspace():
            j += 1
        if j >= n:
            i += 1
            continue

        if line[j] == "(":
            depth = 1
            k = j + 1
            while k < n and depth > 0:
                if line[k] == "(":
                    depth += 1
                elif line[k] == ")":
                    depth -= 1
                k += 1
            if depth == 0:
                dens.append(line[j:k].strip())
                i = k
                continue
            i += 1
            continue

        m = re.match(
            r"[A-Za-z_]\w*|"
            r"[-+]?(?:0x[0-9A-Fa-f]+|(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)"
            r"(?:[uUlLfF]+)?",
            line[j:],
        )
        if m:
            dens.append(m.group(0).strip())
            i = j + len(m.group(0))
            continue

        i += 1

    return dens


def has_top_level_add_sub(expr: str) -> bool:
    s = strip_wrapping_parentheses(expr).strip()
    if not s:
        return False

    depth = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            continue
        if depth != 0 or ch not in {"+", "-"}:
            continue

        j = i - 1
        while j >= 0 and s[j].isspace():
            j -= 1
        if j < 0:
            # unary sign at expression start
            continue

        prev = s[j]
        if prev in "([*/%+-,:<>=!&|?":
            # unary sign after operator
            continue

        # exponent sign in scientific notation, e.g. 1e-30
        if prev in {"e", "E"}:
            k = j - 1
            while k >= 0 and s[k].isspace():
                k -= 1
            if k >= 0 and (s[k].isdigit() or s[k] == "."):
                continue

        return True

    return False


def detect_null_pointer_risks(fn: FunctionInfo) -> List[Finding]:
    findings: List[Finding] = []
    ptrs = extract_pointer_params(fn.params_text)
    if not ptrs:
        return findings

    body_lines_orig = fn.body.splitlines()
    body_lines_mask = mask_comments(fn.body).splitlines()

    for ptr in ptrs:
        p_re = re.escape(ptr)
        deref = re.compile(rf"(?:\b{p_re}\b\s*->|\*\s*\b{p_re}\b|\b{p_re}\b\s*\[)")
        assert_nonnull = re.compile(
            rf"\b(?:assert|CHECK|CHECK_NOTNULL)\s*\(\s*\b{p_re}\b(?:\s*!=\s*(?:nullptr|NULL|0))?\s*\)"
        )

        depth = 0
        current_epoch = 0
        global_guard_epoch = -1
        block_guards: List[Tuple[int, int]] = []
        pending_truthy_if_epoch: Optional[int] = None

        for i, line in enumerate(body_lines_mask):
            stripped = line.strip()
            block_guards = [(end_depth, ep) for end_depth, ep in block_guards if depth > end_depth]

            line_guard_epoch = -1
            if pending_truthy_if_epoch is not None and stripped:
                if stripped.startswith("{"):
                    block_guards.append((depth, pending_truthy_if_epoch))
                else:
                    line_guard_epoch = pending_truthy_if_epoch
                pending_truthy_if_epoch = None

            for cond, tail in iter_if_conditions(line):
                cond_kind = classify_pointer_if_condition(ptr, cond)
                tail_stripped = tail.strip()
                if cond_kind in {"truthy", "nonnull"}:
                    if tail_stripped.startswith("{"):
                        block_guards.append((depth, current_epoch))
                    elif not tail_stripped:
                        pending_truthy_if_epoch = current_epoch
                    else:
                        line_guard_epoch = current_epoch
                elif (cond_kind == "null" or has_null_disjunct_guard(ptr, cond)) and has_flow_exit_nearby(
                    body_lines_mask, i
                ):
                    global_guard_epoch = current_epoch

            if assert_nonnull.search(line):
                global_guard_epoch = current_epoch

            if pointer_assignment_kind(ptr, line):
                current_epoch += 1
                if pending_truthy_if_epoch is not None and pending_truthy_if_epoch != current_epoch:
                    pending_truthy_if_epoch = None

            has_block_guard = any(depth > end_depth and ep == current_epoch for end_depth, ep in block_guards)
            has_global_guard = global_guard_epoch == current_epoch
            has_line_guard = line_guard_epoch == current_epoch
            has_inline_guard = has_inline_pointer_guard(ptr, line)

            if deref.search(line) and not (has_block_guard or has_global_guard or has_line_guard or has_inline_guard):
                code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
                findings.append(
                    Finding(
                        risk_type="null_pointer_risk",
                        file=fn.file,
                        line=fn.start_line + 1 + i,
                        function=fn.name,
                        detail=f"指针参数 '{ptr}' 在此处被解引用，但未识别到明确的判空保护。",
                        code=code,
                    )
                )

            opens, closes = count_braces(line)
            depth = max(0, depth + opens - closes)

    return findings


def detect_out_of_bounds_risks(fn: FunctionInfo) -> List[Finding]:
    findings: List[Finding] = []
    body_lines_orig = fn.body.splitlines()
    body_lines_mask = mask_comments(fn.body).splitlines()
    pointer_params = set(extract_pointer_params(fn.params_text))

    for i, line in enumerate(body_lines_mask):
        for m in INDEX_ACCESS_RE.finditer(line):
            container = m.group(1)
            index_expr = m.group(2).strip()
            if not index_expr:
                continue
            # For raw pointer parameters, `p[0]` is semantically `*p`.
            # Let null-pointer rules cover this case to avoid OOB false positives.
            if container in pointer_params:
                lit = parse_integer_literal(index_expr)
                if lit == 0:
                    continue
            if is_array_declaration_occurrence(line, m.start(1), m.end()):
                continue
            is_lit, in_bounds, lit_idx, known_size = evaluate_literal_index_against_container_size(
                index_expr, container, body_lines_mask, i
            )
            if is_lit and in_bounds is True:
                continue
            if is_lit and in_bounds is False:
                code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
                if known_size is not None and known_size > 0:
                    bound_text = f"0~{known_size - 1}"
                else:
                    bound_text = "空区间"
                findings.append(
                    Finding(
                        risk_type="out_of_bounds_risk",
                        file=fn.file,
                        line=fn.start_line + 1 + i,
                        function=fn.name,
                        detail=(
                            f"索引访问 '{container}[{index_expr}]' 超出已识别容量范围 "
                            f"(容量={known_size}，有效索引={bound_text})。"
                        ),
                        code=code,
                    )
                )
                continue
            if looks_like_integer_literal(index_expr):
                pass
            elif '"' in index_expr or "'" in index_expr:
                continue
            elif not is_integer_index_expr(index_expr, fn.params_text, body_lines_mask, i):
                code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
                findings.append(
                    Finding(
                        risk_type="out_of_bounds_risk",
                        file=fn.file,
                        line=fn.start_line + 1 + i,
                        function=fn.name,
                        detail=f"索引表达式 '{index_expr}' 不是明显的整数索引。",
                        code=code,
                    )
                )
                continue
            if has_bounds_guard(index_expr, container, body_lines_mask, i):
                continue

            code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
            findings.append(
                Finding(
                    risk_type="out_of_bounds_risk",
                    file=fn.file,
                    line=fn.start_line + 1 + i,
                    function=fn.name,
                    detail=f"索引访问 '{container}[{index_expr}]' 未识别到明确的边界检查。",
                    code=code,
                )
            )
    return findings


def detect_divide_by_zero_risks(fn: FunctionInfo) -> List[Finding]:
    findings: List[Finding] = []
    body_lines_orig = fn.body.splitlines()
    body_lines_mask = mask_comments(fn.body).splitlines()
    active_conds_by_line = collect_active_if_conditions(body_lines_mask)
    floating_params = extract_floating_params(fn.params_text)

    for i, line in enumerate(body_lines_mask):
        dens = parse_denominators(line)
        if not dens:
            continue

        for den in dens:
            d = den.strip()
            if not d:
                continue
            if is_zero_literal(d):
                code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
                findings.append(
                    Finding(
                        risk_type="divide_by_zero_risk",
                        file=fn.file,
                        line=fn.start_line + 1 + i,
                        function=fn.name,
                        detail=f"除数 '{d}' 是零字面量。",
                        code=code,
                    )
                )
                continue

            ids = extract_identifiers(d if not (d.startswith("(") and d.endswith(")")) else d[1:-1])
            line_conds = active_conds_by_line[i] if i < len(active_conds_by_line) else []
            expr_requires_expression_guard = has_top_level_add_sub(d)
            guarded_nonzero_by_expr_cond = any(
                condition_implies_expr_away_from_zero(d, cond) for cond in line_conds
            )
            if not ids:
                if looks_like_floating_expr(d) and is_tiny_nonzero_literal(d):
                    code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
                    findings.append(
                        Finding(
                            risk_type="small_denominator_risk",
                            file=fn.file,
                            line=fn.start_line + 1 + i,
                            function=fn.name,
                            detail=(
                                f"除数 '{d}' 虽非 0 但非常小 "
                                f"(|den| < {SMALL_DENOMINATOR_EPS:.0e})，可能缺少近零保护。"
                            ),
                            code=code,
                        )
                    )
                continue

            guarded_nonzero = guarded_nonzero_by_expr_cond
            if not expr_requires_expression_guard:
                guarded_nonzero = guarded_nonzero or any(
                    has_nonzero_guard(var, body_lines_mask, i, line_conds) for var in ids
                )
            if not guarded_nonzero and line_conds and not expr_requires_expression_guard:
                guarded_nonzero = any(
                    condition_implies_nonzero(var, cond)
                    for var in ids
                    for cond in line_conds
                )
            if not guarded_nonzero:
                code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
                findings.append(
                    Finding(
                        risk_type="divide_by_zero_risk",
                        file=fn.file,
                        line=fn.start_line + 1 + i,
                        function=fn.name,
                        detail=f"除数 '{d}' 未识别到明确的非零保护。",
                        code=code,
                    )
                )
                continue

            floating_ids = [
                var
                for var in ids
                if var in floating_params or is_likely_floating_identifier(var, body_lines_mask, i)
            ]
            likely_floating = looks_like_floating_expr(d) or bool(floating_ids)
            if not likely_floating:
                continue

            has_near_zero_guard = guarded_nonzero_by_expr_cond or has_expr_small_value_guard(
                d, body_lines_mask, i
            )
            if not expr_requires_expression_guard:
                has_near_zero_guard = has_near_zero_guard or any(
                    has_small_value_guard(var, body_lines_mask, i, line_conds)
                    for var in floating_ids
                )
            if not has_near_zero_guard and line_conds and not expr_requires_expression_guard:
                vars_for_cond = floating_ids if floating_ids else ids
                has_near_zero_guard = any(
                    condition_implies_away_from_zero(var, cond, SMALL_DENOMINATOR_EPS)
                    for var in vars_for_cond
                    for cond in line_conds
                )
            if has_near_zero_guard:
                continue

            code = body_lines_orig[i].strip() if i < len(body_lines_orig) else ""
            findings.append(
                Finding(
                    risk_type="small_denominator_risk",
                    file=fn.file,
                    line=fn.start_line + 1 + i,
                    function=fn.name,
                    detail=(
                        f"除数 '{d}' 仅做了非零检查；未识别到围绕 "
                        f"{SMALL_DENOMINATOR_EPS:.0e} 的近零保护。"
                    ),
                    code=code,
                )
            )
    return findings


def dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[Tuple[str, int, str, str]] = set()
    for f in findings:
        key = (f.file, f.line, f.function, f.risk_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan(paths: Sequence[str], declared_only: bool = False) -> dict:
    files = collect_files(paths)
    if not files:
        raise FileNotFoundError("输入路径下未找到 .h/.hpp/.hh/.hxx/.cpp/.cc/.cxx 文件。")

    header_files = [f for f in files if f.suffix.lower() in HEADER_EXTS]
    interface_names: Set[str] = set()
    for h in header_files:
        interface_names.update(extract_declared_interface_names(h))

    functions: List[FunctionInfo] = []
    for f in files:
        functions.extend(extract_function_definitions(f))

    if declared_only and interface_names:
        target_functions = [fn for fn in functions if fn.base_name in interface_names]
    else:
        target_functions = functions

    findings: List[Finding] = []
    for fn in target_functions:
        findings.extend(detect_null_pointer_risks(fn))
        findings.extend(detect_out_of_bounds_risks(fn))
        findings.extend(detect_divide_by_zero_risks(fn))

    findings = sorted(
        dedupe_findings(findings),
        key=lambda x: (x.file.lower(), x.line, x.function, x.risk_type),
    )

    null_count = sum(1 for f in findings if f.risk_type == "null_pointer_risk")
    oob_count = sum(1 for f in findings if f.risk_type == "out_of_bounds_risk")
    divide_total_count = sum(
        1 for f in findings if f.risk_type in {"divide_by_zero_risk", "small_denominator_risk"}
    )

    summary = {
        "null_pointer_risk": null_count,
        "out_of_bounds_risk": oob_count,
        # Unified count: includes near-zero denominator findings.
        "divide_by_zero_risk": divide_total_count,
    }
    findings_dicts: List[dict] = []
    for f in findings:
        row = asdict(f)
        row["risk_type_zh"] = RISK_TYPE_ZH.get(f.risk_type, f.risk_type)
        findings_dicts.append(row)

    summary_zh = {
        "空指针风险": null_count,
        "数组越界风险": oob_count,
        "除0风险": divide_total_count,
    }
    scan_mode = "declared_only" if declared_only else "all_definitions"

    return {
        "scan_mode": scan_mode,
        "scan_mode_zh": SCAN_MODE_ZH.get(scan_mode, scan_mode),
        "scanned_files": [str(f) for f in files],
        "scanned_function_count": len(target_functions),
        "interface_function_name_count": len(interface_names),
        "summary": summary,
        "summary_zh": summary_zh,
        "findings": findings_dicts,
    }


def print_text_report(report: dict) -> None:
    findings = report.get("findings", [])
    null_risks = [f for f in findings if f.get("risk_type") == "null_pointer_risk"]
    oob_risks = [f for f in findings if f.get("risk_type") == "out_of_bounds_risk"]
    div_risks = [
        f
        for f in findings
        if f.get("risk_type") in {"divide_by_zero_risk", "small_denominator_risk"}
    ]
    cwd = Path.cwd().resolve()

    def display_file(path_text: str) -> str:
        if not path_text:
            return "未知文件"
        p = Path(path_text)
        try:
            return str(p.resolve().relative_to(cwd))
        except Exception:
            return str(p)

    print("====空指针访问风险====")
    print(f"共计{len(null_risks)}处")
    for i, f in enumerate(null_risks, start=1):
        m = re.search(r"指针参数\s+'([^']+)'", f.get("detail", ""))
        var_name = m.group(1) if m else "未知"
        file_text = display_file(f.get("file", ""))
        print(f"{i}. 文件{file_text}，{f['function']}接口{f['line']}行，变量{var_name}")

    print("====数组越界访问风险====")
    print(f"共计{len(oob_risks)}处")
    for i, f in enumerate(oob_risks, start=1):
        file_text = display_file(f.get("file", ""))
        print(f"{i}. 文件{file_text}，{f['function']}接口{f['line']}行")

    print("====除0风险====")
    print(f"共计{len(div_risks)}处")
    for i, f in enumerate(div_risks, start=1):
        file_text = display_file(f.get("file", ""))
        print(f"{i}. 文件{file_text}，{f['function']}接口{f['line']}行")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="C/C++ 启发式风险扫描工具（.h/.cpp）")
    parser.add_argument("paths", nargs="+", help="输入文件或目录。")
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="兼容旧参数。当前默认已扫描全部函数定义。",
    )
    parser.add_argument(
        "--declared-only",
        action="store_true",
        help="仅扫描输入路径中头文件声明过名字的函数定义。",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出 JSON 结果。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    declared_only = args.declared_only
    report = scan(args.paths, declared_only=declared_only)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_text_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
