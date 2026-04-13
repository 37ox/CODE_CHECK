#!/usr/bin/env python3
"""
Tkinter GUI wrapper for cpp_risk_scanner.

UI layout:
- Upper area: report output
- Lower area: operations (choose folder + scan)
"""

from __future__ import annotations

import re
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from typing import Callable, Dict, List

from cpp_risk_scanner import scan


SUPPORTED_TYPES_TEXT = ".h/.hpp/.hh/.hxx/.cpp/.cc/.cxx"


def format_report_for_ui(report: Dict, folder: str) -> str:
    findings = report.get("findings", [])
    null_risks = [f for f in findings if f.get("risk_type") == "null_pointer_risk"]
    oob_risks = [f for f in findings if f.get("risk_type") == "out_of_bounds_risk"]
    div_risks = [
        f
        for f in findings
        if f.get("risk_type") in {"divide_by_zero_risk", "small_denominator_risk"}
    ]
    base_dir = Path(folder).resolve()

    def display_file(path_text: str) -> str:
        if not path_text:
            return "未知文件"
        p = Path(path_text)
        try:
            return str(p.resolve().relative_to(base_dir))
        except Exception:
            return str(p)

    lines: List[str] = [
        f"扫描目录: {folder}",
        f"扫描模式: {report.get('scan_mode_zh', report.get('scan_mode', '未知'))}",
        f"匹配文件类型: {SUPPORTED_TYPES_TEXT}",
        f"扫描文件数量: {len(report.get('scanned_files', []))}",
        f"扫描函数数量: {report.get('scanned_function_count', 0)}",
        "",
    ]

    def append_section(title: str, items: List[Dict], row_builder: Callable[[Dict], str]) -> None:
        lines.append(f"===={title}====")
        lines.append(f"共计{len(items)}处")
        for idx, item in enumerate(items, start=1):
            lines.append(f"{idx}. {row_builder(item)}")
        lines.append("")

    def null_row(item: Dict) -> str:
        m = re.search(r"指针参数\s+'([^']+)'", item.get("detail", ""))
        var_name = m.group(1) if m else "未知"
        file_text = display_file(item.get("file", ""))
        return (
            f"文件{file_text}，"
            f"{item.get('function', '未知')}接口{item.get('line', '未知')}行，变量{var_name}"
        )

    append_section("空指针访问风险", null_risks, null_row)
    append_section(
        "数组越界访问风险",
        oob_risks,
        lambda f: (
            f"文件{display_file(f.get('file', ''))}，"
            f"{f.get('function', '未知')}接口{f.get('line', '未知')}行"
        ),
    )
    append_section(
        "除0风险",
        div_risks,
        lambda f: (
            f"文件{display_file(f.get('file', ''))}，"
            f"{f.get('function', '未知')}接口{f.get('line', '未知')}行"
        ),
    )

    if findings:
        lines.append("----详细信息----")
        for idx, item in enumerate(findings, start=1):
            risk_label = item.get("risk_type_zh", item.get("risk_type", "未知风险"))
            file_text = display_file(item.get("file", ""))
            lines.append(
                f"{idx}. [{risk_label}] 文件{file_text} "
                f"{item.get('function', '未知')}:{item.get('line', '未知')}"
            )
            lines.append(f"   {item.get('detail', '')}")
            code = item.get("code", "")
            if code:
                lines.append(f"   代码: {code}")
        lines.append("")
    else:
        lines.append("未发现风险。")

    return "\n".join(lines).strip() + "\n"


class ScannerGuiApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("C/C++ 风险扫描工具")
        self.geometry("980x700")
        self.minsize(820, 560)

        self.selected_dir = tk.StringVar(value="")
        self.is_scanning = False

        self._build_ui()

    def _build_ui(self) -> None:
        output_frame = tk.Frame(self)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 6))

        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self._set_output(
            "请选择一个目录，然后点击“开始接口提取校验”。\n"
            f"当前支持文件类型: {SUPPORTED_TYPES_TEXT}\n"
        )

        action_frame = tk.Frame(self, relief=tk.GROOVE, borderwidth=1, height=120)
        action_frame.pack(fill=tk.X, expand=False, padx=10, pady=(0, 10))
        action_frame.pack_propagate(False)

        path_label = tk.Label(action_frame, text="当前目录:")
        path_label.pack(anchor="w", padx=12, pady=(10, 2))

        self.path_entry = tk.Entry(action_frame, textvariable=self.selected_dir)
        self.path_entry.pack(fill=tk.X, padx=12, pady=(0, 8))

        button_row = tk.Frame(action_frame)
        button_row.pack(fill=tk.X, padx=12, pady=(0, 10))

        self.choose_button = tk.Button(button_row, text="选择文件夹", command=self._choose_folder, width=14)
        self.choose_button.pack(side=tk.LEFT)

        self.scan_button = tk.Button(
            button_row,
            text="开始接口提取校验",
            command=self._start_scan,
            width=18,
        )
        self.scan_button.pack(side=tk.LEFT, padx=(10, 0))

    def _choose_folder(self) -> None:
        chosen = filedialog.askdirectory(title="选择待扫描目录")
        if chosen:
            self.selected_dir.set(chosen)

    def _start_scan(self) -> None:
        if self.is_scanning:
            return

        folder = self.selected_dir.get().strip()
        if not folder:
            messagebox.showwarning("提示", "请先选择文件夹。")
            return

        p = Path(folder)
        if not p.exists() or not p.is_dir():
            messagebox.showerror("错误", "请选择有效的目录路径。")
            return

        self._set_scanning(True)
        self._set_output("正在扫描，请稍候...\n")

        worker = threading.Thread(target=self._scan_worker, args=(folder,), daemon=True)
        worker.start()

    def _scan_worker(self, folder: str) -> None:
        try:
            report = scan([folder], declared_only=False)
            text = format_report_for_ui(report, folder)
            self.after(0, lambda: self._finish_scan(text=text, error_msg=""))
        except Exception as exc:  # pragma: no cover
            err = f"{exc}\n\n{traceback.format_exc()}"
            self.after(0, lambda: self._finish_scan(text="", error_msg=err))

    def _finish_scan(self, text: str, error_msg: str) -> None:
        if error_msg:
            self._set_output(f"扫描失败:\n{error_msg}")
        else:
            self._set_output(text)
        self._set_scanning(False)

    def _set_scanning(self, scanning: bool) -> None:
        self.is_scanning = scanning
        state = tk.DISABLED if scanning else tk.NORMAL
        self.choose_button.config(state=state)
        self.scan_button.config(state=state)
        self.scan_button.config(text="扫描中..." if scanning else "开始接口提取校验")

    def _set_output(self, text: str) -> None:
        self.output_text.configure(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.configure(state=tk.DISABLED)


def main() -> int:
    app = ScannerGuiApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
