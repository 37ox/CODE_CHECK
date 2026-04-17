#!/usr/bin/env python3
"""
Simple GUI for cpp_risk_scanner.

Layout:
- Upper area: output
- Lower area: actions (choose folder + run scan)
"""

from __future__ import annotations

import contextlib
import importlib
import io
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from typing import Dict

import cpp_risk_scanner as scanner_mod


SUPPORTED_TYPES_TEXT = ".h/.hpp/.hh/.hxx/.cpp/.cc/.cxx"


def run_scan(folder: str) -> Dict:
    global scanner_mod
    scanner_mod = importlib.reload(scanner_mod)

    folder_abs = str(Path(folder).resolve())
    return scanner_mod.scan([folder_abs], declared_only=False)


def render_cli_text(report: Dict) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        scanner_mod.print_text_report(report)
    return buf.getvalue()


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

        tk.Label(action_frame, text="当前目录:").pack(anchor="w", padx=12, pady=(10, 2))

        self.path_entry = tk.Entry(action_frame, textvariable=self.selected_dir)
        self.path_entry.pack(fill=tk.X, padx=12, pady=(0, 8))

        btn_row = tk.Frame(action_frame)
        btn_row.pack(fill=tk.X, padx=12, pady=(0, 10))

        self.choose_btn = tk.Button(btn_row, text="选择文件夹", command=self._choose_folder, width=14)
        self.choose_btn.pack(side=tk.LEFT)

        self.scan_btn = tk.Button(btn_row, text="开始接口提取校验", command=self._start_scan, width=18)
        self.scan_btn.pack(side=tk.LEFT, padx=(10, 0))

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
            messagebox.showerror("错误", "请选择有效目录。")
            return

        self._set_scanning(True)
        self._set_output("正在扫描，请稍候...\n")
        threading.Thread(target=self._scan_worker, args=(folder,), daemon=True).start()

    def _scan_worker(self, folder: str) -> None:
        try:
            report = run_scan(folder)
            text = render_cli_text(report)
            self.after(0, lambda: self._finish_scan(text, ""))
        except Exception as exc:  # pragma: no cover
            err = f"{exc}\n\n{traceback.format_exc()}"
            self.after(0, lambda: self._finish_scan("", err))

    def _finish_scan(self, text: str, error_msg: str) -> None:
        if error_msg:
            self._set_output(f"扫描失败:\n{error_msg}")
        else:
            self._set_output(text)
        self._set_scanning(False)

    def _set_scanning(self, scanning: bool) -> None:
        self.is_scanning = scanning
        state = tk.DISABLED if scanning else tk.NORMAL
        self.choose_btn.config(state=state)
        self.scan_btn.config(state=state)
        self.scan_btn.config(text="扫描中..." if scanning else "开始接口提取校验")

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
