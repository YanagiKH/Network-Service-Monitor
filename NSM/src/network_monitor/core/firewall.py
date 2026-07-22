from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class 防火牆結果:
    成功: bool
    訊息: str
    規則名: str = ""


_PREFIX = "NetworkServiceMonitor"


def _規則名(pid: int, exe_path: str) -> str:
    檔名 = Path(exe_path).name if exe_path else f"PID_{pid}"
    return f"{_PREFIX}_{pid}_{檔名}"


def _執行命令(args: list[str]) -> tuple[int, str]:
    completed = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="ignore", check=False)
    return completed.returncode, completed.stdout + completed.stderr


def 封鎖程序(pid: int, exe_path: str) -> 防火牆結果:
    if not exe_path or not Path(exe_path).exists():
        return 防火牆結果(False, "找不到可封鎖的程序路徑")
    name = _規則名(pid, exe_path)
    code, output = _執行命令([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=out",
        "action=block",
        f"program={exe_path}",
        "enable=yes",
        "profile=any",
    ])
    if code == 0:
        return 防火牆結果(True, "已建立防火牆封鎖規則", name)
    return 防火牆結果(False, f"封鎖失敗：{output.strip() or code}", name)


def 解除封鎖程序(pid: int, exe_path: str) -> 防火牆結果:
    name = _規則名(pid, exe_path)
    code, output = _執行命令([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name}",
    ])
    if code == 0:
        return 防火牆結果(True, "已移除防火牆封鎖規則", name)
    return 防火牆結果(False, f"解除失敗：{output.strip() or code}", name)


def 查詢規則(pid: int, exe_path: str) -> str:
    return _規則名(pid, exe_path)
