from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import psutil


@dataclass
class 動作結果:
    成功: bool
    訊息: str


def 取得程序(pid: int) -> Optional[psutil.Process]:
    try:
        return psutil.Process(pid)
    except Exception:
        return None


def 終止程序(pid: int) -> 動作結果:
    proc = 取得程序(pid)
    if not proc:
        return 動作結果(False, "找不到程序")
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        return 動作結果(True, "已終止程序")
    except Exception as exc:
        return 動作結果(False, f"終止失敗：{exc}")


def 暫停程序(pid: int) -> 動作結果:
    proc = 取得程序(pid)
    if not proc:
        return 動作結果(False, "找不到程序")
    try:
        proc.suspend()
        return 動作結果(True, "已暫停程序")
    except Exception as exc:
        return 動作結果(False, f"暫停失敗：{exc}")


def 恢復程序(pid: int) -> 動作結果:
    proc = 取得程序(pid)
    if not proc:
        return 動作結果(False, "找不到程序")
    try:
        proc.resume()
        return 動作結果(True, "已恢復程序")
    except Exception as exc:
        return 動作結果(False, f"恢復失敗：{exc}")


def 開啟檔案位置(path: str) -> 動作結果:
    if not path:
        return 動作結果(False, "沒有可開啟的路徑")
    try:
        subprocess.Popen(["explorer", "/select,", path])
        return 動作結果(True, "已開啟檔案位置")
    except Exception as exc:
        return 動作結果(False, f"開啟失敗：{exc}")


def 開啟命令列(pid: int) -> 動作結果:
    proc = 取得程序(pid)
    if not proc:
        return 動作結果(False, "找不到程序")
    try:
        command = proc.cmdline()
        if not command:
            return 動作結果(False, "沒有命令列資訊")
        text = " ".join(command)
        return 動作結果(True, text)
    except Exception as exc:
        return 動作結果(False, f"讀取命令列失敗：{exc}")
