from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional

from ..utils.formatters import 安全判斷位址, 風險等級文字


@dataclass
class 安全分析:
    風險分數: int
    風險等級: str
    反向DNS: str
    位址類型: str
    服務提示: str
    判斷說明: str


_常見安全埠 = {53, 80, 123, 135, 137, 138, 139, 143, 389, 443, 465, 587, 993, 995, 3074, 5228, 5229, 5230, 6667}
_常見程序 = {
    "chrome.exe", "msedge.exe", "firefox.exe", "discord.exe", "steam.exe", "onedrive.exe",
    "teams.exe", "slack.exe", "spotify.exe", "code.exe", "python.exe", "pythonw.exe",
    "explorer.exe", "svchost.exe", "System", "System Idle Process", "RuntimeBroker.exe",
    "dwm.exe", "audiodg.exe", "nvcontainer.exe", "googledrivefs.exe"
}


def _反向解析(ip: str | None) -> str:
    if not ip:
        return "-"
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return "-"


def _服務提示(port: int | None, proc_name: str | None) -> str:
    if proc_name and proc_name.lower() in _常見程序:
        return f"已知程序：{proc_name}"
    if port in _常見安全埠:
        return f"常見連接埠：{port}"
    if port == 0 or port is None:
        return "未建立遠端連線"
    return f"遠端埠：{port}"


def 分析連線(remote_ip: str | None, remote_port: int | None, proc_name: str | None, exe_path: str | None) -> 安全分析:
    位址類型 = 安全判斷位址(remote_ip)
    score = 5
    說明 = []

    if remote_ip:
        if 位址類型 == "內網":
            score += 2
            說明.append("內網位址")
        elif 位址類型 == "外網":
            score += 18
            說明.append("外網位址")
        elif 位址類型 == "回環":
            score -= 2
            說明.append("本機回環")
    else:
        說明.append("未連至遠端")

    if remote_port in _常見安全埠:
        score += 5
        說明.append("常見服務埠")
    elif remote_port and remote_port not in (0, 1, 2, 3):
        score += 10
        說明.append("非典型埠")

    if proc_name:
        if proc_name.lower() in {x.lower() for x in _常見程序}:
            score -= 8
            說明.append("常見程序")
        else:
            score += 8
            說明.append("未知程序")

    if exe_path:
        路徑 = exe_path.lower()
        if any(k in 路徑 for k in ("\\windows\\", "\\program files\\", "\\program files (x86)\\")):
            score -= 6
            說明.append("常見安裝路徑")
        else:
            score += 10
            說明.append("非典型路徑")

    score = max(0, min(100, score))
    return 安全分析(
        風險分數=score,
        風險等級=風險等級文字(score),
        反向DNS=_反向解析(remote_ip),
        位址類型=位址類型,
        服務提示=_服務提示(remote_port, proc_name),
        判斷說明="、".join(說明) if 說明 else "無",
    )
