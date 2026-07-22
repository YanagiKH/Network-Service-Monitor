from __future__ import annotations

import math
import ipaddress
from datetime import datetime, timezone


def 位元組格式(value: int | float | None) -> str:
    if value is None:
        return "-"
    try:
        v = float(value)
    except Exception:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if abs(v) < 1024.0:
            return f"{v:,.1f} {unit}"
        v /= 1024.0
    return f"{v:,.1f} PB"


def 百分比格式(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.1f}%"


def 時間格式(timestamp: float | None) -> str:
    if not timestamp:
        return "-"
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


def 絕對時間格式(timestamp: float | None) -> str:
    if not timestamp:
        return "-"
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


def 協定名稱(kind: str, proto: str) -> str:
    if kind == "inet6":
        return f"{proto.upper()}6"
    return proto.upper()


def 安全判斷位址(addr: str | None) -> str:
    if not addr:
        return "未知"
    try:
        ip = ipaddress.ip_address(addr)
        if ip.is_loopback:
            return "回環"
        if ip.is_private:
            return "內網"
        if ip.is_link_local:
            return "區域鏈路"
        if ip.is_multicast:
            return "多播"
        return "外網"
    except Exception:
        return "未知"


def 風險等級文字(score: int) -> str:
    if score >= 80:
        return "高"
    if score >= 50:
        return "中"
    if score >= 20:
        return "低"
    return "極低"


def 選擇字串(*values: str | None) -> str:
    for value in values:
        if value:
            return value
    return "-"
