from __future__ import annotations

import os
import socket
from dataclasses import dataclass, asdict
from typing import Optional

import psutil
import socket

from ..storage.資料庫 import 儲存庫
from ..utils.formatters import 位元組格式, 時間格式, 協定名稱, 選擇字串
from .services import 取得服務名稱
from .security import 分析連線


@dataclass
class 連線資料:
    鍵: str
    pid: int | None
    程序名稱: str
    服務名稱: str
    協定: str
    狀態: str
    本地位址: str
    本地埠: int | None
    遠端位址: str
    遠端埠: int | None
    程序路徑: str
    命令列: str
    使用者: str
    建立時間: str
    CPU: float | None
    記憶體MB: float | None
    線程數: int | None
    開啟檔案數: int | None
    風險分數: int
    風險等級: str
    反向DNS: str
    位址類型: str
    服務提示: str
    判斷說明: str
    備註: str = ""
    標記: str = ""


def _取得程序資訊(pid: int | None):
    if not pid:
        return None
    try:
        return psutil.Process(pid)
    except Exception:
        return None


def _命令列(proc: psutil.Process | None) -> str:
    if not proc:
        return "-"
    try:
        cmd = proc.cmdline()
        return " ".join(cmd) if cmd else "-"
    except Exception:
        return "-"


def _使用者(proc: psutil.Process | None) -> str:
    if not proc:
        return "-"
    try:
        return proc.username()
    except Exception:
        return "-"


def _路徑(proc: psutil.Process | None) -> str:
    if not proc:
        return "-"
    try:
        return proc.exe()
    except Exception:
        return "-"


def _名稱(proc: psutil.Process | None) -> str:
    if not proc:
        return "-"
    try:
        return proc.name()
    except Exception:
        return "-"


def _資源(proc: psutil.Process | None) -> tuple[float | None, float | None, int | None, int | None]:
    if not proc:
        return None, None, None, None
    try:
        cpu = proc.cpu_percent(interval=None)
    except Exception:
        cpu = None
    try:
        mem = proc.memory_info().rss / (1024 * 1024)
    except Exception:
        mem = None
    try:
        th = proc.num_threads()
    except Exception:
        th = None
    try:
        of = len(proc.open_files())
    except Exception:
        of = None
    return cpu, mem, th, of


def _連線鍵(proto: str, laddr: tuple[str, int] | None, raddr: tuple[str, int] | None, pid: int | None) -> str:
    return f"{proto}|{pid or 0}|{laddr[0] if laddr else ''}:{laddr[1] if laddr else ''}|{raddr[0] if raddr else ''}:{raddr[1] if raddr else ''}"


def 掃描連線() -> list[連線資料]:
    儲存 = 儲存庫()
    備註映射 = 儲存.讀取所有備註()
    結果: list[連線資料] = []

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []

    for conn in conns:
        try:
            pid = conn.pid
            proc = _取得程序資訊(pid)
            proc_name = _名稱(proc)
            service_name = 取得服務名稱(pid)
            laddr = conn.laddr if conn.laddr else None
            raddr = conn.raddr if conn.raddr else None
            local_ip = laddr.ip if laddr else "-"
            local_port = laddr.port if laddr else None
            remote_ip = raddr.ip if raddr else "-"
            remote_port = raddr.port if raddr else None
            family_kind = "inet6" if conn.family == socket.AF_INET6 else "inet"
            proto = 協定名稱(family_kind, "tcp" if getattr(conn.type, "name", "").endswith("STREAM") else "udp")
            path = _路徑(proc)
            cmd = _命令列(proc)
            user = _使用者(proc)
            create_time = 時間格式(proc.create_time() if proc else None)
            cpu, mem, th, of = _資源(proc)
            sec = 分析連線(remote_ip if remote_ip != "-" else None, remote_port, proc_name, path if path != "-" else None)
            key = _連線鍵(proto, laddr, raddr, pid)
            note, tag = 備註映射.get(key, ("", ""))
            結果.append(
                連線資料(
                    鍵=key,
                    pid=pid,
                    程序名稱=proc_name,
                    服務名稱=service_name,
                    協定=proto,
                    狀態=str(conn.status),
                    本地位址=f"{local_ip}:{local_port}" if local_port is not None else local_ip,
                    本地埠=local_port,
                    遠端位址=f"{remote_ip}:{remote_port}" if remote_port is not None else remote_ip,
                    遠端埠=remote_port,
                    程序路徑=path,
                    命令列=cmd,
                    使用者=user,
                    建立時間=create_time,
                    CPU=cpu,
                    記憶體MB=mem,
                    線程數=th,
                    開啟檔案數=of,
                    風險分數=sec.風險分數,
                    風險等級=sec.風險等級,
                    反向DNS=sec.反向DNS,
                    位址類型=sec.位址類型,
                    服務提示=sec.服務提示,
                    判斷說明=sec.判斷說明,
                    備註=note,
                    標記=tag,
                )
            )
        except Exception:
            continue

    def 排序鍵(x: 連線資料):
        return (x.風險分數, x.pid or 0, x.程序名稱, x.遠端位址)

    結果.sort(key=排序鍵, reverse=True)
    return 結果
