from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import socket

import psutil

from ..storage.資料庫 import 儲存庫
from ..utils.formatters import 時間格式, 協定名稱
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


def _連線鍵(proto: str, laddr: tuple[str, int] | None, raddr: tuple[str, int] | None, pid: int | None) -> str:
    return f"{proto}|{pid or 0}|{laddr[0] if laddr else ''}:{laddr[1] if laddr else ''}|{raddr[0] if raddr else ''}:{raddr[1] if raddr else ''}"


def _安全取值(fn, 預設=None):
    try:
        return fn()
    except Exception:
        return 預設


def _取得程序摘要(pid: int | None, 快取: dict[int, dict[str, Any]]) -> dict[str, Any]:
    if not pid:
        return {
            "程序名稱": "-",
            "程序路徑": "-",
            "命令列": "-",
            "使用者": "-",
            "建立時間": None,
            "CPU": None,
            "記憶體MB": None,
            "線程數": None,
            "開啟檔案數": None,
        }

    if pid in 快取:
        return 快取[pid]

    try:
        proc = psutil.Process(pid)
        程序名稱 = _安全取值(proc.name, "-")
        程序路徑 = _安全取值(proc.exe, "-")
        命令列清單 = _安全取值(proc.cmdline, [])
        使用者 = _安全取值(proc.username, "-")
        建立時間 = _安全取值(proc.create_time, None)

        # 這些值只對「唯一 PID」取一次，避免對每條連線重複呼叫造成掃描變慢
        cpu = _安全取值(lambda: proc.cpu_percent(interval=None), None)
        記憶體 = _安全取值(lambda: proc.memory_info().rss / (1024 * 1024), None)
        線程數 = _安全取值(proc.num_threads, None)
        開啟檔案數 = None

        摘要 = {
            "程序名稱": 程序名稱,
            "程序路徑": 程序路徑,
            "命令列": " ".join(命令列清單) if 命令列清單 else "-",
            "使用者": 使用者,
            "建立時間": 建立時間,
            "CPU": cpu,
            "記憶體MB": 記憶體,
            "線程數": 線程數,
            "開啟檔案數": 開啟檔案數,
        }
    except Exception:
        摘要 = {
            "程序名稱": "-",
            "程序路徑": "-",
            "命令列": "-",
            "使用者": "-",
            "建立時間": None,
            "CPU": None,
            "記憶體MB": None,
            "線程數": None,
            "開啟檔案數": None,
        }

    快取[pid] = 摘要
    return 摘要


def 掃描連線() -> list[連線資料]:
    儲存 = 儲存庫()
    備註映射 = 儲存.讀取所有備註()
    結果: list[連線資料] = []
    程序快取: dict[int, dict[str, Any]] = {}

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []

    for conn in conns:
        try:
            pid = conn.pid
            摘要 = _取得程序摘要(pid, 程序快取)

            laddr = conn.laddr if conn.laddr else None
            raddr = conn.raddr if conn.raddr else None

            local_ip = laddr.ip if laddr else "-"
            local_port = laddr.port if laddr else None
            remote_ip = raddr.ip if raddr else "-"
            remote_port = raddr.port if raddr else None

            family_kind = "inet6" if conn.family == socket.AF_INET6 else "inet"
            proto = 協定名稱(family_kind, "tcp" if getattr(conn.type, "name", "").endswith("STREAM") else "udp")

            path = 摘要["程序路徑"]
            cmd = 摘要["命令列"]
            user = 摘要["使用者"]
            create_time = 時間格式(摘要["建立時間"])

            sec = 分析連線(
                remote_ip if remote_ip != "-" else None,
                remote_port,
                摘要["程序名稱"],
                path if path != "-" else None,
            )

            key = _連線鍵(proto, laddr, raddr, pid)
            note, tag = 備註映射.get(key, ("", ""))

            結果.append(
                連線資料(
                    鍵=key,
                    pid=pid,
                    程序名稱=摘要["程序名稱"],
                    服務名稱=取得服務名稱(pid),
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
                    CPU=摘要["CPU"],
                    記憶體MB=摘要["記憶體MB"],
                    線程數=摘要["線程數"],
                    開啟檔案數=摘要["開啟檔案數"],
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

    結果.sort(key=lambda x: (x.風險分數, x.pid or 0, x.程序名稱, x.遠端位址), reverse=True)
    return 結果
