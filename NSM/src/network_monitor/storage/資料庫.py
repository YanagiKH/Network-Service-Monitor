from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Optional


def _資料庫路徑() -> Path:
    根目錄 = Path(os.getenv("APPDATA", Path.home()))
    目錄 = 根目錄 / "NetworkServiceMonitor"
    目錄.mkdir(parents=True, exist_ok=True)
    return 目錄 / "data.sqlite3"


class 儲存庫:
    def __init__(self) -> None:
        self.路徑 = _資料庫路徑()
        self._初始化()

    def _連線(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.路徑)
        conn.row_factory = sqlite3.Row
        return conn

    def _初始化(self) -> None:
        with self._連線() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS 連線備註 (
                    鍵 TEXT PRIMARY KEY,
                    備註 TEXT NOT NULL DEFAULT '',
                    標記 TEXT NOT NULL DEFAULT '',
                    最後更新時間 REAL NOT NULL DEFAULT (strftime('%s', 'now'))
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS 防火牆規則 (
                    規則名 TEXT PRIMARY KEY,
                    程序路徑 TEXT NOT NULL,
                    PID INTEGER NOT NULL,
                    建立時間 REAL NOT NULL DEFAULT (strftime('%s', 'now'))
                )
                """
            )

    def 讀取備註(self, 鍵: str) -> tuple[str, str]:
        with self._連線() as conn:
            row = conn.execute("SELECT 備註, 標記 FROM 連線備註 WHERE 鍵 = ?", (鍵,)).fetchone()
            if row:
                return str(row["備註"]), str(row["標記"])
            return "", ""

    def 儲存備註(self, 鍵: str, 備註: str, 標記: str) -> None:
        with self._連線() as conn:
            conn.execute(
                """
                INSERT INTO 連線備註 (鍵, 備註, 標記, 最後更新時間)
                VALUES (?, ?, ?, strftime('%s', 'now'))
                ON CONFLICT(鍵) DO UPDATE SET
                    備註=excluded.備註,
                    標記=excluded.標記,
                    最後更新時間=excluded.最後更新時間
                """,
                (鍵, 備註, 標記),
            )

    def 儲存防火牆規則(self, 規則名: str, 程序路徑: str, pid: int) -> None:
        with self._連線() as conn:
            conn.execute(
                """
                INSERT INTO 防火牆規則 (規則名, 程序路徑, PID, 建立時間)
                VALUES (?, ?, ?, strftime('%s', 'now'))
                ON CONFLICT(規則名) DO UPDATE SET
                    程序路徑=excluded.程序路徑,
                    PID=excluded.PID,
                    建立時間=excluded.建立時間
                """,
                (規則名, 程序路徑, pid),
            )

    def 刪除防火牆規則(self, 規則名: str) -> None:
        with self._連線() as conn:
            conn.execute("DELETE FROM 防火牆規則 WHERE 規則名 = ?", (規則名,))

    def 讀取所有防火牆規則(self) -> list[sqlite3.Row]:
        with self._連線() as conn:
            return list(conn.execute("SELECT * FROM 防火牆規則 ORDER BY 建立時間 DESC"))

    def 讀取所有備註(self) -> dict[str, tuple[str, str]]:
        with self._連線() as conn:
            rows = conn.execute("SELECT 鍵, 備註, 標記 FROM 連線備註").fetchall()
        return {str(row["鍵"]): (str(row["備註"]), str(row["標記"])) for row in rows}
