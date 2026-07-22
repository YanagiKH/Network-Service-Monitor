from __future__ import annotations

import csv
import subprocess
from functools import lru_cache


@lru_cache(maxsize=1)
def 取得服務映射() -> dict[int, list[str]]:
    映射: dict[int, list[str]] = {}
    try:
        行 = subprocess.run(
            ["tasklist", "/svc", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        ).stdout.splitlines()
        for row in csv.reader(行):
            if len(row) < 2:
                continue
            名稱 = row[0].strip()
            pid_text = row[1].strip()
            服務欄 = row[2].strip() if len(row) > 2 else ""
            try:
                pid = int(pid_text)
            except Exception:
                continue
            服務清單 = []
            if 服務欄 and 服務欄 not in ("N/A", '"N/A"'):
                服務清單 = [x.strip() for x in 服務欄.split(",") if x.strip()]
            if 服務清單:
                映射.setdefault(pid, []).extend(服務清單)
    except Exception:
        pass
    return 映射


def 取得服務名稱(pid: int | None) -> str:
    if not pid:
        return "-"
    映射 = 取得服務映射()
    名稱 = 映射.get(pid, [])
    if 名稱:
        去重後 = list(dict.fromkeys(名稱))
        return ", ".join(去重後)
    return "-"
