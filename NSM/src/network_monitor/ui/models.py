from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex, QVariant

from ..core.scanner import 連線資料
from ..utils.formatters import 位元組格式


欄位名稱 = [
    "程序/服務",
    "PID",
    "協定",
    "狀態",
    "本地位址",
    "遠端位址",
    "風險",
    "反向DNS",
    "程序路徑",
    "備註",
    "標記",
]

_ATTR_MAP = {
    0: lambda x: f"{x.程序名稱}\n{x.服務名稱}",
    1: lambda x: x.pid or "-",
    2: lambda x: x.協定,
    3: lambda x: x.狀態,
    4: lambda x: x.本地位址,
    5: lambda x: x.遠端位址,
    6: lambda x: f"{x.風險分數} / {x.風險等級}",
    7: lambda x: x.反向DNS,
    8: lambda x: x.程序路徑,
    9: lambda x: x.備註,
    10: lambda x: x.標記,
}


class 連線表模型(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._資料: list[連線資料] = []

    def 設定資料(self, items: list[連線資料]) -> None:
        self.beginResetModel()
        self._資料 = items
        self.endResetModel()

    def 取資料(self, row: int) -> 連線資料 | None:
        if 0 <= row < len(self._資料):
            return self._資料[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._資料)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(欄位名稱)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()
        row = index.row()
        col = index.column()
        if row >= len(self._資料):
            return QVariant()
        item = self._資料[row]
        if role == Qt.ItemDataRole.DisplayRole:
            try:
                return _ATTR_MAP[col](item)
            except Exception:
                return ""
        if role == Qt.ItemDataRole.ToolTipRole:
            return f"{item.程序名稱} / {item.服務名稱}\n{item.命令列}\n{item.判斷說明}"
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (1, 6):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if role == Qt.ItemDataRole.UserRole:
            return item
        return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return 欄位名稱[section]
        return QVariant()
