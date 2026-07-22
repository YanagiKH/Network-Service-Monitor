from __future__ import annotations

import os
from dataclasses import asdict
from typing import Optional

from PySide6.QtCore import Qt, QThreadPool, QRunnable, QObject, Signal, Slot, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QFont, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QPlainTextEdit, QProgressBar, QSplitter, QTableView, QTextEdit,
    QToolBar, QVBoxLayout, QWidget, QHeaderView, QAbstractItemView, QGroupBox, QFormLayout, QCheckBox,
    QSpinBox
)

from ..core.scanner import 掃描連線, 連線資料
from ..core.process_actions import 終止程序, 暫停程序, 恢復程序, 開啟檔案位置
from ..core.firewall import 封鎖程序, 解除封鎖程序, 查詢規則
from ..storage.資料庫 import 儲存庫
from .models import 連線表模型


class _信號(QObject):
    完成 = Signal(list)
    錯誤 = Signal(str)


class _掃描工作(QRunnable):
    def __init__(self, signal: _信號) -> None:
        super().__init__()
        self.signal = signal

    @Slot()
    def run(self) -> None:
        try:
            items = 掃描連線()
            self.signal.完成.emit(items)
        except Exception as exc:
            self.signal.錯誤.emit(str(exc))


class 主視窗(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Network Service Monitor")
        self.resize(1700, 980)
        self._儲存庫 = 儲存庫()
        self._模型 = 連線表模型()
        self._目前資料: list[連線資料] = []
        self._執行中 = False
        self._自動刷新 = True
        self._搜尋文字 = ""
        self._選中鍵: str | None = None
        self._執行緒池 = QThreadPool.globalInstance()
        self._信號 = _信號()
        self._信號.完成.connect(self._掃描完成)
        self._信號.錯誤.connect(self._顯示錯誤)
        self._建立介面()
        self._建立工具列()
        self._套用刷新()
        self._開始刷新計時器()

    def _建立介面(self) -> None:
        中央 = QWidget()
        主要布局 = QVBoxLayout(中央)
        主要布局.setContentsMargins(10, 10, 10, 10)
        主要布局.setSpacing(8)

        上方列 = QHBoxLayout()
        self.搜尋框 = QLineEdit()
        self.搜尋框.setPlaceholderText("搜尋程序、服務、PID、IP、路徑、標記...")
        self.搜尋框.textChanged.connect(self._更新搜尋)
        self.自動刷新勾選 = QCheckBox("自動刷新")
        self.自動刷新勾選.setChecked(True)
        self.自動刷新勾選.toggled.connect(self._切換自動刷新)
        self.刷新間隔 = QSpinBox()
        self.刷新間隔.setRange(1, 60)
        self.刷新間隔.setValue(2)
        self.刷新間隔.setSuffix(" 秒")
        self.刷新間隔.valueChanged.connect(self._套用刷新)
        self.刷新按鈕 = QPushButton("立即刷新")
        self.刷新按鈕.clicked.connect(self._立即刷新)
        上方列.addWidget(self.搜尋框, 1)
        上方列.addWidget(self.自動刷新勾選)
        上方列.addWidget(QLabel("間隔"))
        上方列.addWidget(self.刷新間隔)
        上方列.addWidget(self.刷新按鈕)
        主要布局.addLayout(上方列)

        分割 = QSplitter()
        分割.setOrientation(Qt.Orientation.Horizontal)

        左側 = QWidget()
        左布局 = QVBoxLayout(左側)
        左布局.setContentsMargins(0, 0, 0, 0)

        self.表格 = QTableView()
        self.表格.setModel(self._模型)
        self.表格.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.表格.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.表格.setAlternatingRowColors(True)
        self.表格.setSortingEnabled(False)
        self.表格.horizontalHeader().setStretchLastSection(True)
        self.表格.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.表格.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.表格.verticalHeader().setVisible(False)
        self.表格.clicked.connect(self._選中列)
        self.表格.doubleClicked.connect(self._編輯備註)
        self.表格.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)

        左布局.addWidget(self.表格)

        右側 = QWidget()
        右布局 = QVBoxLayout(右側)
        右布局.setContentsMargins(0, 0, 0, 0)

        self.標題 = QLabel("尚未選取連線")
        self.標題.setStyleSheet("font-size: 20px; font-weight: 700;")
        self.詳細 = QTextEdit()
        self.詳細.setReadOnly(True)
        self.詳細.setMinimumHeight(300)
        self.詳細.setPlainText("選取左側任一列以查看完整資訊。")

        控制框 = QGroupBox("管理控制")
        控制布局 = QVBoxLayout(控制框)
        按鈕列1 = QHBoxLayout()
        self.終止按鈕 = QPushButton("終止程序")
        self.暫停按鈕 = QPushButton("暫停程序")
        self.恢復按鈕 = QPushButton("恢復程序")
        self.開啟位置按鈕 = QPushButton("開啟位置")
        按鈕列1.addWidget(self.終止按鈕)
        按鈕列1.addWidget(self.暫停按鈕)
        按鈕列1.addWidget(self.恢復按鈕)
        按鈕列1.addWidget(self.開啟位置按鈕)

        按鈕列2 = QHBoxLayout()
        self.封鎖按鈕 = QPushButton("封鎖連線")
        self.解除封鎖按鈕 = QPushButton("解除封鎖")
        self.編輯備註按鈕 = QPushButton("編輯備註")
        self.複製資訊按鈕 = QPushButton("複製資訊")
        按鈕列2.addWidget(self.封鎖按鈕)
        按鈕列2.addWidget(self.解除封鎖按鈕)
        按鈕列2.addWidget(self.編輯備註按鈕)
        按鈕列2.addWidget(self.複製資訊按鈕)

        控制布局.addLayout(按鈕列1)
        控制布局.addLayout(按鈕列2)
        右布局.addWidget(self.標題)
        右布局.addWidget(self.詳細, 1)
        右布局.addWidget(控制框)

        self.封鎖按鈕.clicked.connect(self._封鎖選中)
        self.解除封鎖按鈕.clicked.connect(self._解除封鎖選中)
        self.終止按鈕.clicked.connect(self._終止選中)
        self.暫停按鈕.clicked.connect(self._暫停選中)
        self.恢復按鈕.clicked.connect(self._恢復選中)
        self.開啟位置按鈕.clicked.connect(self._開啟位置選中)
        self.編輯備註按鈕.clicked.connect(self._編輯備註)
        self.複製資訊按鈕.clicked.connect(self._複製資訊)

        分割.addWidget(左側)
        分割.addWidget(右側)
        分割.setSizes([1100, 600])
        主要布局.addWidget(分割, 1)

        下方 = QHBoxLayout()
        self.狀態標籤 = QLabel("準備就緒")
        self.進度條 = QProgressBar()
        self.進度條.setRange(0, 0)
        self.進度條.setVisible(False)
        下方.addWidget(self.狀態標籤, 1)
        下方.addWidget(self.進度條)
        主要布局.addLayout(下方)

        self.setCentralWidget(中央)

    def _建立工具列(self) -> None:
        工具列 = QToolBar("主要工具")
        工具列.setMovable(False)
        self.addToolBar(工具列)

        立即刷新 = QAction("刷新", self)
        立即刷新.triggered.connect(self._立即刷新)
        工具列.addAction(立即刷新)

        匯出 = QAction("複製選中資料", self)
        匯出.triggered.connect(self._複製資訊)
        工具列.addAction(匯出)

        退出 = QAction("退出", self)
        退出.triggered.connect(self.close)
        工具列.addAction(退出)

    def _開始刷新計時器(self) -> None:
        self.計時器 = QTimer(self)
        self.計時器.timeout.connect(self._立即刷新)
        self._套用刷新()

    def _套用刷新(self) -> None:
        秒數 = self.刷新間隔.value()
        self.計時器.setInterval(秒數 * 1000)
        if self.自動刷新勾選.isChecked():
            self.計時器.start()
        else:
            self.計時器.stop()

    def _切換自動刷新(self, enabled: bool) -> None:
        self._自動刷新 = enabled
        self._套用刷新()

    def _更新搜尋(self, text: str) -> None:
        self._搜尋文字 = text.strip().lower()
        self._套用篩選()

    def _立即刷新(self) -> None:
        if self._執行中:
            return
        self._執行中 = True
        self.進度條.setVisible(True)
        self.狀態標籤.setText("正在掃描連線...")
        worker = _掃描工作(self._信號)
        self._執行緒池.start(worker)

    def _掃描完成(self, items: list[連線資料]) -> None:
        self._執行中 = False
        self.進度條.setVisible(False)
        self._目前資料 = items
        self._套用篩選()
        self.狀態標籤.setText(f"已載入 {len(items)} 筆連線資料")

    def _顯示錯誤(self, text: str) -> None:
        self._執行中 = False
        self.進度條.setVisible(False)
        self.狀態標籤.setText("掃描失敗")
        QMessageBox.critical(self, "錯誤", text)

    def _套用篩選(self) -> None:
        if not self._搜尋文字:
            顯示 = self._目前資料
        else:
            關鍵 = self._搜尋文字
            顯示 = []
            for item in self._目前資料:
                串 = " ".join([
                    str(item.pid or ""),
                    item.程序名稱,
                    item.服務名稱,
                    item.協定,
                    item.狀態,
                    item.本地位址,
                    item.遠端位址,
                    item.程序路徑,
                    item.命令列,
                    item.使用者,
                    item.反向DNS,
                    item.備註,
                    item.標記,
                ]).lower()
                if 關鍵 in 串:
                    顯示.append(item)
        self._模型.設定資料(顯示)
        if self.表格.model().rowCount() > 0:
            self.表格.selectRow(0)
            self._選中列(self.表格.model().index(0, 0))

    def _取目前選中(self) -> Optional[連線資料]:
        idx = self.表格.currentIndex()
        if not idx.isValid():
            return None
        return self._模型.取資料(idx.row())

    def _選中列(self, index) -> None:
        item = self._模型.取資料(index.row())
        if not item:
            return
        self._選中鍵 = item.鍵
        標題 = f"{item.程序名稱} | PID {item.pid or '-'} | {item.協定} | {item.風險分數} 分"
        self.標題.setText(標題)
        內容 = []
        內容.append(f"程序名稱：{item.程序名稱}")
        內容.append(f"服務名稱：{item.服務名稱}")
        內容.append(f"PID：{item.pid or '-'}")
        內容.append(f"協定：{item.協定}")
        內容.append(f"狀態：{item.狀態}")
        內容.append(f"本地位址：{item.本地位址}")
        內容.append(f"遠端位址：{item.遠端位址}")
        內容.append(f"程序路徑：{item.程序路徑}")
        內容.append(f"命令列：{item.命令列}")
        內容.append(f"使用者：{item.使用者}")
        內容.append(f"建立時間：{item.建立時間}")
        內容.append(f"CPU：{item.CPU if item.CPU is not None else '-'} %")
        內容.append(f"記憶體：{item.記憶體MB:.1f} MB" if item.記憶體MB is not None else "記憶體：-")
        內容.append(f"線程數：{item.線程數 if item.線程數 is not None else '-'}")
        內容.append(f"開啟檔案數：{item.開啟檔案數 if item.開啟檔案數 is not None else '-'}")
        內容.append(f"風險分數：{item.風險分數}")
        內容.append(f"風險等級：{item.風險等級}")
        內容.append(f"位址類型：{item.位址類型}")
        內容.append(f"反向DNS：{item.反向DNS}")
        內容.append(f"服務提示：{item.服務提示}")
        內容.append(f"判斷說明：{item.判斷說明}")
        內容.append(f"備註：{item.備註 or '-'}")
        內容.append(f"標記：{item.標記 or '-'}")
        規則 = 查詢規則(item.pid or 0, item.程序路徑 if item.程序路徑 != "-" else "")
        內容.append(f"防火牆規則：{規則}")
        self.詳細.setPlainText("\n".join(內容))

    def _編輯備註(self) -> None:
        item = self._取目前選中()
        if not item:
            QMessageBox.information(self, "提示", "請先選取一筆連線。")
            return
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QVBoxLayout, QLineEdit, QLabel
        dlg = QDialog(self)
        dlg.setWindowTitle("編輯備註與標記")
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel(f"程序：{item.程序名稱}\nPID：{item.pid or '-'}"))
        note = QLineEdit(item.備註)
        tag = QLineEdit(item.標記)
        note.setPlaceholderText("備註")
        tag.setPlaceholderText("標記")
        layout.addWidget(note)
        layout.addWidget(tag)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        layout.addWidget(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._儲存庫.儲存備註(item.鍵, note.text().strip(), tag.text().strip())
            self._立即刷新()

    def _複製資訊(self) -> None:
        item = self._取目前選中()
        if not item:
            QMessageBox.information(self, "提示", "請先選取一筆連線。")
            return
        from PySide6.QtGui import QGuiApplication
        text = "\n".join([
            f"程序名稱：{item.程序名稱}",
            f"服務名稱：{item.服務名稱}",
            f"PID：{item.pid or '-'}",
            f"協定：{item.協定}",
            f"狀態：{item.狀態}",
            f"本地位址：{item.本地位址}",
            f"遠端位址：{item.遠端位址}",
            f"程序路徑：{item.程序路徑}",
            f"命令列：{item.命令列}",
            f"使用者：{item.使用者}",
            f"風險分數：{item.風險分數}",
            f"風險等級：{item.風險等級}",
            f"反向DNS：{item.反向DNS}",
            f"判斷說明：{item.判斷說明}",
            f"備註：{item.備註}",
            f"標記：{item.標記}",
        ])
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage("已複製資訊", 2500)

    def _終止選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            return
        if QMessageBox.question(self, "確認", f"確定要終止程序 {item.程序名稱} (PID {item.pid})？") != QMessageBox.StandardButton.Yes:
            return
        result = 終止程序(item.pid)
        QMessageBox.information(self, "結果", result.訊息)
        self._立即刷新()

    def _暫停選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            return
        result = 暫停程序(item.pid)
        QMessageBox.information(self, "結果", result.訊息)

    def _恢復選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            return
        result = 恢復程序(item.pid)
        QMessageBox.information(self, "結果", result.訊息)

    def _開啟位置選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.程序路徑 or item.程序路徑 == "-":
            QMessageBox.information(self, "提示", "沒有可開啟的程序路徑。")
            return
        result = 開啟檔案位置(item.程序路徑)
        if not result.成功:
            QMessageBox.warning(self, "失敗", result.訊息)

    def _封鎖選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            return
        result = 封鎖程序(item.pid, item.程序路徑 if item.程序路徑 != "-" else "")
        if result.成功:
            self._儲存庫.儲存防火牆規則(result.規則名, item.程序路徑, item.pid)
            QMessageBox.information(self, "完成", result.訊息)
        else:
            QMessageBox.warning(self, "失敗", result.訊息)

    def _解除封鎖選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            return
        result = 解除封鎖程序(item.pid, item.程序路徑 if item.程序路徑 != "-" else "")
        if result.成功:
            self._儲存庫.刪除防火牆規則(result.規則名)
            QMessageBox.information(self, "完成", result.訊息)
        else:
            QMessageBox.warning(self, "失敗", result.訊息)
