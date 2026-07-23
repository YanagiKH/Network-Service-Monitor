from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QThreadPool, QRunnable, QObject, Signal, Slot, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QAbstractItemView,
    QProgressBar,
    QSplitter,
    QTableView,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QSpinBox,
)

from ..core.firewall import 封鎖程序, 解除封鎖程序, 查詢規則
from ..core.process_actions import 終止程序, 暫停程序, 恢復程序, 開啟檔案位置
from ..core.scanner import 連線資料, 掃描連線
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

        self.語言 = "en"
        self.語言順序 = ["en", "ja", "zh"]

        self._翻譯 = {
            "en": {
                "app_title": "Network Service Monitor",
                "search_placeholder": "Search process, service, PID, IP, path, tag...",
                "auto_refresh": "Auto refresh",
                "interval": "Interval",
                "refresh_now": "Refresh now",
                "language_button": "English",
                "management": "Management",
                "terminate_process": "Terminate process",
                "suspend_process": "Suspend process",
                "resume_process": "Resume process",
                "open_location": "Open location",
                "block_connection": "Block connection",
                "unblock_connection": "Unblock connection",
                "edit_note": "Edit note",
                "copy_info": "Copy info",
                "ready": "Ready",
                "loading": "Scanning connections...",
                "loaded": "Loaded {count} connections",
                "scan_failed": "Scan failed",
                "no_selection": "No connection selected.",
                "select_first": "Select a connection first.",
                "copied_info": "Information copied.",
                "confirm_terminate": "Terminate process {name} (PID {pid})?",
                "note_title": "Edit note and tag",
                "note": "Note",
                "tag": "Tag",
                "completed": "Completed",
                "failed": "Failed",
                "no_path": "No process path available.",
                "open_failed": "Open failed: {msg}",
                "block_ok": "Firewall rule created.",
                "unblock_ok": "Firewall rule removed.",
                "block_failed": "Block failed: {msg}",
                "unblock_failed": "Unblock failed: {msg}",
                "detail_process": "Process name",
                "detail_service": "Service name",
                "detail_pid": "PID",
                "detail_proto": "Protocol",
                "detail_status": "Status",
                "detail_local": "Local address",
                "detail_remote": "Remote address",
                "detail_path": "Process path",
                "detail_cmd": "Command line",
                "detail_user": "User",
                "detail_created": "Created",
                "detail_cpu": "CPU",
                "detail_mem": "Memory",
                "detail_threads": "Threads",
                "detail_files": "Open files",
                "detail_risk_score": "Risk score",
                "detail_risk_level": "Risk level",
                "detail_addr_type": "Address type",
                "detail_dns": "Reverse DNS",
                "detail_service_hint": "Service hint",
                "detail_reason": "Reason",
                "detail_note": "Note",
                "detail_tag": "Tag",
                "detail_rule": "Firewall rule",
                "table_headers": [
                    "Process / Service",
                    "PID",
                    "Protocol",
                    "Status",
                    "Local Address",
                    "Remote Address",
                    "Risk",
                    "Reverse DNS",
                    "Process Path",
                    "Note",
                    "Tag",
                ],
                "suffix_seconds": " sec",
                "language_name": "English",
            },
            "ja": {
                "app_title": "ネットワークサービスモニター",
                "search_placeholder": "プロセス、サービス、PID、IP、パス、タグを検索...",
                "auto_refresh": "自動更新",
                "interval": "間隔",
                "refresh_now": "今すぐ更新",
                "language_button": "日本語",
                "management": "管理",
                "terminate_process": "プロセス終了",
                "suspend_process": "一時停止",
                "resume_process": "再開",
                "open_location": "場所を開く",
                "block_connection": "接続をブロック",
                "unblock_connection": "ブロック解除",
                "edit_note": "メモ編集",
                "copy_info": "情報をコピー",
                "ready": "準備完了",
                "loading": "接続をスキャン中...",
                "loaded": "{count} 件の接続を読み込みました",
                "scan_failed": "スキャン失敗",
                "no_selection": "接続が選択されていません。",
                "select_first": "先に接続を選択してください。",
                "copied_info": "情報をコピーしました。",
                "confirm_terminate": "プロセス {name} (PID {pid}) を終了しますか？",
                "note_title": "メモとタグを編集",
                "note": "メモ",
                "tag": "タグ",
                "completed": "完了",
                "failed": "失敗",
                "no_path": "プロセスのパスがありません。",
                "open_failed": "開く失敗: {msg}",
                "block_ok": "ファイアウォール規則を作成しました。",
                "unblock_ok": "ファイアウォール規則を削除しました。",
                "block_failed": "ブロック失敗: {msg}",
                "unblock_failed": "解除失敗: {msg}",
                "detail_process": "プロセス名",
                "detail_service": "サービス名",
                "detail_pid": "PID",
                "detail_proto": "プロトコル",
                "detail_status": "状態",
                "detail_local": "ローカルアドレス",
                "detail_remote": "リモートアドレス",
                "detail_path": "プロセスパス",
                "detail_cmd": "コマンドライン",
                "detail_user": "ユーザー",
                "detail_created": "作成時刻",
                "detail_cpu": "CPU",
                "detail_mem": "メモリ",
                "detail_threads": "スレッド数",
                "detail_files": "開いているファイル",
                "detail_risk_score": "リスクスコア",
                "detail_risk_level": "リスクレベル",
                "detail_addr_type": "アドレス種別",
                "detail_dns": "逆引きDNS",
                "detail_service_hint": "サービスヒント",
                "detail_reason": "判定理由",
                "detail_note": "メモ",
                "detail_tag": "タグ",
                "detail_rule": "ファイアウォール規則",
                "table_headers": [
                    "プロセス / サービス",
                    "PID",
                    "プロトコル",
                    "状態",
                    "ローカルアドレス",
                    "リモートアドレス",
                    "リスク",
                    "逆引きDNS",
                    "プロセスパス",
                    "メモ",
                    "タグ",
                ],
                "suffix_seconds": " 秒",
                "language_name": "日本語",
            },
            "zh": {
                "app_title": "Network Service Monitor",
                "search_placeholder": "搜尋程序、服務、PID、IP、路徑、標記...",
                "auto_refresh": "自動刷新",
                "interval": "間隔",
                "refresh_now": "立即刷新",
                "language_button": "繁體中文",
                "management": "管理控制",
                "terminate_process": "終止程序",
                "suspend_process": "暫停程序",
                "resume_process": "恢復程序",
                "open_location": "開啟位置",
                "block_connection": "封鎖連線",
                "unblock_connection": "解除封鎖",
                "edit_note": "編輯備註",
                "copy_info": "複製資訊",
                "ready": "準備就緒",
                "loading": "正在掃描連線...",
                "loaded": "已載入 {count} 筆連線資料",
                "scan_failed": "掃描失敗",
                "no_selection": "尚未選取連線。",
                "select_first": "請先選取一筆連線。",
                "copied_info": "已複製資訊。",
                "confirm_terminate": "確定要終止程序 {name} (PID {pid})？",
                "note_title": "編輯備註與標記",
                "note": "備註",
                "tag": "標記",
                "completed": "完成",
                "failed": "失敗",
                "no_path": "沒有可開啟的程序路徑。",
                "open_failed": "開啟失敗：{msg}",
                "block_ok": "已建立防火牆封鎖規則。",
                "unblock_ok": "已移除防火牆封鎖規則。",
                "block_failed": "封鎖失敗：{msg}",
                "unblock_failed": "解除失敗：{msg}",
                "detail_process": "程序名稱",
                "detail_service": "服務名稱",
                "detail_pid": "PID",
                "detail_proto": "協定",
                "detail_status": "狀態",
                "detail_local": "本地位址",
                "detail_remote": "遠端位址",
                "detail_path": "程序路徑",
                "detail_cmd": "命令列",
                "detail_user": "使用者",
                "detail_created": "建立時間",
                "detail_cpu": "CPU",
                "detail_mem": "記憶體",
                "detail_threads": "線程數",
                "detail_files": "開啟檔案數",
                "detail_risk_score": "風險分數",
                "detail_risk_level": "風險等級",
                "detail_addr_type": "位址類型",
                "detail_dns": "反向DNS",
                "detail_service_hint": "服務提示",
                "detail_reason": "判斷說明",
                "detail_note": "備註",
                "detail_tag": "標記",
                "detail_rule": "防火牆規則",
                "table_headers": [
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
                ],
                "suffix_seconds": " 秒",
                "language_name": "繁體中文",
            },
        }

        self.計時器 = QTimer(self)
        self._建立介面()
        self._建立工具列()
        self._更新文字()
        self._套用刷新()
        self._開始刷新計時器()

    def _t(self, key: str, **kwargs) -> str:
        text = self._翻譯.get(self.語言, self._翻譯["en"]).get(key, self._翻譯["en"].get(key, key))
        if kwargs:
            return text.format(**kwargs)
        return text

    def _語言顯示名稱(self) -> str:
        return self._t("language_name")

    def _建立介面(self) -> None:
        中央 = QWidget()
        主要布局 = QVBoxLayout(中央)
        主要布局.setContentsMargins(10, 10, 10, 10)
        主要布局.setSpacing(8)

        上方列 = QHBoxLayout()
        self.搜尋框 = QLineEdit()
        self.搜尋框.textChanged.connect(self._更新搜尋)

        self.語言按鈕 = QPushButton()
        self.語言按鈕.clicked.connect(self._切換語言)

        self.自動刷新勾選 = QCheckBox()
        self.自動刷新勾選.setChecked(True)
        self.自動刷新勾選.toggled.connect(self._切換自動刷新)

        self.刷新間隔 = QSpinBox()
        self.刷新間隔.setRange(1, 60)
        self.刷新間隔.setValue(2)
        self.刷新間隔.valueChanged.connect(self._套用刷新)

        self.刷新按鈕 = QPushButton()
        self.刷新按鈕.clicked.connect(self._立即刷新)

        上方列.addWidget(self.搜尋框, 1)
        上方列.addWidget(self.語言按鈕)
        上方列.addWidget(self.自動刷新勾選)
        上方列.addWidget(QLabel())
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

        左布局.addWidget(self.表格)

        右側 = QWidget()
        右布局 = QVBoxLayout(右側)
        右布局.setContentsMargins(0, 0, 0, 0)

        self.標題 = QLabel()
        self.標題.setStyleSheet("font-size: 20px; font-weight: 700;")
        self.詳細 = QTextEdit()
        self.詳細.setReadOnly(True)
        self.詳細.setMinimumHeight(300)

        self.控制框 = QGroupBox()
        控制布局 = QVBoxLayout(self.控制框)

        按鈕列1 = QHBoxLayout()
        self.終止按鈕 = QPushButton()
        self.暫停按鈕 = QPushButton()
        self.恢復按鈕 = QPushButton()
        self.開啟位置按鈕 = QPushButton()
        按鈕列1.addWidget(self.終止按鈕)
        按鈕列1.addWidget(self.暫停按鈕)
        按鈕列1.addWidget(self.恢復按鈕)
        按鈕列1.addWidget(self.開啟位置按鈕)

        按鈕列2 = QHBoxLayout()
        self.封鎖按鈕 = QPushButton()
        self.解除封鎖按鈕 = QPushButton()
        self.編輯備註按鈕 = QPushButton()
        self.複製資訊按鈕 = QPushButton()
        按鈕列2.addWidget(self.封鎖按鈕)
        按鈕列2.addWidget(self.解除封鎖按鈕)
        按鈕列2.addWidget(self.編輯備註按鈕)
        按鈕列2.addWidget(self.複製資訊按鈕)

        控制布局.addLayout(按鈕列1)
        控制布局.addLayout(按鈕列2)

        右布局.addWidget(self.標題)
        右布局.addWidget(self.詳細, 1)
        右布局.addWidget(self.控制框)

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
        self.狀態標籤 = QLabel()
        self.進度條 = QProgressBar()
        self.進度條.setRange(0, 0)
        self.進度條.setVisible(False)
        下方.addWidget(self.狀態標籤, 1)
        下方.addWidget(self.進度條)
        主要布局.addLayout(下方)

        self.setCentralWidget(中央)

    def _建立工具列(self) -> None:
        self.工具列 = QToolBar("主要工具")
        self.工具列.setMovable(False)
        self.addToolBar(self.工具列)

        self.動作刷新 = QAction(self)
        self.動作刷新.triggered.connect(self._立即刷新)
        self.工具列.addAction(self.動作刷新)

        self.動作複製 = QAction(self)
        self.動作複製.triggered.connect(self._複製資訊)
        self.工具列.addAction(self.動作複製)

        self.動作退出 = QAction(self)
        self.動作退出.triggered.connect(self.close)
        self.工具列.addAction(self.動作退出)

    def _更新文字(self) -> None:
        self.setWindowTitle(self._t("app_title"))
        self.搜尋框.setPlaceholderText(self._t("search_placeholder"))
        self.語言按鈕.setText(self._t("language_button"))
        self.自動刷新勾選.setText(self._t("auto_refresh"))
        self.刷新按鈕.setText(self._t("refresh_now"))
        self.控制框.setTitle(self._t("management"))
        self.終止按鈕.setText(self._t("terminate_process"))
        self.暫停按鈕.setText(self._t("suspend_process"))
        self.恢復按鈕.setText(self._t("resume_process"))
        self.開啟位置按鈕.setText(self._t("open_location"))
        self.封鎖按鈕.setText(self._t("block_connection"))
        self.解除封鎖按鈕.setText(self._t("unblock_connection"))
        self.編輯備註按鈕.setText(self._t("edit_note"))
        self.複製資訊按鈕.setText(self._t("copy_info"))
        self.狀態標籤.setText(self._t("ready"))
        self.刷新間隔.setSuffix(self._t("suffix_seconds"))
        self._模型.設定欄位標題(self._t("table_headers"))
        self.動作刷新.setText(self._t("refresh_now"))
        self.動作複製.setText(self._t("copy_info"))
        self.動作退出.setText("Exit" if self.語言 == "en" else ("終了" if self.語言 == "ja" else "退出"))

    def _切換語言(self) -> None:
        idx = self.語言順序.index(self.語言)
        self.語言 = self.語言順序[(idx + 1) % len(self.語言順序)]
        self._更新文字()
        self._套用篩選()
        if self._選中鍵:
            self._更新詳細顯示()

    def _開始刷新計時器(self) -> None:
        self.計時器.timeout.connect(self._立即刷新)

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
        self.狀態標籤.setText(self._t("loading"))
        worker = _掃描工作(self._信號)
        self._執行緒池.start(worker)

    def _掃描完成(self, items: list[連線資料]) -> None:
        self._執行中 = False
        self.進度條.setVisible(False)
        self._目前資料 = items
        self._套用篩選()
        self.狀態標籤.setText(self._t("loaded", count=len(items)))

    def _顯示錯誤(self, text: str) -> None:
        self._執行中 = False
        self.進度條.setVisible(False)
        self.狀態標籤.setText(self._t("scan_failed"))
        QMessageBox.critical(self, self._t("scan_failed"), text)

    def _套用篩選(self) -> None:
        if not self._搜尋文字:
            顯示 = self._目前資料
        else:
            關鍵 = self._搜尋文字
            顯示 = []
            for item in self._目前資料:
                串 = " ".join(
                    [
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
                    ]
                ).lower()
                if 關鍵 in 串:
                    顯示.append(item)

        self._模型.設定資料(顯示)
        if self.表格.model().rowCount() > 0:
            self.表格.selectRow(0)
            self._選中列(self.表格.model().index(0, 0))
        else:
            self.標題.setText(self._t("no_selection"))
            self.詳細.setPlainText(self._t("select_first"))

    def _取目前選中(self) -> Optional[連線資料]:
        idx = self.表格.currentIndex()
        if not idx.isValid():
            return None
        return self._模型.取資料(idx.row())

    def _更新詳細顯示(self) -> None:
        item = self._取目前選中()
        if item:
            self._選中列(self.表格.currentIndex())

    def _選中列(self, index) -> None:
        item = self._模型.取資料(index.row())
        if not item:
            return
        self._選中鍵 = item.鍵
        self.標題.setText(f"{item.程序名稱} | PID {item.pid or '-'} | {item.協定} | {item.風險分數} 分")
        內容 = []
        內容.append(f"{self._t('detail_process')}：{item.程序名稱}")
        內容.append(f"{self._t('detail_service')}：{item.服務名稱}")
        內容.append(f"{self._t('detail_pid')}：{item.pid or '-'}")
        內容.append(f"{self._t('detail_proto')}：{item.協定}")
        內容.append(f"{self._t('detail_status')}：{item.狀態}")
        內容.append(f"{self._t('detail_local')}：{item.本地位址}")
        內容.append(f"{self._t('detail_remote')}：{item.遠端位址}")
        內容.append(f"{self._t('detail_path')}：{item.程序路徑}")
        內容.append(f"{self._t('detail_cmd')}：{item.命令列}")
        內容.append(f"{self._t('detail_user')}：{item.使用者}")
        內容.append(f"{self._t('detail_created')}：{item.建立時間}")
        內容.append(f"{self._t('detail_cpu')}：{item.CPU if item.CPU is not None else '-'} %")
        內容.append(f"{self._t('detail_mem')}：{item.記憶體MB:.1f} MB" if item.記憶體MB is not None else f"{self._t('detail_mem')}：-")
        內容.append(f"{self._t('detail_threads')}：{item.線程數 if item.線程數 is not None else '-'}")
        內容.append(f"{self._t('detail_files')}：{item.開啟檔案數 if item.開啟檔案數 is not None else '-'}")
        內容.append(f"{self._t('detail_risk_score')}：{item.風險分數}")
        內容.append(f"{self._t('detail_risk_level')}：{item.風險等級}")
        內容.append(f"{self._t('detail_addr_type')}：{item.位址類型}")
        內容.append(f"{self._t('detail_dns')}：{item.反向DNS}")
        內容.append(f"{self._t('detail_service_hint')}：{item.服務提示}")
        內容.append(f"{self._t('detail_reason')}：{item.判斷說明}")
        內容.append(f"{self._t('detail_note')}：{item.備註 or '-'}")
        內容.append(f"{self._t('detail_tag')}：{item.標記 or '-'}")
        規則 = 查詢規則(item.pid or 0, item.程序路徑 if item.程序路徑 != "-" else "")
        內容.append(f"{self._t('detail_rule')}：{規則}")
        self.詳細.setPlainText("\n".join(內容))

    def _編輯備註(self) -> None:
        item = self._取目前選中()
        if not item:
            QMessageBox.information(self, self._t("note_title"), self._t("select_first"))
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(self._t("note_title"))
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel(f"{self._t('detail_process')}：{item.程序名稱}\n{self._t('detail_pid')}：{item.pid or '-'}"))

        note = QLineEdit(item.備註)
        tag = QLineEdit(item.標記)
        note.setPlaceholderText(self._t("note"))
        tag.setPlaceholderText(self._t("tag"))
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
            QMessageBox.information(self, self._t("copy_info"), self._t("select_first"))
            return

        from PySide6.QtGui import QGuiApplication

        text = "\n".join(
            [
                f"{self._t('detail_process')}：{item.程序名稱}",
                f"{self._t('detail_service')}：{item.服務名稱}",
                f"{self._t('detail_pid')}：{item.pid or '-'}",
                f"{self._t('detail_proto')}：{item.協定}",
                f"{self._t('detail_status')}：{item.狀態}",
                f"{self._t('detail_local')}：{item.本地位址}",
                f"{self._t('detail_remote')}：{item.遠端位址}",
                f"{self._t('detail_path')}：{item.程序路徑}",
                f"{self._t('detail_cmd')}：{item.命令列}",
                f"{self._t('detail_user')}：{item.使用者}",
                f"{self._t('detail_risk_score')}：{item.風險分數}",
                f"{self._t('detail_risk_level')}：{item.風險等級}",
                f"{self._t('detail_dns')}：{item.反向DNS}",
                f"{self._t('detail_reason')}：{item.判斷說明}",
                f"{self._t('detail_note')}：{item.備註}",
                f"{self._t('detail_tag')}：{item.標記}",
            ]
        )
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage(self._t("copied_info"), 2500)

    def _終止選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            QMessageBox.information(self, self._t("terminate_process"), self._t("select_first"))
            return
        if QMessageBox.question(self, self._t("terminate_process"), self._t("confirm_terminate", name=item.程序名稱, pid=item.pid)) != QMessageBox.StandardButton.Yes:
            return
        result = 終止程序(item.pid)
        QMessageBox.information(self, self._t("terminate_process"), result.訊息)
        self._立即刷新()

    def _暫停選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            QMessageBox.information(self, self._t("suspend_process"), self._t("select_first"))
            return
        result = 暫停程序(item.pid)
        QMessageBox.information(self, self._t("suspend_process"), result.訊息)

    def _恢復選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            QMessageBox.information(self, self._t("resume_process"), self._t("select_first"))
            return
        result = 恢復程序(item.pid)
        QMessageBox.information(self, self._t("resume_process"), result.訊息)

    def _開啟位置選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.程序路徑 or item.程序路徑 == "-":
            QMessageBox.information(self, self._t("open_location"), self._t("no_path"))
            return
        result = 開啟檔案位置(item.程序路徑)
        if not result.成功:
            QMessageBox.warning(self, self._t("open_location"), self._t("open_failed", msg=result.訊息))

    def _封鎖選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            QMessageBox.information(self, self._t("block_connection"), self._t("select_first"))
            return
        result = 封鎖程序(item.pid, item.程序路徑 if item.程序路徑 != "-" else "")
        if result.成功:
            self._儲存庫.儲存防火牆規則(result.規則名, item.程序路徑, item.pid)
            QMessageBox.information(self, self._t("block_connection"), self._t("block_ok"))
        else:
            QMessageBox.warning(self, self._t("block_connection"), self._t("block_failed", msg=result.訊息))

    def _解除封鎖選中(self) -> None:
        item = self._取目前選中()
        if not item or not item.pid:
            QMessageBox.information(self, self._t("unblock_connection"), self._t("select_first"))
            return
        result = 解除封鎖程序(item.pid, item.程序路徑 if item.程序路徑 != "-" else "")
        if result.成功:
            self._儲存庫.刪除防火牆規則(result.規則名)
            QMessageBox.information(self, self._t("unblock_connection"), self._t("unblock_ok"))
        else:
            QMessageBox.warning(self, self._t("unblock_connection"), self._t("unblock_failed", msg=result.訊息))
