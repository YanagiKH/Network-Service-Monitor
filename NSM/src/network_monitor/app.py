from __future__ import annotations

import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from .ui.main_window import 主視窗


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Network Service Monitor")
    app.setOrganizationName("OpenAI")
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    app.setStyle("Fusion")

    視窗 = 主視窗()
    視窗.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
