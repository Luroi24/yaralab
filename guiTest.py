#!/usr/bin/env python3
"""
file_copy_gui.py

PyQt6 GUI to accept files (via button or drag & drop) and copy/move them to a chosen directory.
Includes an in-list visual indicator that the widget supports drag & drop.
Fixed: safe removal of items to avoid crashes when removing everything.
"""

import os
import sys
import shutil
from pathlib import Path
from typing import List

import yaralab

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QListWidget, QLabel, QHBoxLayout, QCheckBox, QMessageBox, QProgressBar, QAbstractItemView,
    QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl

REMOTE_FILES_DIR = "./remote/files" 


class DropListWidget(QListWidget):
    """QListWidget subclass that accepts file drag-and-drop from OS file manager."""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Allow drops, show indicator and accept external drops
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)

        # Overlay label to indicate drag & drop support
        self.overlay = QLabel(self)
        self.overlay.setText("Drop files here\n(or use 'Add files...')") 
        self.overlay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.overlay.setWordWrap(True)
        self.overlay.setStyleSheet(
            "QLabel {"
            " color: #666; "
            " background: rgba(255,255,255,0.0); "
            " border: 2px dashed #bdbdbd; "
            " padding: 10px; "
            " border-radius: 8px;"
            " font-size: 13pt;"
            "}"
        )
        self.overlay.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._update_overlay_visibility()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_overlay()

    def _position_overlay(self):
        w = max(200, int(self.width() * 0.6))
        h = max(60, int(self.height() * 0.3))
        x = (self.width() - w) // 2
        y = (self.height() - h) // 2
        self.overlay.setGeometry(x, y, w, h)

    def _update_overlay_visibility(self):
        if self.count() == 0:
            self.overlay.show()
        else:
            self.overlay.hide()

    def _extract_paths_from_mime(self, mime):
        paths = []
        if mime.hasUrls():
            for url in mime.urls():
                try:
                    if isinstance(url, QUrl) and url.isLocalFile():
                        local = url.toLocalFile()
                        if local:
                            paths.append(local)
                    else:
                        local = url.toLocalFile()
                        if local:
                            paths.append(local)
                except Exception:
                    continue
        elif mime.hasFormat(b"text/uri-list") or mime.hasFormat("text/uri-list"):
            txt = mime.data("text/uri-list")
            try:
                s = bytes(txt).decode(errors="ignore")
            except Exception:
                s = str(txt)
            for line in s.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("file://"):
                    line = QUrl(line).toLocalFile()
                paths.append(line)
        elif mime.hasText():
            text = mime.text()
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("file://"):
                    line = QUrl(line).toLocalFile()
                paths.append(line)
        return paths

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        paths = self._extract_paths_from_mime(mime)
        if paths:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        mime = event.mimeData()
        paths = self._extract_paths_from_mime(mime)
        if paths:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        mime = event.mimeData()
        paths = self._extract_paths_from_mime(mime)
        if not paths:
            event.ignore()
            return

        existing = {self.item(i).text() for i in range(self.count())}
        for p in paths:
            if p and Path(p).exists() and p not in existing:
                super().addItem(p)
        event.acceptProposedAction()
        self._update_overlay_visibility()

    # Keep overlay visibility correct when items change
    def addItem(self, item):
        super().addItem(item)
        self._update_overlay_visibility()

    def addItems(self, items):
        super().addItems(items)
        self._update_overlay_visibility()

    def takeItem(self, row):
        # Defensive: if row is out of range, return None
        if row < 0 or row >= self.count():
            return None
        it = super().takeItem(row)
        self._update_overlay_visibility()
        return it

    def clear(self):
        super().clear()
        self._update_overlay_visibility()


class FileCopyThread(QThread):
    progress = pyqtSignal(int)
    file_copied = pyqtSignal(str)
    finished_ok = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, paths: List[str], dest_dir: str, move: bool = False):
        super().__init__()
        self.paths = [Path(p) for p in paths]
        self.dest_dir = Path(dest_dir)
        self.move = move
        self._is_cancelled = False

    def run(self):
        try:
            total_items = len(self.paths)
            if total_items == 0:
                self.progress.emit(100)
                self.finished_ok.emit()
                return

            for idx, p in enumerate(self.paths, start=1):
                if self._is_cancelled:
                    break
                try:
                    if p.is_dir():
                        target = self.dest_dir / p.name
                        target = self._resolve_collision(target)
                        if self.move:
                            shutil.move(str(p), str(target))
                        else:
                            shutil.copytree(str(p), str(target))
                        self.file_copied.emit(str(target))
                    else:
                        target = self.dest_dir / p.name
                        target = self._resolve_collision(target)
                        if self.move:
                            shutil.move(str(p), str(target))
                        else:
                            shutil.copy2(str(p), str(target))
                        self.file_copied.emit(str(target))
                except Exception as e:
                    self.error.emit(f"Error copying {p}: {e}")

                percent = int((idx / total_items) * 100)
                self.progress.emit(percent)

            self.progress.emit(100)
            self.finished_ok.emit()
        except Exception as e:
            self.error.emit(f"Unexpected error: {e}")

    def _resolve_collision(self, target: Path) -> Path:
        if not target.exists():
            return target
        base = target.stem
        suffix = target.suffix
        parent = target.parent
        i = 1
        while True:
            candidate = parent / f"{base} ({i}){suffix}"
            if not candidate.exists():
                return candidate
            i += 1

    def cancel(self):
        self._is_cancelled = True


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PYFA - Portable Yara File Analyzer")
        self.resize(700, 400)
        layout = QVBoxLayout(self)

        dest_layout = QHBoxLayout()
        # self.dest_label = QLabel("Destination: (not set)")
        # dest_layout.addWidget(self.dest_label)
        # self.btn_choose_dest = QPushButton("Choose Destination")
        # self.btn_choose_dest.clicked.connect(self.choose_destination)
        # dest_layout.addWidget(self.btn_choose_dest)
        self.chk_run_name = QLineEdit()
        self.chk_run_name.setPlaceholderText(f"Enter run name... (default: {self.get_default_run_name()})")
        dest_layout.addWidget(self.chk_run_name)
        layout.addLayout(dest_layout)

        layout.addWidget(QLabel("Files to copy (drag files here or use 'Add files')"))
        self.files_list = DropListWidget()
        layout.addWidget(self.files_list)

        btn_row = QHBoxLayout()
        self.btn_add = QPushButton("Add files...")
        self.btn_add.clicked.connect(self.add_files)
        btn_row.addWidget(self.btn_add)
        self.btn_remove = QPushButton("Remove selected")
        self.btn_remove.clicked.connect(self.remove_selected)
        btn_row.addWidget(self.btn_remove)
        self.chk_move = QCheckBox("Move files (instead of copy)")
        btn_row.addWidget(self.chk_move)
        self.btn_clear = QPushButton("Clear list")
        self.btn_clear.clicked.connect(self.clear_list)
        btn_row.addWidget(self.btn_clear)
        layout.addLayout(btn_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        layout.addWidget(self.progress)
        self.status = QLabel("")
        layout.addWidget(self.status)

        analysis_row = QHBoxLayout()
        self.chk_group_by_tags = QCheckBox("Group output by tags instead of rules")
        analysis_row.addWidget(self.chk_group_by_tags)
        layout.addLayout(analysis_row)

        action_row = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_start.clicked.connect(self.start_copy)
        action_row.addWidget(self.btn_start)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.cancel_copy)
        self.btn_cancel.setEnabled(False)
        action_row.addWidget(self.btn_cancel)
        layout.addLayout(action_row)

        self.set_destination(REMOTE_FILES_DIR)
        self.worker = None

    def get_default_run_name(self):
        base = "yara_run"
        name = base
        i = 1
        while os.path.exists(os.path.join(REMOTE_FILES_DIR, name)):
            name = f"{base}_{i}"
            i += 1
        
        return name

    def choose_destination(self):
        directory = QFileDialog.getExistingDirectory(self, "Select destination directory")
        if directory:
            self.set_destination(directory)

    def set_destination(self, path: str):
        path = os.path.abspath(path)
        self.dest_dir = path
        #self.dest_label.setText(f"Destination: {path}")

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to copy/move")
        if files:
            self.files_list.addItems(files)

    def remove_selected(self):
        # SAFER: use selectedItems() which returns QListWidgetItem objects
        items = list(self.files_list.selectedItems())
        if not items:
            return
        # remove by row in reverse order to keep indices valid
        rows = sorted((self.files_list.row(it) for it in items), reverse=True)
        for r in rows:
            # takeItem is defensive; it returns None if row invalid
            self.files_list.takeItem(r)

    def clear_list(self):
        self.files_list.clear()

    def start_copy(self):
        if self.files_list.count() == 0:
            QMessageBox.warning(self, "No files", "Add files (or drag them) before starting.")
            return
        if not self.dest_dir:
            QMessageBox.warning(self, "No destination", "Choose a destination directory first.")
            return
        
        # Create directory within destination for this run
        run_name = self.chk_run_name.text().strip()
        if not run_name:
            run_name = self.get_default_run_name()
        self.run_name = run_name
        dest_path = os.path.join(self.dest_dir, run_name)
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Cannot create destination directory '{dest_path}': {e}")
            return
        self.set_destination(dest_path)

        paths = [self.files_list.item(i).text() for i in range(self.files_list.count())]
        move = self.chk_move.isChecked()
        self._set_ui_enabled(False)
        self.status.setText("Starting...")
        self.progress.setValue(0)
        self.worker = FileCopyThread(paths, self.dest_dir, move)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.file_copied.connect(self.on_file_copied)
        self.worker.error.connect(self.on_error)
        self.worker.finished_ok.connect(self.on_finished)
        self.worker.start()
        self.btn_cancel.setEnabled(True)

        self.start_analysis()

    def start_analysis(self):
        #QMessageBox.information(self, "Analysis", "Starting analysis... (not implemented)")
        cmd = f"python3 /data/run-rules.py -f {self.run_name}"

        if self.chk_group_by_tags.isChecked():
            cmd += " -gt"
        
        yaralab.simple_test(cmd)

    def cancel_copy(self):
        if self.worker:
            self.worker.cancel()
            self.status.setText("Cancelling...")

    def on_file_copied(self, path):
        self.status.setText(f"Last: {path}")

    def on_error(self, message):
        QMessageBox.warning(self, "Copy error", message)

    def on_finished(self):
        #QMessageBox.information(self, "Done", "Copy/Move operation finished.")
        self._set_ui_enabled(True)
        self.btn_cancel.setEnabled(False)
        self.worker = None

    def _set_ui_enabled(self, enabled: bool):
        self.btn_add.setEnabled(enabled)
        self.btn_remove.setEnabled(enabled)
        self.btn_clear.setEnabled(enabled)
        #self.btn_choose_dest.setEnabled(enabled)
        self.chk_move.setEnabled(enabled)
        self.btn_start.setEnabled(enabled)
        self.files_list.setEnabled(enabled)
        if enabled:
            self.status.setText("")
        else:
            self.status.setText("Working...")


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
