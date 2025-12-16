import os
import sys
import shutil
from pathlib import Path
from typing import List

import yaralab

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QListWidget, QLabel, QHBoxLayout, QCheckBox, QMessageBox, QProgressBar, QAbstractItemView,
    QLineEdit, QDialog, QComboBox, QListWidgetItem, QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, QTimer
from PyQt6.QtGui import QIcon, QPixmap

from docker_db_handler import MongoDB_Handler

REMOTE_FILES_DIR = "./remote/files" 
ICON_PATH = "misc/junimo_pyfa.png"


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


class ProgressDialog(QDialog):
    """A popup dialog showing progress bar and status."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Processing Files")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.resize(500, 120)
        
        layout = QVBoxLayout(self)
        
        self.status_label = QLabel("Starting...")
        layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        btn_layout.addWidget(self.btn_cancel)
        layout.addLayout(btn_layout)
        
    def update_progress(self, value: int):
        """Update the progress bar value."""
        self.progress_bar.setValue(value)
        
    def update_status(self, text: str):
        """Update the status label text."""
        self.status_label.setText(text)


class MultiSelectTagDropdown(QWidget):
    """A widget with a button that opens a tag selection dialog."""
    
    selectionChanged = pyqtSignal(list)  # Signal emitted when selection changes
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_tags = []
        self.selected_tags = set()
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        # Button to open tag selection dialog
        self.select_button = QPushButton("Select Tags...")
        self.select_button.clicked.connect(self._open_tag_dialog)
        layout.addWidget(self.select_button)
        
        # Label showing selection count
        self.selection_label = QLabel("(0 selected)")
        layout.addWidget(self.selection_label)
        
    def _open_tag_dialog(self):
        """Open the tag selection dialog."""
        dialog = TagSelectionDialog(self.all_tags, self.selected_tags, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.selected_tags = dialog.get_selected_tags()
            self._update_label()
            self.selectionChanged.emit(list(self.selected_tags))
            
    def _update_label(self):
        """Update the selection label."""
        count = len(self.selected_tags)
        if count == 0:
            self.selection_label.setText("(0 selected)")
        elif count <= 2:
            self.selection_label.setText(f"({', '.join(sorted(self.selected_tags))})")
        else:
            self.selection_label.setText(f"({count} selected)")
            
    def set_tags(self, tags: list):
        """Set the available tags list."""
        self.all_tags = sorted(tags) if tags else []
        self.select_button.setEnabled(len(self.all_tags) > 0)
        self._update_label()
        
    def get_selected_tags(self) -> list:
        """Return list of selected tags."""
        return list(self.selected_tags)
    
    def clear_selection(self):
        """Clear all selected tags."""
        self.selected_tags.clear()
        self._update_label()


class TagSelectionDialog(QDialog):
    """Dialog for selecting multiple tags with search functionality."""
    
    def __init__(self, all_tags: list, selected_tags: set, parent=None):
        super().__init__(parent)
        self.all_tags = all_tags
        self.selected_tags = set(selected_tags)  # Copy to avoid modifying original until OK
        self._setup_ui()
        
    def _setup_ui(self):
        self.setWindowTitle("Select Tags")
        self.setMinimumSize(400, 500)
        self.resize(450, 550)
        
        layout = QVBoxLayout(self)
        
        # Search box
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Type to filter tags...")
        self.search_input.textChanged.connect(self._filter_tags)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Select All / Clear All buttons
        btn_row = QHBoxLayout()
        self.btn_select_all = QPushButton("Select All Visible")
        self.btn_select_all.clicked.connect(self._select_all_visible)
        self.btn_clear_all = QPushButton("Clear All")
        self.btn_clear_all.clicked.connect(self._clear_all)
        btn_row.addWidget(self.btn_select_all)
        btn_row.addWidget(self.btn_clear_all)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        
        # Tag list with checkboxes
        self.tag_list = QListWidget()
        self.tag_list.setAlternatingRowColors(True)
        layout.addWidget(self.tag_list)
        
        # Populate the list
        for tag in self.all_tags:
            item = QListWidgetItem(tag)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            item.setCheckState(Qt.CheckState.Checked if tag in self.selected_tags else Qt.CheckState.Unchecked)
            self.tag_list.addItem(item)
        
        # Connect after populating
        self.tag_list.itemChanged.connect(self._on_item_changed)
        
        # Selection count label
        self.count_label = QLabel()
        self._update_count_label()
        layout.addWidget(self.count_label)
        
        # OK / Cancel buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.btn_ok = QPushButton("OK")
        self.btn_ok.clicked.connect(self.accept)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(self.btn_ok)
        button_layout.addWidget(self.btn_cancel)
        layout.addLayout(button_layout)
        
        # Focus search on open
        self.search_input.setFocus()
        
    def _filter_tags(self, search_text: str):
        """Filter visible tags based on search text."""
        search_text = search_text.lower()
        for i in range(self.tag_list.count()):
            item = self.tag_list.item(i)
            tag_text = item.text().lower()
            item.setHidden(search_text not in tag_text)
            
    def _on_item_changed(self, item: QListWidgetItem):
        """Handle checkbox state changes."""
        tag = item.text()
        if item.checkState() == Qt.CheckState.Checked:
            self.selected_tags.add(tag)
        else:
            self.selected_tags.discard(tag)
        self._update_count_label()
        
    def _select_all_visible(self):
        """Select all currently visible tags."""
        self.tag_list.blockSignals(True)
        for i in range(self.tag_list.count()):
            item = self.tag_list.item(i)
            if not item.isHidden():
                item.setCheckState(Qt.CheckState.Checked)
                self.selected_tags.add(item.text())
        self.tag_list.blockSignals(False)
        self._update_count_label()
        
    def _clear_all(self):
        """Clear all selections."""
        self.tag_list.blockSignals(True)
        for i in range(self.tag_list.count()):
            item = self.tag_list.item(i)
            item.setCheckState(Qt.CheckState.Unchecked)
        self.tag_list.blockSignals(False)
        self.selected_tags.clear()
        self._update_count_label()
        
    def _update_count_label(self):
        """Update the selection count label."""
        self.count_label.setText(f"Selected: {len(self.selected_tags)} / {len(self.all_tags)} tags")
        
    def get_selected_tags(self) -> set:
        """Return the set of selected tags."""
        return self.selected_tags


class TagLoaderThread(QThread):
    """Thread to load tags from database without blocking UI."""
    tags_loaded = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            db_handler = MongoDB_Handler()
            tags = db_handler.get_distinct("rules", "tags")
            db_handler.close()
            # Filter out empty tags
            tags = [t for t in tags if t and isinstance(t, str)]
            self.tags_loaded.emit(tags)
        except Exception as e:
            self.error.emit(str(e))


class ContainerInitThread(QThread):
    """Thread to initialize Docker containers without blocking UI."""
    finished_ok = pyqtSignal()
    error = pyqtSignal(str)
    
    def run(self):
        try:
            docker_handler = yaralab.get_docker_handler()
            docker_handler.run_container(
                image_name="yara",
                container_name="yara_container",
            )
            self.finished_ok.emit()
        except Exception as e:
            self.error.emit(str(e))


class SplashScreen(QWidget):
    """Splash screen shown while containers are initializing."""
    
    containers_ready = pyqtSignal()
    containers_error = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PYFA - Loading...")
        self.setWindowIcon(QIcon(ICON_PATH))
        self.setFixedSize(400, 350)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)
        
        # Logo
        self.logo_label = QLabel()
        pixmap = QPixmap(ICON_PATH)
        if not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pixmap)
        else:
            self.logo_label.setText("PYFA")
            self.logo_label.setStyleSheet("font-size: 48pt; font-weight: bold;")
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.logo_label)
        
        # Title
        title_label = QLabel("PYFA")
        title_label.setStyleSheet("font-size: 24pt; font-weight: bold; color: white;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Portable Yara File Analyzer")
        subtitle_label.setStyleSheet("font-size: 12pt; color: white;")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle_label)
        
        # Status label
        self.status_label = QLabel("Initializing containers...")
        self.status_label.setStyleSheet("font-size: 10pt; color: white;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Progress indicator (animated dots)
        self._dot_count = 0
        self._dot_timer = QTimer(self)
        self._dot_timer.timeout.connect(self._animate_dots)
        self._dot_timer.start(500)
        
        # Center on screen
        self._center_on_screen()
        
        # Start container initialization
        self._init_thread = ContainerInitThread()
        self._init_thread.finished_ok.connect(self._on_success)
        self._init_thread.error.connect(self._on_error)
        self._init_thread.start()
        
    def _center_on_screen(self):
        """Center the splash screen on the primary screen."""
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
        
    def _animate_dots(self):
        """Animate the loading dots."""
        self._dot_count = (self._dot_count + 1) % 4
        dots = "." * self._dot_count
        self.status_label.setText(f"Initializing containers{dots}")
        
    def _on_success(self):
        """Handle successful container initialization."""
        self._dot_timer.stop()
        self.status_label.setText("Ready!")
        # Small delay before showing main window
        QTimer.singleShot(500, lambda: self.containers_ready.emit())
        
    def _on_error(self, error: str):
        """Handle container initialization error."""
        self._dot_timer.stop()
        self.status_label.setText("Error!")
        self.containers_error.emit(error)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PYFA - Portable Yara File Analyzer")
        self.setWindowIcon(QIcon(ICON_PATH))
        self.resize(700, 400)
        layout = QVBoxLayout(self)

        # Containers are already initialized by splash screen
        self._containers_ready = True

        dest_layout = QHBoxLayout()
        self.chk_run_name = QLineEdit()
        self.chk_run_name.setPlaceholderText(f"Enter run name... (default: {self.get_run_name()})")
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

        analysis_row = QHBoxLayout()
        self.chk_group_by_tags = QCheckBox("Group output by tags instead of rules")
        analysis_row.addWidget(self.chk_group_by_tags)
        self.chk_use_database = QCheckBox("Use database for rules")
        self.chk_use_database.stateChanged.connect(self._on_use_database_changed)
        analysis_row.addWidget(self.chk_use_database)
        
        # Tag selector dropdown (hidden by default, shown when database is enabled)
        self.tag_dropdown = MultiSelectTagDropdown()
        self.tag_dropdown.setVisible(False)
        self.tag_dropdown.setMinimumWidth(200)
        self.tag_dropdown.setMaximumWidth(350)
        analysis_row.addWidget(self.tag_dropdown)
        
        analysis_row.addStretch()
        layout.addLayout(analysis_row)

        action_row = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_start.clicked.connect(self.start_copy)
        action_row.addWidget(self.btn_start)
        layout.addLayout(action_row)

        self.set_destination(REMOTE_FILES_DIR)
        self.worker = None
        self.progress_dialog = None
        self.tag_loader = None
        self._tags_loaded = False

    def _on_use_database_changed(self, state):
        """Handle database checkbox state change."""
        is_checked = state == Qt.CheckState.Checked.value
        self.tag_dropdown.setVisible(is_checked)
        
        if is_checked and not self._tags_loaded:
            # Load tags from database in background
            self._load_tags_from_database()
            
    def _load_tags_from_database(self):
        """Load available tags from database."""
        self.tag_dropdown.select_button.setText("Loading...")
        self.tag_dropdown.select_button.setEnabled(False)
        
        self.tag_loader = TagLoaderThread()
        self.tag_loader.tags_loaded.connect(self._on_tags_loaded)
        self.tag_loader.error.connect(self._on_tags_load_error)
        self.tag_loader.start()
        
    def _on_tags_loaded(self, tags: list):
        """Handle successful tags loading."""
        self.tag_dropdown.set_tags(tags)
        self.tag_dropdown.select_button.setText("Select Tags...")
        self.tag_dropdown.select_button.setEnabled(True)
        self._tags_loaded = True
        
    def _on_tags_load_error(self, error: str):
        """Handle tags loading error."""
        self.tag_dropdown.select_button.setText("Error loading")
        self.tag_dropdown.select_button.setEnabled(True)
        QMessageBox.warning(self, "Database Error", f"Failed to load tags from database:\n{error}")

    def get_run_name(self, base: str = "yara_run"):
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
        self.run_name = self.get_run_name( run_name if run_name else 'yara_run' ) 
        print(f"Run destination: {self.dest_dir}, run name: {self.run_name}")
        dest_path = os.path.join(self.dest_dir, self.run_name)
        try:
            os.makedirs(dest_path, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Cannot create destination directory '{dest_path}': {e}")
            return
        self.set_destination(dest_path)

        paths = [self.files_list.item(i).text() for i in range(self.files_list.count())]
        move = self.chk_move.isChecked()
        self._set_ui_enabled(False)
        
        # Create and show progress dialog
        self.progress_dialog = ProgressDialog(self)
        self.progress_dialog.btn_cancel.clicked.connect(self.cancel_copy)
        
        self.worker = FileCopyThread(paths, self.dest_dir, move)
        self.worker.progress.connect(self.progress_dialog.update_progress)
        self.worker.file_copied.connect(self.on_file_copied)
        self.worker.error.connect(self.on_error)
        self.worker.finished_ok.connect(self.on_finished)
        self.worker.start()
        
        self.progress_dialog.show()

    def start_analysis(self):
        #QMessageBox.information(self, "Analysis", "Starting analysis... (not implemented)")
        cmd = f"python3 /data/run-rules.py -f {self.run_name}"

        if self.chk_group_by_tags.isChecked():
            cmd += " -gt"

        if self.chk_use_database.isChecked():
            cmd += " -db"
            # Add selected tags if any
            selected_tags = self.tag_dropdown.get_selected_tags()
            if selected_tags:
                tags_str = " ".join(selected_tags)
                cmd += f" -t {tags_str}"
        
        yaralab.simple_test(cmd)

    def cancel_copy(self):
        if self.worker:
            self.worker.cancel()
            if self.progress_dialog:
                self.progress_dialog.update_status("Cancelling...")

    def on_file_copied(self, path):
        if self.progress_dialog:
            filename = os.path.basename(path)
            self.progress_dialog.update_status(f"Copied: {filename}")

    def on_error(self, message):
        QMessageBox.warning(self, "Copy error", message)

    def on_finished(self):
        #QMessageBox.information(self, "Done", "Copy/Move operation finished.")
        if self.progress_dialog:
            self.progress_dialog.update_status("Running YARA analysis...")
        
        # Run analysis after files are copied
        self.start_analysis()
        
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None
        self._set_ui_enabled(True)
        self.worker = None
        self.set_destination(REMOTE_FILES_DIR)

    def _set_ui_enabled(self, enabled: bool):
        self.btn_add.setEnabled(enabled)
        self.btn_remove.setEnabled(enabled)
        self.btn_clear.setEnabled(enabled)
        #self.btn_choose_dest.setEnabled(enabled)
        self.chk_move.setEnabled(enabled)
        self.btn_start.setEnabled(enabled)
        self.files_list.setEnabled(enabled)


def main():
    app = QApplication(sys.argv)
    
    # Show splash screen while initializing
    splash = SplashScreen()
    main_window = None
    
    def show_main_window():
        nonlocal main_window
        splash.close()
        main_window = MainWindow()
        main_window.show()
    
    def show_error(error: str):
        splash.close()
        QMessageBox.critical(None, "Docker Error", f"Failed to initialize containers:\n{error}")
        sys.exit(1)
    
    splash.containers_ready.connect(show_main_window)
    splash.containers_error.connect(show_error)
    splash.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
