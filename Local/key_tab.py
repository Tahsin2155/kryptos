"""
Kryptos Key Management Tab
============================

Manage encryption keys:
  - Generate system keys
  - Import custom keys (Base64 or Hex)
  - Create/view machine-specific key
  - List, rename, delete, copy, and export keys
"""

from __future__ import annotations

import base64

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import algo
from key_manager import KeyManager


class KeyTab(QWidget):
    """Key management tab."""

    def __init__(self, key_manager: KeyManager, parent=None):
        super().__init__(parent)
        self._km = key_manager
        self._setup_ui()
        self._refresh_table()

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(12)
        scroll.setWidget(scroll_content)
        outer.addWidget(scroll)

        # ----- Generate / Import Section -----
        gen_group = QGroupBox("Create or Import Key")
        gen_layout = QVBoxLayout(gen_group)
        gen_layout.setSpacing(10)

        # Generate system key
        gen_desc = QLabel("Generate a new random AES-256 key:")
        gen_desc.setStyleSheet("color: #a0a0b8; font-size: 12px;")
        gen_layout.addWidget(gen_desc)

        gen_row = QHBoxLayout()
        self._gen_name_input = QLineEdit()
        self._gen_name_input.setPlaceholderText("Key name (e.g. 'My Secure Key')")
        self._gen_name_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._gen_btn = QPushButton("Generate Key")
        self._gen_btn.clicked.connect(self._on_generate)
        gen_row.addWidget(self._gen_name_input, 1)
        gen_row.addWidget(self._gen_btn)
        gen_layout.addLayout(gen_row)

        # Separator
        sep = QLabel("")
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #2a2a4a;")
        gen_layout.addWidget(sep)

        # Import custom key
        import_desc = QLabel("Import a key from text:")
        import_desc.setStyleSheet("color: #a0a0b8; font-size: 12px;")
        gen_layout.addWidget(import_desc)

        import_row1 = QHBoxLayout()
        self._import_name_input = QLineEdit()
        self._import_name_input.setPlaceholderText("Key name")
        self._import_name_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._import_format_combo = QComboBox()
        self._import_format_combo.addItem("Base64", "b64")
        self._import_format_combo.addItem("Hex", "hex")
        import_row1.addWidget(self._import_name_input, 1)
        import_row1.addWidget(self._import_format_combo)
        gen_layout.addLayout(import_row1)

        import_row2 = QHBoxLayout()
        self._import_value_input = QLineEdit()
        self._import_value_input.setPlaceholderText("Key value (Base64 or Hex string)")
        self._import_btn = QPushButton("Import")
        self._import_btn.setProperty("class", "secondary")
        self._import_btn.clicked.connect(self._on_import)
        import_row2.addWidget(self._import_value_input, 1)
        import_row2.addWidget(self._import_btn)
        gen_layout.addLayout(import_row2)

        # Import from file
        import_file_row = QHBoxLayout()
        import_file_label = QLabel("Or import from a .key file:")
        self._import_file_btn = QPushButton("Import from File")
        self._import_file_btn.setProperty("class", "secondary")
        self._import_file_btn.clicked.connect(self._on_import_from_file)
        import_file_row.addWidget(import_file_label)
        import_file_row.addStretch()
        import_file_row.addWidget(self._import_file_btn)
        gen_layout.addLayout(import_file_row)

        # Separator
        sep2 = QLabel("")
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: #2a2a4a;")
        gen_layout.addWidget(sep2)

        # Machine key
        machine_row = QHBoxLayout()
        machine_label = QLabel("Machine-specific key (unique to this device):")
        machine_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self._machine_btn = QPushButton("Get Machine Key")
        self._machine_btn.setProperty("class", "success")
        self._machine_btn.clicked.connect(self._on_machine_key)
        machine_row.addWidget(machine_label)
        machine_row.addWidget(self._machine_btn)
        gen_layout.addLayout(machine_row)

        layout.addWidget(gen_group)

        # ----- Key Table -----
        table_group = QGroupBox("Stored Keys")
        table_layout = QVBoxLayout(table_group)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Mode", "Created", "Key (preview)"]
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        table_layout.addWidget(self._table)

        # Action buttons for selected key
        action_row = QHBoxLayout()
        action_row.setSpacing(8)

        self._copy_key_btn = QPushButton("Copy B64")
        self._copy_key_btn.setProperty("class", "secondary")
        self._copy_key_btn.setToolTip("Copy key as Base64 to clipboard")
        self._copy_key_btn.clicked.connect(self._on_copy_key)
        action_row.addWidget(self._copy_key_btn)

        self._copy_hex_btn = QPushButton("Copy Hex")
        self._copy_hex_btn.setProperty("class", "secondary")
        self._copy_hex_btn.setToolTip("Copy key as hexadecimal to clipboard")
        self._copy_hex_btn.clicked.connect(self._on_copy_hex)
        action_row.addWidget(self._copy_hex_btn)

        self._rename_btn = QPushButton("Rename")
        self._rename_btn.setProperty("class", "secondary")
        self._rename_btn.clicked.connect(self._on_rename)
        action_row.addWidget(self._rename_btn)

        self._export_btn = QPushButton("Export")
        self._export_btn.setProperty("class", "secondary")
        self._export_btn.setToolTip("Export key to a .key file")
        self._export_btn.clicked.connect(self._on_export)
        action_row.addWidget(self._export_btn)

        action_row.addStretch()

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.setProperty("class", "danger")
        self._delete_btn.clicked.connect(self._on_delete)
        action_row.addWidget(self._delete_btn)

        table_layout.addLayout(action_row)
        layout.addWidget(table_group, 1)

        # Status
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setMinimumHeight(24)
        self._status_label.setStyleSheet("padding: 4px 0; font-size: 13px;")
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

    # ----- Table refresh -----

    def _refresh_table(self) -> None:
        keys = self._km.list_keys()
        self._table.setRowCount(len(keys))
        for row, entry in enumerate(keys):
            name_item = QTableWidgetItem(entry.name)
            name_item.setData(Qt.ItemDataRole.UserRole, entry.key_id)
            self._table.setItem(row, 0, name_item)

            mode_item = QTableWidgetItem(entry.mode.capitalize())
            mode_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 1, mode_item)

            # Format created date nicely
            created = entry.created
            if "T" in created:
                created = created.split("T")[0]
            self._table.setItem(row, 2, QTableWidgetItem(created))

            # Show masked key with first/last few chars
            key_b64 = entry.key_b64
            if len(key_b64) > 12:
                masked = key_b64[:6] + "\u2026" + key_b64[-6:]
            else:
                masked = key_b64
            key_item = QTableWidgetItem(masked)
            key_item.setToolTip("Select row and use Copy to get full key")
            self._table.setItem(row, 3, key_item)

    def _selected_key_id(self) -> str | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        item = self._table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    # ----- Actions -----

    def _on_generate(self) -> None:
        name = self._gen_name_input.text().strip()
        if not name:
            name = "Untitled Key"
        try:
            entry = self._km.generate_system_key(name)
            self._gen_name_input.clear()
            self._refresh_table()
            self._set_status(
                f"Generated key '{entry.name}' — {entry.key_b64[:20]}...", "success"
            )
        except Exception as e:
            self._set_status(f"Error: {e}", "error")

    def _on_import(self) -> None:
        name = self._import_name_input.text().strip()
        value = self._import_value_input.text().strip()
        fmt = self._import_format_combo.currentData()

        if not name:
            name = "Imported Key"
        if not value:
            self._set_status("Please enter a key value.", "error")
            return

        try:
            if fmt == "hex":
                entry = self._km.import_hex_key(name, value)
            else:
                entry = self._km.import_custom_key(name, value)
            self._import_name_input.clear()
            self._import_value_input.clear()
            self._refresh_table()
            self._set_status(f"Imported key '{entry.name}' successfully.", "success")
        except Exception as e:
            self._set_status(f"Import failed: {e}", "error")

    def _on_machine_key(self) -> None:
        try:
            entry = self._km.get_or_create_machine_key()
            self._refresh_table()
            self._set_status(
                f"Machine key: {entry.name} — {entry.key_b64[:20]}...", "success"
            )
        except Exception as e:
            self._set_status(f"Error: {e}", "error")

    def _on_copy_key(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            self._set_status("Select a key first.", "warning")
            return
        entry = self._km.get_key(key_id)
        if entry:
            QApplication.clipboard().setText(entry.key_b64)
            self._set_status(f"Key '{entry.name}' (Base64) copied to clipboard!", "success")

    def _on_copy_hex(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            self._set_status("Select a key first.", "warning")
            return
        entry = self._km.get_key(key_id)
        if entry:
            try:
                raw = base64.urlsafe_b64decode(entry.key_b64)
                hex_str = raw.hex().upper()
                QApplication.clipboard().setText(hex_str)
                self._set_status(f"Key '{entry.name}' (Hex) copied to clipboard!", "success")
            except Exception as e:
                self._set_status(f"Copy failed: {e}", "error")

    def _on_rename(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            self._set_status("Select a key first.", "warning")
            return
        entry = self._km.get_key(key_id)
        if not entry:
            return
        new_name, ok = QInputDialog.getText(
            self, "Rename Key", "New name:", text=entry.name
        )
        if ok and new_name.strip():
            self._km.rename_key(key_id, new_name.strip())
            self._refresh_table()
            self._set_status(f"Renamed to '{new_name.strip()}'.", "success")

    def _on_export(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            self._set_status("Select a key first.", "warning")
            return
        entry = self._km.get_key(key_id)
        if not entry:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Key",
            f"{entry.name}.key",
            "Key Files (*.key);;Text Files (*.txt);;All Files (*)",
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"# Kryptos Key Export\n")
                    f.write(f"# Name: {entry.name}\n")
                    f.write(f"# Mode: {entry.mode}\n")
                    f.write(f"# Created: {entry.created}\n")
                    f.write(f"# Format: Base64 (URL-safe)\n")
                    f.write(f"# WARNING: Keep this file secure!\n\n")
                    f.write(entry.key_b64 + "\n")
                self._set_status(f"Key exported to {path}", "success")
            except OSError as e:
                self._set_status(f"Export failed: {e}", "error")

    def _on_import_from_file(self) -> None:
        """Import a key from a .key or text file."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Key File",
            "",
            "Key Files (*.key);;Text Files (*.txt);;All Files (*)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Parse name from header if present
            name = "Imported Key"
            key_value = None
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("# Name:"):
                    name = stripped[len("# Name:"):].strip()
                elif stripped and not stripped.startswith("#"):
                    key_value = stripped
                    break

            if not key_value:
                self._set_status("No key data found in file.", "error")
                return

            entry = self._km.import_custom_key(name, key_value)
            self._refresh_table()
            self._set_status(f"Imported key '{entry.name}' from file.", "success")
        except Exception as e:
            self._set_status(f"Import from file failed: {e}", "error")

    def _on_delete(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            self._set_status("Select a key first.", "warning")
            return
        entry = self._km.get_key(key_id)
        if not entry:
            return

        reply = QMessageBox.warning(
            self,
            "Delete Key",
            f"Are you sure you want to delete '{entry.name}'?\n\n"
            "WARNING: Any data encrypted with this key will become "
            "permanently unrecoverable!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._km.delete_key(key_id)
            self._refresh_table()
            self._set_status(f"Key '{entry.name}' deleted.", "warning")

    # ----- Status -----

    def _set_status(self, msg: str, level: str = "") -> None:
        self._status_label.setText(msg)
        if level == "success":
            self._status_label.setStyleSheet("color: #2ecc71; font-weight: 600;")
        elif level == "error":
            self._status_label.setStyleSheet("color: #e74c3c; font-weight: 600;")
        elif level == "warning":
            self._status_label.setStyleSheet("color: #f39c12; font-weight: 600;")
        else:
            self._status_label.setStyleSheet("color: #a0a0b8;")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh_table()
