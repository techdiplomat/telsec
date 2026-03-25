"""
TelSec - Structured Logger
===========================
Provides a Rich-formatted console logger plus SQLite audit trail.
Every action (test run, finding, user action) is persisted to the DB.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from rich.logging import RichHandler
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

_DB_PATH = os.environ.get("TELEAUDIT_DB", "teleaudit.db")
_DB_LOCK = threading.Lock()
_LOGGERS: dict[str, logging.Logger] = {}

# ---------------------------------------------------------------------------
# DB initialization
# ---------------------------------------------------------------------------

def _init_db(db_path: str = _DB_PATH) -> None:
    """Create audit log table if it doesn't exist."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT    NOT NULL,
                level    TEXT    NOT NULL,
                module   TEXT    NOT NULL,
                message  TEXT    NOT NULL,
                extra    TEXT
            )
        """)
        conn.commit()


try:
    _init_db()
except Exception:
    pass  # Non-fatal — log to console only if DB unavailable


# ---------------------------------------------------------------------------
# SQLite handler
# ---------------------------------------------------------------------------

class SQLiteHandler(logging.Handler):
    """Persist log records to the TelSec audit database."""

    def __init__(self, db_path: str = _DB_PATH):
        super().__init__()
        self.db_path = db_path

    def emit(self, record: logging.LogRecord) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        try:
            with _DB_LOCK, sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO audit_log (ts, level, module, message) VALUES (?,?,?,?)",
                    (ts, record.levelname, record.name, self.format(record)),
                )
                conn.commit()
        except Exception:
            pass  # Never crash on logging failure


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Return (or create) a named logger with Rich console + SQLite handlers.

    Args:
        name:  Logger name (usually the calling module's __name__)
        level: Logging level string

    Returns:
        Configured logging.Logger instance
    """
    if name in _LOGGERS:
        return _LOGGERS[name]

    log = logging.getLogger(f"teleaudit.{name}")
    log.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not log.handlers:
        # Console handler
        if _HAS_RICH:
            console_handler = RichHandler(
                rich_tracebacks=True,
                show_path=False,
                markup=True,
            )
        else:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
                    datefmt="%H:%M:%S",
                )
            )

        # File handler
        file_handler = logging.FileHandler("teleaudit.log", encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
            )
        )

        # SQLite handler
        db_handler = SQLiteHandler()

        log.addHandler(console_handler)
        log.addHandler(file_handler)
        log.addHandler(db_handler)
        log.propagate = False

    _LOGGERS[name] = log
    return log


def get_audit_log(limit: int = 200, level: Optional[str] = None) -> list[dict]:
    """
    Retrieve recent audit log entries from SQLite.

    Args:
        limit: Max rows to return
        level: Optional filter (DEBUG/INFO/WARNING/ERROR)

    Returns:
        List of dicts with keys: id, ts, level, module, message
    """
    try:
        with sqlite3.connect(_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            if level:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE level=? ORDER BY id DESC LIMIT ?",
                    (level.upper(), limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []
