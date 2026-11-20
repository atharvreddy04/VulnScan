import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "vulnscan.db"


class Base:
    class metadata:
        @staticmethod
        def create_all(bind=None):
            with sqlite3.connect(DB_PATH) as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host TEXT UNIQUE NOT NULL,
                        is_authorized INTEGER DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target_id INTEGER,
                        scan_type TEXT,
                        profile TEXT,
                        status TEXT,
                        summary TEXT
                    );
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        module TEXT,
                        title TEXT,
                        severity TEXT,
                        remediation TEXT,
                        details TEXT
                    );
                    """
                )


engine = None


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()