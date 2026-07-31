"""SQLite tabanli sorgu onbellegi - ayni IOC'yi ikinci kez sorgulamaz."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Optional

DEFAULT_PATH = os.path.join(os.path.expanduser("~"), ".iocforge", "cache.sqlite")
DEFAULT_TTL = 24 * 3600


class Cache:
    def __init__(self, path: str = DEFAULT_PATH, ttl: int = DEFAULT_TTL,
                 enabled: bool = True):
        self.ttl = ttl
        self.enabled = enabled
        self.conn: Optional[sqlite3.Connection] = None
        if not enabled:
            return
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS entries ("
            " provider TEXT, indicator TEXT, fetched_at REAL, payload TEXT,"
            " PRIMARY KEY (provider, indicator))")
        self.conn.commit()

    def get(self, provider: str, indicator: str) -> Optional[Any]:
        if not self.conn:
            return None
        row = self.conn.execute(
            "SELECT fetched_at, payload FROM entries WHERE provider=? AND indicator=?",
            (provider, indicator)).fetchone()
        if not row:
            return None
        fetched_at, payload = row
        if time.time() - fetched_at > self.ttl:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def put(self, provider: str, indicator: str, payload: Any) -> None:
        if not self.conn:
            return
        self.conn.execute(
            "INSERT OR REPLACE INTO entries VALUES (?,?,?,?)",
            (provider, indicator, time.time(), json.dumps(payload, ensure_ascii=False)))
        self.conn.commit()

    def purge(self) -> int:
        if not self.conn:
            return 0
        cursor = self.conn.execute("DELETE FROM entries WHERE fetched_at < ?",
                                   (time.time() - self.ttl,))
        self.conn.commit()
        return cursor.rowcount

    def clear(self) -> None:
        if self.conn:
            self.conn.execute("DELETE FROM entries")
            self.conn.commit()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
