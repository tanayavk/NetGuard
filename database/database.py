"""
database/database.py
────────────────────
Single source of truth for all database operations.

Responsibilities
  • Create / migrate the SQLite schema on first run
  • Provide helper functions used by both the traffic generator
    and the detection engine (no logic lives here — only I/O)

Schema
  traffic_logs
    id          INTEGER  PRIMARY KEY AUTOINCREMENT
    timestamp   REAL     UNIX epoch (float) — indexed for fast window queries
    source_ip   TEXT     NOT NULL
    dest_ip     TEXT     NOT NULL
    packets     INTEGER  NOT NULL
    bytes       INTEGER  NOT NULL
    protocol    TEXT     NOT NULL  (TCP / UDP / ICMP)
    port        INTEGER

  blocked_ips
    ip          TEXT     PRIMARY KEY
    blocked_at  REAL     UNIX epoch
    reason      TEXT
"""

import sqlite3
import time
import os
from contextlib import contextmanager
from typing import Generator

# ── Path resolution ──────────────────────────────────────────────────────────
# Works whether you run from project root or from inside database/
_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_HERE, "ddos.db")


# ── Connection helper ─────────────────────────────────────────────────────────
@contextmanager
def get_connection(path: str = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Yield a WAL-mode connection and commit / close it automatically."""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode: allows concurrent readers while writer is active
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema init ───────────────────────────────────────────────────────────────
def init_db(path: str = DB_PATH) -> None:
    """Create tables and indexes if they do not already exist."""
    with get_connection(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                source_ip   TEXT    NOT NULL,
                dest_ip     TEXT    NOT NULL,
                packets     INTEGER NOT NULL DEFAULT 1,
                bytes       INTEGER NOT NULL DEFAULT 0,
                protocol    TEXT    NOT NULL DEFAULT 'TCP',
                port        INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_timestamp
                ON traffic_logs (timestamp);

            CREATE INDEX IF NOT EXISTS idx_source_ip
                ON traffic_logs (source_ip);

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip         TEXT PRIMARY KEY,
                blocked_at REAL NOT NULL,
                reason     TEXT
            );
            """
        )
    print(f"[DB] Initialised → {path}")


# ── Write helpers ─────────────────────────────────────────────────────────────
def insert_log(
    source_ip: str,
    dest_ip: str,
    packets: int,
    bytes_: int,
    protocol: str = "TCP",
    port: int | None = None,
    timestamp: float | None = None,
    path: str = DB_PATH,
) -> None:
    """Insert a single traffic record. Called by traffic_generator."""
    ts = timestamp if timestamp is not None else time.time()
    with get_connection(path) as conn:
        conn.execute(
            """
            INSERT INTO traffic_logs (timestamp, source_ip, dest_ip,
                                      packets, bytes, protocol, port)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, source_ip, dest_ip, packets, bytes_, protocol, port),
        )


def insert_logs_bulk(rows: list[dict], path: str = DB_PATH) -> None:
    """
    Bulk-insert multiple log rows for efficiency.
    Each dict must have keys: source_ip, dest_ip, packets, bytes,
                               protocol (opt), port (opt), timestamp (opt)
    """
    now = time.time()
    records = [
        (
            r.get("timestamp", now),
            r["source_ip"],
            r["dest_ip"],
            r["packets"],
            r["bytes"],
            r.get("protocol", "TCP"),
            r.get("port"),
        )
        for r in rows
    ]
    with get_connection(path) as conn:
        conn.executemany(
            """
            INSERT INTO traffic_logs (timestamp, source_ip, dest_ip,
                                      packets, bytes, protocol, port)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            records,
        )


# ── Read helpers ──────────────────────────────────────────────────────────────
def fetch_window(window_seconds: float = 5.0, path: str = DB_PATH) -> list[dict]:
    """
    Return every raw log row from the last `window_seconds`.
    The detection engine aggregates these — this function only fetches.
    """
    cutoff = time.time() - window_seconds
    with get_connection(path) as conn:
        rows = conn.execute(
            """
            SELECT timestamp, source_ip, dest_ip,
                   packets, bytes, protocol, port
            FROM   traffic_logs
            WHERE  timestamp >= ?
            ORDER  BY timestamp ASC
            """,
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def fetch_aggregated_window(
    window_seconds: float = 5.0, path: str = DB_PATH
) -> list[dict]:
    """
    Return per-IP aggregated totals from the last `window_seconds`.
    Used directly by the Flask backend as a fast path when the full
    detector pipeline is not needed.
    """
    cutoff = time.time() - window_seconds
    with get_connection(path) as conn:
        rows = conn.execute(
            """
            SELECT source_ip,
                   SUM(packets)  AS total_packets,
                   SUM(bytes)    AS total_bytes,
                   COUNT(*)      AS log_count,
                   MAX(timestamp) AS last_seen
            FROM   traffic_logs
            WHERE  timestamp >= ?
            GROUP  BY source_ip
            ORDER  BY total_packets DESC
            """,
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Blocked-IP helpers ────────────────────────────────────────────────────────
def block_ip(ip: str, reason: str = "manual", path: str = DB_PATH) -> None:
    """Persist a blocked IP. Silently ignored if already present."""
    with get_connection(path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, reason)
            VALUES (?, ?, ?)
            """,
            (ip, time.time(), reason),
        )


def unblock_ip(ip: str, path: str = DB_PATH) -> None:
    with get_connection(path) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))


def get_blocked_ips(path: str = DB_PATH) -> list[dict]:
    with get_connection(path) as conn:
        rows = conn.execute(
            "SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def is_blocked(ip: str, path: str = DB_PATH) -> bool:
    with get_connection(path) as conn:
        row = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)
        ).fetchone()
    return row is not None


# ── Maintenance ───────────────────────────────────────────────────────────────
def purge_old_logs(older_than_seconds: float = 300.0, path: str = DB_PATH) -> int:
    """
    Delete logs older than `older_than_seconds` (default 5 min).
    Call this periodically from the traffic generator or a background thread
    to prevent unbounded DB growth.
    Returns the number of deleted rows.
    """
    cutoff = time.time() - older_than_seconds
    with get_connection(path) as conn:
        cur = conn.execute(
            "DELETE FROM traffic_logs WHERE timestamp < ?", (cutoff,)
        )
    return cur.rowcount


# ── CLI convenience ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print(f"[DB] Schema ready at {DB_PATH}")