"""
logger_db.py
=============
High-performance SQLite database logger and structured audit log system.

Provides:
  - Thread-safe SQLite connection pool via SQLAlchemy.
  - Async-compatible batch insert for high-throughput event logging.
  - Append-only structured log file for auditability.
  - Query interface for the dashboard to retrieve recent events.

Schema:
  firewall_events(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    source_ip     TEXT    NOT NULL,
    threat_type   TEXT    NOT NULL,
    anomaly_score REAL    NOT NULL,
    action_taken  TEXT    NOT NULL,
    mitigation_latency_ms REAL,
    rule_status   TEXT    DEFAULT 'ACTIVE'
  )
"""

import json
import logging
import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Tuple

import config

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("firewall")


def setup_logging() -> logging.Logger:
    """
    Configure the global firewall logger with both console and
    rotating file handlers.
    """
    fw_logger = logging.getLogger("firewall")
    fw_logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    # Prevent duplicate handlers on re-init
    if fw_logger.handlers:
        return fw_logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    fw_logger.addHandler(console)

    # Rotating file handler
    os.makedirs(os.path.dirname(config.LOG_FILE) or ".", exist_ok=True)
    file_handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
    )
    file_handler.setFormatter(formatter)
    fw_logger.addHandler(file_handler)

    return fw_logger


# ---------------------------------------------------------------------------
# SQLite Database Manager
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS firewall_events (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp             TEXT    NOT NULL,
    source_ip             TEXT    NOT NULL,
    threat_type           TEXT    NOT NULL,
    anomaly_score         REAL    NOT NULL,
    action_taken          TEXT    NOT NULL,
    mitigation_latency_ms REAL,
    rule_status           TEXT    DEFAULT 'ACTIVE'
);
"""

_CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON firewall_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON firewall_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_rule_status ON firewall_events(rule_status);
"""

_INSERT_EVENT_SQL = """
INSERT INTO firewall_events
    (timestamp, source_ip, threat_type, anomaly_score, action_taken,
     mitigation_latency_ms, rule_status)
VALUES (?, ?, ?, ?, ?, ?, ?);
"""


class DatabaseManager:
    """
    Thread-safe SQLite database manager with write-ahead logging (WAL)
    for high-throughput concurrent reads/writes.

    Uses a dedicated writer thread to serialize all INSERT operations,
    preventing SQLite's "database is locked" errors under load.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or config.DATABASE_PATH
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)

        # Write queue for async batch inserts
        self._write_queue: queue.Queue = queue.Queue(maxsize=50000)
        self._running = False
        self._writer_thread: Optional[threading.Thread] = None

        # Initialize database schema
        self._init_db()

    def _init_db(self) -> None:
        """Create tables and indices if they don't exist."""
        with self._connect() as conn:
            conn.executescript(_CREATE_TABLE_SQL)
            conn.executescript(_CREATE_INDEX_SQL)
            conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.commit()
        logger.info("Database initialized at %s", self.db_path)

    @contextmanager
    def _connect(self):
        """Context manager for SQLite connections."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Async Writer Thread
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background writer thread."""
        if self._running:
            return
        self._running = True
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="db-writer"
        )
        self._writer_thread.start()
        logger.info("Database writer thread started")

    def stop(self) -> None:
        """Stop the background writer thread and flush remaining events."""
        self._running = False
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=5.0)
        logger.info("Database writer thread stopped")

    def _writer_loop(self) -> None:
        """
        Dedicated writer loop that batches INSERT operations.
        Commits in batches of up to 100 events or every 0.5s.
        """
        BATCH_SIZE = 100
        FLUSH_INTERVAL = 0.5

        with self._connect() as conn:
            batch: List[Tuple] = []
            last_flush = time.monotonic()

            while self._running or not self._write_queue.empty():
                try:
                    event = self._write_queue.get(timeout=0.1)
                    batch.append(event)
                except queue.Empty:
                    pass

                now = time.monotonic()
                if len(batch) >= BATCH_SIZE or (
                    batch and (now - last_flush) >= FLUSH_INTERVAL
                ):
                    try:
                        conn.executemany(_INSERT_EVENT_SQL, batch)
                        conn.commit()
                    except sqlite3.Error as e:
                        logger.error("DB batch insert error: %s", e)
                    batch.clear()
                    last_flush = now

            # Final flush
            if batch:
                try:
                    conn.executemany(_INSERT_EVENT_SQL, batch)
                    conn.commit()
                except sqlite3.Error as e:
                    logger.error("DB final flush error: %s", e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_event(
        self,
        source_ip: str,
        threat_type: str,
        anomaly_score: float,
        action_taken: str,
        mitigation_latency_ms: float = 0.0,
        rule_status: str = "ACTIVE",
    ) -> None:
        """
        Queue a firewall event for asynchronous database insertion.

        This method is non-blocking and thread-safe.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            self._write_queue.put_nowait(
                (timestamp, source_ip, threat_type, anomaly_score,
                 action_taken, mitigation_latency_ms, rule_status)
            )
        except queue.Full:
            logger.warning("Event write queue full — dropping event for %s", source_ip)

        # Also write to structured audit log
        audit_entry = {
            "ts": timestamp,
            "ip": source_ip,
            "threat": threat_type,
            "score": round(anomaly_score, 4),
            "action": action_taken,
            "latency_ms": round(mitigation_latency_ms, 2),
            "status": rule_status,
        }
        logger.info("EVENT | %s", json.dumps(audit_entry))

    def update_rule_status(self, source_ip: str, new_status: str) -> None:
        """
        Update the rule_status for the most recent event matching source_ip.
        Used when rules expire or are manually overridden.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE firewall_events SET rule_status = ? "
                "WHERE source_ip = ? AND rule_status = 'ACTIVE'",
                (new_status, source_ip),
            )
            conn.commit()

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve the most recent firewall events for the dashboard."""
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM firewall_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "threat_type": row["threat_type"],
                    "anomaly_score": row["anomaly_score"],
                    "action_taken": row["action_taken"],
                    "mitigation_latency_ms": row["mitigation_latency_ms"],
                    "rule_status": row["rule_status"],
                }
                for row in rows
            ]

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Retrieve all currently active block/rate-limit rules."""
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT source_ip, threat_type, anomaly_score, action_taken, "
                "timestamp, mitigation_latency_ms "
                "FROM firewall_events WHERE rule_status = 'ACTIVE' "
                "AND action_taken IN ('DROP_IP', 'RATE_LIMIT_IP') "
                "ORDER BY timestamp DESC",
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics for the dashboard."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM firewall_events"
            ).fetchone()[0]

            threats = conn.execute(
                "SELECT COUNT(*) FROM firewall_events WHERE threat_type != 'NORMAL'"
            ).fetchone()[0]

            active_blocks = conn.execute(
                "SELECT COUNT(*) FROM firewall_events "
                "WHERE rule_status = 'ACTIVE' AND action_taken IN ('DROP_IP', 'RATE_LIMIT_IP')"
            ).fetchone()[0]

            avg_latency_row = conn.execute(
                "SELECT AVG(mitigation_latency_ms) FROM firewall_events "
                "WHERE mitigation_latency_ms > 0"
            ).fetchone()
            avg_latency = avg_latency_row[0] if avg_latency_row[0] else 0.0

            # False positive rate estimation
            total_blocks = conn.execute(
                "SELECT COUNT(*) FROM firewall_events "
                "WHERE action_taken IN ('DROP_IP', 'RATE_LIMIT_IP')"
            ).fetchone()[0]
            expired_quickly = conn.execute(
                "SELECT COUNT(*) FROM firewall_events "
                "WHERE rule_status = 'EXPIRED_FP'"
            ).fetchone()[0]
            fpr = (expired_quickly / max(total_blocks, 1)) * 100

            return {
                "total_events": total,
                "total_threats": threats,
                "active_blocks": active_blocks,
                "avg_latency_ms": round(avg_latency, 2),
                "false_positive_rate": round(fpr, 2),
            }

    def get_threat_distribution(self) -> Dict[str, int]:
        """Get count of events grouped by threat type."""
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT threat_type, COUNT(*) as cnt "
                "FROM firewall_events GROUP BY threat_type ORDER BY cnt DESC"
            )
            return {row["threat_type"]: row["cnt"] for row in cursor.fetchall()}
