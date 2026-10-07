import abc
import math
import sqlite3
import time


class ReplayStoreError(RuntimeError):
    """Replay protection storage is unavailable or returned an indeterminate result."""


class ReplayStore(abc.ABC):
    @abc.abstractmethod
    def consume(self, snapshot_id: str, expires_at: float) -> bool:
        """Atomically return True once for an ID and False for an existing ID."""
        raise NotImplementedError


class SQLiteReplayStore(ReplayStore):
    """Durable replay protection for local and single-node deployments."""

    def __init__(self, db_path: str = "replay_store.db", timeout_seconds: float = 5.0):
        if not db_path:
            raise ValueError("db_path is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.db_path = db_path
        self.timeout_seconds = timeout_seconds
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=self.timeout_seconds)

    def _init_db(self):
        try:
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS seen_snapshots (
                        snapshot_id TEXT PRIMARY KEY,
                        expires_at REAL NOT NULL,
                        consumed_at REAL NOT NULL
                    )
                """)
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_expires_at "
                    "ON seen_snapshots (expires_at)"
                )
        except sqlite3.Error as exc:
            raise ReplayStoreError("replay store initialization failed") from exc

    def consume(self, snapshot_id: str, expires_at: float) -> bool:
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ReplayStoreError("snapshot_id must be a non-empty string")
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
            raise ReplayStoreError("expires_at must be numeric")
        if not math.isfinite(expires_at):
            raise ReplayStoreError("expires_at must be finite")
        try:
            with self._connect() as conn:
                conn.execute("PRAGMA busy_timeout=5000")
                cur = conn.execute(
                    "INSERT OR IGNORE INTO seen_snapshots "
                    "(snapshot_id, expires_at, consumed_at) VALUES (?, ?, ?)",
                    (snapshot_id, float(expires_at), time.time()),
                )
                return cur.rowcount == 1
        except sqlite3.Error as exc:
            raise ReplayStoreError("replay store consume failed") from exc

    def prune_expired(self, now_s: float | None = None) -> int:
        cutoff = time.time() if now_s is None else now_s
        if isinstance(cutoff, bool) or not isinstance(cutoff, (int, float)):
            raise ReplayStoreError("prune cutoff must be numeric")
        if not math.isfinite(cutoff):
            raise ReplayStoreError("prune cutoff must be finite")
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM seen_snapshots WHERE expires_at < ?",
                    (float(cutoff),),
                )
                return cur.rowcount
        except sqlite3.Error as exc:
            raise ReplayStoreError("replay store prune failed") from exc


class RedisReplayStore(ReplayStore):
    """Shared replay protection using atomic Redis SET NX EX semantics."""

    def __init__(self, client, key_prefix: str = "amr:replay:", minimum_ttl_s: int = 1):
        if client is None:
            raise ValueError("Redis client is required")
        self.client = client
        self.key_prefix = key_prefix
        self.minimum_ttl_s = minimum_ttl_s

    def consume(self, snapshot_id: str, expires_at: float) -> bool:
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ReplayStoreError("snapshot_id must be a non-empty string")
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
            raise ReplayStoreError("expires_at must be numeric")
        if not math.isfinite(expires_at):
            raise ReplayStoreError("expires_at must be finite")
        ttl = max(self.minimum_ttl_s, math.ceil(float(expires_at) - time.time()))
        try:
            result = self.client.set(
                self.key_prefix + snapshot_id, "1", nx=True, ex=ttl
            )
        except Exception as exc:
            raise ReplayStoreError("Redis replay store consume failed") from exc
        if result is True:
            return True
        if result in (False, None):
            return False
        raise ReplayStoreError("unexpected Redis replay store response")
