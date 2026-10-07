"""AMR v0.5-C persistent sovereign identity registry (SQLite, local/single-node)."""
from __future__ import annotations

import sqlite3
import time

from identity.sovereign_identity import (
    ACTIVE, REVOKED, ROTATED, AuthenticationError, AuthorizationError,
    IdentityError, PublicKeyRecord,
)


class SQLiteSovereignIdentityRegistry:
    def __init__(self, db_path: str, timeout_seconds: float = 5.0):
        if not db_path:
            raise ValueError("db_path is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.db_path = db_path
        self.timeout_seconds = timeout_seconds
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(
            self.db_path, timeout=self.timeout_seconds, isolation_level=None
        )
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self):
        conn = None
        try:
            conn = self._connect()
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    active INTEGER NOT NULL CHECK(active IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                    algorithm TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE','ROTATED','REVOKED')),
                    not_before REAL NOT NULL,
                    not_after REAL,
                    revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS permissions (
                    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                    capability TEXT NOT NULL,
                    PRIMARY KEY(agent_id, capability)
                );
                CREATE TABLE IF NOT EXISTS retired_key_ids (
                    key_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    retired_at REAL NOT NULL,
                    reason TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS identity_audit (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    key_id TEXT,
                    related_key_id TEXT,
                    capability TEXT,
                    event_time REAL NOT NULL
                );
            """)
        except sqlite3.Error as exc:
            raise IdentityError("persistent identity initialization failed") from exc
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _validate_key(key: PublicKeyRecord):
        if not key.key_id or not key.public_key_pem:
            raise IdentityError("keyId and public key are required")
        if key.algorithm != "Ed25519":
            raise IdentityError("only Ed25519 is approved")
        if key.status != ACTIVE:
            raise IdentityError("new key must be ACTIVE")
        if key.not_after is not None and key.not_after < key.not_before:
            raise IdentityError("invalid key validity interval")

    def _write(self, operation):
        conn = None
        try:
            conn = self._connect()
            conn.execute("BEGIN IMMEDIATE")
            result = operation(conn)
            conn.commit()
            return result
        except IdentityError:
            if conn is not None:
                conn.rollback()
            raise
        except sqlite3.Error as exc:
            if conn is not None:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            raise IdentityError("persistent identity transaction failed") from exc
        finally:
            if conn is not None:
                conn.close()

    def register_agent(self, agent_id, public_key, permissions=None, at_time=None):
        if not agent_id:
            raise IdentityError("agentId is required")
        self._validate_key(public_key)
        ts = time.time() if at_time is None else float(at_time)

        def op(conn):
            if conn.execute("SELECT 1 FROM retired_key_ids WHERE key_id=?",
                            (public_key.key_id,)).fetchone():
                raise IdentityError("keyId was retired")
            try:
                conn.execute("INSERT INTO agents(agent_id,active) VALUES(?,1)", (agent_id,))
                conn.execute(
                    "INSERT INTO keys VALUES(?,?,?,?,?,?,?,?)",
                    (public_key.key_id, agent_id, public_key.algorithm,
                     public_key.public_key_pem, ACTIVE, public_key.not_before,
                     public_key.not_after, None),
                )
                for capability in set(permissions or set()):
                    conn.execute("INSERT INTO permissions VALUES(?,?)", (agent_id, capability))
                conn.execute(
                    "INSERT INTO identity_audit(event_type,agent_id,key_id,event_time) "
                    "VALUES('AGENT_REGISTERED',?,?,?)",
                    (agent_id, public_key.key_id, ts),
                )
            except sqlite3.IntegrityError as exc:
                raise IdentityError("agentId/keyId already registered") from exc
        self._write(op)

    def resolve_key(self, agent_id, key_id, at_time):
        conn = None
        try:
            conn = self._connect()
            agent = conn.execute("SELECT active FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if agent is None or agent[0] != 1:
                raise AuthenticationError("unknown or inactive agent")
            row = conn.execute(
                "SELECT agent_id,algorithm,public_key_pem,status,not_before,not_after,revoked_at "
                "FROM keys WHERE key_id=?", (key_id,)
            ).fetchone()
            if row is None or row[0] != agent_id:
                raise AuthenticationError("keyId is not bound to claimed agentId")
            _, algorithm, pem, status, not_before, not_after, revoked_at = row
            if status == REVOKED:
                raise AuthorizationError("key is revoked")
            if status == ROTATED:
                raise AuthorizationError("key is rotated")
            if at_time < not_before:
                raise AuthorizationError("key is not active yet")
            if not_after is not None and at_time > not_after:
                raise AuthorizationError("key is expired")
            return PublicKeyRecord(key_id, algorithm, pem, status, not_before, not_after, revoked_at)
        except IdentityError:
            raise
        except sqlite3.Error as exc:
            raise IdentityError("persistent identity read failed") from exc
        finally:
            if conn is not None:
                conn.close()

    def authorize(self, agent_id, key_id, capability, at_time):
        self.resolve_key(agent_id, key_id, at_time)
        conn = None
        try:
            conn = self._connect()
            allowed = conn.execute(
                "SELECT 1 FROM permissions WHERE agent_id=? AND capability=?",
                (agent_id, capability),
            ).fetchone()
            if allowed is None:
                raise AuthorizationError("capability denied")
            return True
        except IdentityError:
            raise
        except sqlite3.Error as exc:
            raise IdentityError("persistent authorization read failed") from exc
        finally:
            if conn is not None:
                conn.close()

    def rotate_key(self, agent_id, old_key_id, new_key, at_time,
                   *, administrative_authorized=False, failpoint=None):
        if not administrative_authorized:
            raise AuthorizationError("identity administration authorization required")
        self._validate_key(new_key)
        if new_key.not_before > at_time:
            raise IdentityError("new key activation is in the future")

        def op(conn):
            old = conn.execute(
                "SELECT algorithm,public_key_pem,status,not_before,not_after,revoked_at "
                "FROM keys WHERE key_id=? AND agent_id=?", (old_key_id, agent_id)
            ).fetchone()
            if old is None or old[2] != ACTIVE:
                raise IdentityError("old key is not ACTIVE/bound to agent")
            if conn.execute("SELECT 1 FROM keys WHERE key_id=?", (new_key.key_id,)).fetchone():
                raise IdentityError("new keyId already used")
            if conn.execute("SELECT 1 FROM retired_key_ids WHERE key_id=?",
                            (new_key.key_id,)).fetchone():
                raise IdentityError("new keyId was retired")
            conn.execute("UPDATE keys SET status=?,not_after=? WHERE key_id=?",
                         (ROTATED, at_time, old_key_id))
            conn.execute("INSERT INTO retired_key_ids VALUES(?,?,?,?)",
                         (old_key_id, agent_id, at_time, ROTATED))
            if failpoint == "after_retire":
                raise IdentityError("simulated rotation failure")
            conn.execute(
                "INSERT INTO keys VALUES(?,?,?,?,?,?,?,?)",
                (new_key.key_id, agent_id, new_key.algorithm, new_key.public_key_pem,
                 ACTIVE, new_key.not_before, new_key.not_after, None),
            )
            conn.execute(
                "INSERT INTO identity_audit(event_type,agent_id,key_id,related_key_id,event_time) "
                "VALUES('KEY_ROTATED',?,?,?,?)",
                (agent_id, old_key_id, new_key.key_id, at_time),
            )
        self._write(op)

    def revoke_key(self, agent_id, key_id, at_time, *, administrative_authorized=False):
        if not administrative_authorized:
            raise AuthorizationError("identity administration authorization required")

        def op(conn):
            row = conn.execute(
                "SELECT status FROM keys WHERE key_id=? AND agent_id=?", (key_id, agent_id)
            ).fetchone()
            if row is None or row[0] == REVOKED:
                raise IdentityError("unknown/already revoked key")
            conn.execute(
                "UPDATE keys SET status=?,not_after=?,revoked_at=? WHERE key_id=?",
                (REVOKED, at_time, at_time, key_id),
            )
            conn.execute(
                "INSERT OR IGNORE INTO retired_key_ids VALUES(?,?,?,?)",
                (key_id, agent_id, at_time, REVOKED),
            )
            conn.execute(
                "INSERT INTO identity_audit(event_type,agent_id,key_id,event_time) "
                "VALUES('KEY_REVOKED',?,?,?)", (agent_id, key_id, at_time),
            )
        self._write(op)

    def grant_permission(self, agent_id, capability, at_time=None,
                         *, administrative_authorized=False):
        if not administrative_authorized:
            raise AuthorizationError("identity administration authorization required")
        ts = time.time() if at_time is None else float(at_time)

        def op(conn):
            if conn.execute("SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)).fetchone() is None:
                raise IdentityError("unknown agentId")
            conn.execute("INSERT OR IGNORE INTO permissions VALUES(?,?)", (agent_id, capability))
            conn.execute(
                "INSERT INTO identity_audit(event_type,agent_id,capability,event_time) "
                "VALUES('PERMISSION_GRANTED',?,?,?)", (agent_id, capability, ts),
            )
        self._write(op)

    def audit_events(self):
        conn = None
        try:
            conn = self._connect()
            return conn.execute(
                "SELECT event_type,agent_id,key_id,related_key_id,capability,event_time "
                "FROM identity_audit ORDER BY event_id"
            ).fetchall()
        except sqlite3.Error as exc:
            raise IdentityError("persistent audit read failed") from exc
        finally:
            if conn is not None:
                conn.close()
