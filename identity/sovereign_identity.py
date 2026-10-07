"""AMR v0.5-B sovereign identity registry.

Public verification material and authorization policy only.
Private signing keys never belong in this registry.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable


ACTIVE = "ACTIVE"
ROTATED = "ROTATED"
REVOKED = "REVOKED"
_ALLOWED_KEY_STATES = {ACTIVE, ROTATED, REVOKED}


class IdentityError(RuntimeError):
    """Identity registry state is invalid or unavailable."""


class AuthenticationError(IdentityError):
    """The claimed principal/key cannot authenticate."""


class AuthorizationError(IdentityError):
    """An authenticated principal lacks current authority."""


@dataclass(frozen=True)
class PublicKeyRecord:
    key_id: str
    algorithm: str
    public_key_pem: str
    status: str = ACTIVE
    not_before: float = 0.0
    not_after: float | None = None
    revoked_at: float | None = None


@dataclass
class AgentIdentity:
    agent_id: str
    permissions: set[str] = field(default_factory=set)
    keys: dict[str, PublicKeyRecord] = field(default_factory=dict)
    active: bool = True


class SovereignIdentityRegistry:
    """Thread-safe in-process reference registry for v0.5-B policy semantics."""

    def __init__(self, audit_sink: Callable[[dict], None] | None = None):
        self._agents: dict[str, AgentIdentity] = {}
        self._key_owner: dict[str, str] = {}
        self._retired_key_ids: set[str] = set()
        self._lock = threading.RLock()
        self._audit_sink = audit_sink

    def _audit(self, event: dict) -> None:
        if self._audit_sink is not None:
            self._audit_sink(dict(event))

    @staticmethod
    def _validate_public_record(record: PublicKeyRecord) -> None:
        if not record.key_id or not record.public_key_pem:
            raise IdentityError("keyId and public key are required")
        if record.algorithm != "Ed25519":
            raise IdentityError("only Ed25519 is approved in v0.5-B")
        if record.status not in _ALLOWED_KEY_STATES:
            raise IdentityError("invalid key lifecycle state")
        if record.not_after is not None and record.not_after < record.not_before:
            raise IdentityError("invalid key validity interval")

    def register_agent(
        self,
        agent_id: str,
        public_key: PublicKeyRecord,
        permissions: set[str] | None = None,
    ) -> None:
        if not agent_id:
            raise IdentityError("agentId is required")
        self._validate_public_record(public_key)
        if public_key.status != ACTIVE:
            raise IdentityError("initial key must be ACTIVE")
        with self._lock:
            if agent_id in self._agents:
                raise IdentityError("agentId already registered")
            if public_key.key_id in self._key_owner or public_key.key_id in self._retired_key_ids:
                raise IdentityError("keyId already used")
            self._agents[agent_id] = AgentIdentity(
                agent_id=agent_id,
                permissions=set(permissions or set()),
                keys={public_key.key_id: public_key},
            )
            self._key_owner[public_key.key_id] = agent_id
            self._audit({"event": "AGENT_REGISTERED", "agentId": agent_id, "keyId": public_key.key_id})

    def resolve_key(self, agent_id: str, key_id: str, at_time: float) -> PublicKeyRecord:
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None or not agent.active:
                raise AuthenticationError("unknown or inactive agent")
            if self._key_owner.get(key_id) != agent_id:
                raise AuthenticationError("keyId is not bound to claimed agentId")
            record = agent.keys.get(key_id)
            if record is None:
                raise AuthenticationError("unknown keyId")
            if record.status == REVOKED:
                raise AuthorizationError("key is revoked")
            if record.status == ROTATED:
                raise AuthorizationError("key is rotated and cannot authorize new operations")
            if at_time < record.not_before:
                raise AuthorizationError("key is not active yet")
            if record.not_after is not None and at_time > record.not_after:
                raise AuthorizationError("key is expired")
            return record

    def authorize(self, agent_id: str, key_id: str, capability: str, at_time: float) -> bool:
        self.resolve_key(agent_id, key_id, at_time)
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None or capability not in agent.permissions:
                raise AuthorizationError("capability denied")
            return True

    def rotate_key(
        self,
        agent_id: str,
        old_key_id: str,
        new_key: PublicKeyRecord,
        at_time: float,
        *,
        administrative_authorized: bool = False,
    ) -> None:
        if not administrative_authorized:
            raise AuthorizationError("identity administration authorization required")
        self._validate_public_record(new_key)
        if new_key.status != ACTIVE:
            raise IdentityError("new rotation key must be ACTIVE")
        if new_key.not_before > at_time:
            raise IdentityError("new key activation is in the future")
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                raise IdentityError("unknown agentId")
            if self._key_owner.get(old_key_id) != agent_id:
                raise IdentityError("old key is not bound to agent")
            old = agent.keys[old_key_id]
            if old.status != ACTIVE:
                raise IdentityError("only an ACTIVE key can be rotated")
            if new_key.key_id in self._key_owner or new_key.key_id in self._retired_key_ids:
                raise IdentityError("new keyId was already used")
            agent.keys[old_key_id] = PublicKeyRecord(
                key_id=old.key_id, algorithm=old.algorithm,
                public_key_pem=old.public_key_pem, status=ROTATED,
                not_before=old.not_before, not_after=at_time,
                revoked_at=old.revoked_at,
            )
            agent.keys[new_key.key_id] = new_key
            self._key_owner[new_key.key_id] = agent_id
            self._retired_key_ids.add(old_key_id)
            self._audit({"event": "KEY_ROTATED", "agentId": agent_id,
                         "oldKeyId": old_key_id, "newKeyId": new_key.key_id, "at": at_time})

    def revoke_key(
        self,
        agent_id: str,
        key_id: str,
        at_time: float,
        *,
        administrative_authorized: bool = False,
    ) -> None:
        if not administrative_authorized:
            raise AuthorizationError("identity administration authorization required")
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None or self._key_owner.get(key_id) != agent_id:
                raise IdentityError("unknown agent/key binding")
            old = agent.keys[key_id]
            if old.status == REVOKED:
                raise IdentityError("key already revoked")
            agent.keys[key_id] = PublicKeyRecord(
                key_id=old.key_id, algorithm=old.algorithm,
                public_key_pem=old.public_key_pem, status=REVOKED,
                not_before=old.not_before, not_after=at_time, revoked_at=at_time,
            )
            self._retired_key_ids.add(key_id)
            self._audit({"event": "KEY_REVOKED", "agentId": agent_id, "keyId": key_id, "at": at_time})

    def grant_permission(
        self, agent_id: str, capability: str, *, administrative_authorized: bool = False
    ) -> None:
        if not administrative_authorized:
            raise AuthorizationError("identity administration authorization required")
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                raise IdentityError("unknown agentId")
            agent.permissions.add(capability)
            self._audit({"event": "PERMISSION_GRANTED", "agentId": agent_id, "capability": capability})

    def public_snapshot(self) -> dict:
        """Serialize only public identity state; never private signing material."""
        with self._lock:
            return {
                agent_id: {
                    "active": agent.active,
                    "permissions": sorted(agent.permissions),
                    "keys": {
                        key_id: {
                            "algorithm": key.algorithm,
                            "publicKey": key.public_key_pem,
                            "status": key.status,
                            "notBefore": key.not_before,
                            "notAfter": key.not_after,
                            "revokedAt": key.revoked_at,
                        }
                        for key_id, key in agent.keys.items()
                    },
                }
                for agent_id, agent in self._agents.items()
            }
