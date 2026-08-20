"""Fail-closed, board-local execution gates for production incidents.

This module deliberately does not execute production operations.  It owns the
persistent admission, approval, verifier-receipt, watchdog, and operator-outbox
contracts which an allowlisted adapter must satisfy.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass, replace
from typing import Optional

EVIDENCE_WINDOW_SECONDS = 30 * 60
HUMAN_BLOCKED = "human_blocked"
COMPLETED = "production_completed"


class StateConflict(ValueError):
    pass


@dataclass(frozen=True)
class GateSpec:
    action: str
    risk: str
    rollback: str
    verification_procedure: str
    target: str
    environment: str

    def replace(self, **changes: str) -> "GateSpec":
        return replace(self, **changes)


@dataclass(frozen=True)
class Incident:
    id: str
    task_id: str
    version: int
    state: str
    fence_token: int
    evidence_deadline: int
    spec_digest: str
    adapter_id: str


@dataclass(frozen=True)
class Notification:
    id: int
    incident_id: str
    target: str
    body: str


@dataclass(frozen=True)
class TickResult:
    reclaimed: list[str]
    blocked: list[str]


def spec_digest(spec: GateSpec) -> str:
    values = {key: getattr(spec, key).strip() for key in GateSpec.__dataclass_fields__}
    if any(not value for value in values.values()):
        raise ValueError("production gate spec requires non-empty action, risk, rollback, verification_procedure, target, and environment")
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _target_is_safe(target: str) -> bool:
    value = target.strip().lower()
    return bool(value) and "masa" not in value and "coach" not in value and "coaching" not in value


def install_schema(conn: sqlite3.Connection) -> None:
    """Install additive schema and DB-level P0 invariants. Idempotent."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
    if "production_incident_required" not in cols:
        conn.execute("ALTER TABLE tasks ADD COLUMN production_incident_required INTEGER NOT NULL DEFAULT 0")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS production_incidents (
      id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE, owner TEXT NOT NULL,
      operator_target TEXT NOT NULL, adapter_id TEXT NOT NULL, retry_safe INTEGER NOT NULL,
      state TEXT NOT NULL, version INTEGER NOT NULL, fence_token INTEGER NOT NULL,
      evidence_deadline INTEGER NOT NULL, spec_digest TEXT NOT NULL, created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS production_gate_specs (
      incident_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL,
      action TEXT NOT NULL, risk TEXT NOT NULL, rollback TEXT NOT NULL,
      verification_procedure TEXT NOT NULL, target TEXT NOT NULL, environment TEXT NOT NULL,
      created_at INTEGER NOT NULL, PRIMARY KEY(incident_id, version)
    );
    CREATE TABLE IF NOT EXISTS production_approvals (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, spec_digest TEXT NOT NULL,
      principal TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, invalidated_at INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS production_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, adapter_id TEXT NOT NULL,
      execution_id TEXT NOT NULL, fence_token INTEGER NOT NULL, spec_digest TEXT NOT NULL,
      attestation TEXT NOT NULL, accepted_at INTEGER NOT NULL,
      UNIQUE(incident_id, execution_id, fence_token)
    );
    CREATE TABLE IF NOT EXISTS production_incident_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, kind TEXT NOT NULL,
      payload TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS production_notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, target TEXT NOT NULL,
      dedupe_key TEXT NOT NULL UNIQUE, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      lease_until INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
      acknowledged_at INTEGER, dead_letter_at INTEGER, created_at INTEGER NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS production_required_before_dispatch
    BEFORE UPDATE OF status ON tasks WHEN NEW.production_incident_required = 1
      AND NEW.status IN ('ready','running')
      AND NOT EXISTS (SELECT 1 FROM production_incidents i WHERE i.task_id=NEW.id
          AND i.state = 'approved_executing')
    BEGIN SELECT RAISE(ABORT, 'P0 task requires approved production execution'); END;
    CREATE TRIGGER IF NOT EXISTS production_required_before_done
    BEFORE UPDATE OF status ON tasks WHEN NEW.production_incident_required = 1 AND NEW.status='done'
      AND NOT EXISTS (SELECT 1 FROM production_incidents i WHERE i.task_id=NEW.id
          AND i.state = 'production_completed')
    BEGIN SELECT RAISE(ABORT, 'P0 task lacks verified production completion'); END;
    CREATE TRIGGER IF NOT EXISTS production_required_is_irrevocable
    BEFORE UPDATE OF production_incident_required ON tasks
    WHEN OLD.production_incident_required = 1 AND NEW.production_incident_required = 0
    BEGIN SELECT RAISE(ABORT, 'P0 guard cannot be removed'); END;
    CREATE TRIGGER IF NOT EXISTS production_incident_not_orphaned
    BEFORE DELETE ON tasks WHEN OLD.production_incident_required = 1
      AND EXISTS (SELECT 1 FROM production_incidents i WHERE i.task_id=OLD.id AND i.state NOT IN ('production_completed','human_blocked'))
    BEGIN SELECT RAISE(ABORT, 'active production incident cannot be orphaned'); END;
    """)


def _event(conn: sqlite3.Connection, incident_id: str, kind: str, now: int, **payload: object) -> None:
    conn.execute("INSERT INTO production_incident_events (incident_id,kind,payload,created_at) VALUES (?,?,?,?)", (incident_id, kind, json.dumps(payload, sort_keys=True), now))


def _outbox(conn: sqlite3.Connection, incident_id: str, target: str, kind: str, now: int) -> None:
    if not _target_is_safe(target):
        raise ValueError("operator target must be configured outside coaching/Masa")
    conn.execute("INSERT OR IGNORE INTO production_notifications (incident_id,target,dedupe_key,body,next_attempt_at,created_at) VALUES (?,?,?,?,?,?)", (incident_id, target, f"{incident_id}:{kind}", f"P0 {incident_id}: {kind}", now, now))


def admit_p0_task(conn: sqlite3.Connection, *, title: str, assignee: str, owner: str, operator_target: str, gate_spec: GateSpec, now: int, adapter_id: str = "manual", retry_safe: bool = False) -> tuple[str, str]:
    if not _target_is_safe(operator_target):
        raise ValueError("operator target must be configured outside coaching/Masa")
    digest = spec_digest(gate_spec)
    task_id, incident_id = "p0_" + secrets.token_hex(8), "pi_" + secrets.token_hex(8)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("INSERT INTO tasks (id,title,assignee,status,created_at,production_incident_required) VALUES (?,?,?,'triage',?,1)", (task_id, title.strip(), assignee, now))
        conn.execute("INSERT INTO production_incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (incident_id, task_id, owner, operator_target, adapter_id, int(retry_safe), "registered", 1, 1, now + EVIDENCE_WINDOW_SECONDS, digest, now, now))
        conn.execute("INSERT INTO production_gate_specs VALUES (?,?,?,?,?,?,?,?,?,?)", (incident_id, 1, digest, gate_spec.action, gate_spec.risk, gate_spec.rollback, gate_spec.verification_procedure, gate_spec.target, gate_spec.environment, now))
        _event(conn, incident_id, "registered", now, task_id=task_id, digest=digest)
        _outbox(conn, incident_id, operator_target, "admitted", now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return task_id, incident_id


def get_incident(conn: sqlite3.Connection, incident_id: str) -> Incident:
    row = conn.execute("SELECT id,task_id,version,state,fence_token,evidence_deadline,spec_digest,adapter_id FROM production_incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise ValueError("unknown production incident")
    return Incident(*row)


def _cas(conn: sqlite3.Connection, incident_id: str, expected_version: int, *, state: str, now: int, **fields: object) -> Incident:
    assignments = ["state=?", "version=version+1", "updated_at=?"]
    values: list[object] = [state, now]
    for key, value in fields.items():
        assignments.append(f"{key}=?"); values.append(value)
    values += [incident_id, expected_version]
    cur = conn.execute(f"UPDATE production_incidents SET {', '.join(assignments)} WHERE id=? AND version=?", values)
    if cur.rowcount != 1:
        raise StateConflict("stale incident version")
    return get_incident(conn, incident_id)


def require_approval(conn: sqlite3.Connection, incident_id: str, *, expected_version: int, now: int) -> Incident:
    with conn:
        incident = _cas(conn, incident_id, expected_version, state="approval_required", now=now)
        _event(conn, incident_id, "approval_required", now, version=incident.version)
        _outbox(conn, incident_id, conn.execute("SELECT operator_target FROM production_incidents WHERE id=?", (incident_id,)).fetchone()[0], "approval_required", now)
    return incident


def grant_approval(conn: sqlite3.Connection, incident_id: str, *, principal: str, expected_version: int, expires_at: int, now: int) -> Incident:
    if not principal.strip() or principal.strip() in {"worker", "executor"} or expires_at <= now:
        raise ValueError("approval requires non-worker principal and future expiry")
    with conn:
        incident = get_incident(conn, incident_id)
        if incident.version != expected_version or incident.state != "approval_required": raise StateConflict("approval is no longer required")
        conn.execute("INSERT INTO production_approvals (incident_id,spec_digest,principal,expires_at,created_at) VALUES (?,?,?,?,?)", (incident_id, incident.spec_digest, principal, expires_at, now))
        incident = _cas(conn, incident_id, expected_version, state="approved_dispatching", now=now)
        _event(conn, incident_id, "approved", now, principal=principal, expires_at=expires_at)
    return incident


def begin_approved_execution(conn: sqlite3.Connection, incident_id: str, *, expected_version: int, now: int) -> Incident:
    """Consume a live approval and make the bound task dispatchable once."""
    with conn:
        incident = get_incident(conn, incident_id)
        if incident.version != expected_version or incident.state != "approved_dispatching":
            raise StateConflict("incident is not awaiting approved execution")
        approval = conn.execute(
            "SELECT id FROM production_approvals WHERE incident_id=? AND spec_digest=? "
            "AND invalidated_at IS NULL AND used_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 1",
            (incident_id, incident.spec_digest, now),
        ).fetchone()
        if not approval:
            raise StateConflict("no live approval for execution")
        conn.execute("UPDATE production_approvals SET used_at=? WHERE id=?", (now, approval[0]))
        incident = _cas(conn, incident_id, expected_version, state="approved_executing", now=now)
        conn.execute("UPDATE tasks SET status='ready' WHERE id=?", (incident.task_id,))
        _event(conn, incident_id, "execution_started", now, fence=incident.fence_token)
    return incident


def update_gate_spec(conn: sqlite3.Connection, incident_id: str, gate_spec: GateSpec, *, expected_version: int, now: int) -> Incident:
    digest = spec_digest(gate_spec)
    with conn:
        incident = get_incident(conn, incident_id)
        if incident.version != expected_version: raise StateConflict("stale incident version")
        next_version = incident.version + 1
        conn.execute("UPDATE production_approvals SET invalidated_at=? WHERE incident_id=? AND invalidated_at IS NULL", (now, incident_id))
        conn.execute("INSERT INTO production_gate_specs VALUES (?,?,?,?,?,?,?,?,?,?)", (incident_id, next_version, digest, gate_spec.action, gate_spec.risk, gate_spec.rollback, gate_spec.verification_procedure, gate_spec.target, gate_spec.environment, now))
        incident = _cas(conn, incident_id, expected_version, state="approval_required", now=now, spec_digest=digest)
        _event(conn, incident_id, "spec_updated", now, digest=digest)
    return incident


def accept_verified_receipt(conn: sqlite3.Connection, *, incident_id: str, adapter_id: str, execution_id: str, fence_token: int, spec_digest: str, attestation: str, now: int) -> Incident:
    if not attestation.startswith("verified:"):
        raise ValueError("receipt lacks verifier attestation")
    with conn:
        incident = get_incident(conn, incident_id)
        if incident.adapter_id != adapter_id or incident.fence_token != fence_token or incident.spec_digest != spec_digest:
            raise StateConflict("stale or foreign receipt")
        if incident.state != "approved_executing":
            raise StateConflict("receipt requires approved execution")
        conn.execute("INSERT INTO production_evidence (incident_id,adapter_id,execution_id,fence_token,spec_digest,attestation,accepted_at) VALUES (?,?,?,?,?,?,?)", (incident_id, adapter_id, execution_id, fence_token, spec_digest, attestation, now))
        incident = _cas(conn, incident_id, incident.version, state=COMPLETED, now=now, evidence_deadline=now + EVIDENCE_WINDOW_SECONDS)
        _event(conn, incident_id, "evidence_accepted", now, execution_id=execution_id)
    return incident


def controller_tick(conn: sqlite3.Connection, *, now: int) -> TickResult:
    reclaimed: list[str] = []; blocked: list[str] = []
    rows = conn.execute("SELECT id,version,state,retry_safe,operator_target FROM production_incidents WHERE state NOT IN (?,?) AND evidence_deadline <= ?", (COMPLETED, HUMAN_BLOCKED, now)).fetchall()
    for incident_id, version, state, retry_safe, target in rows:
        with conn:
            if retry_safe:
                updated = _cas(conn, incident_id, version, state="reclaiming", now=now, fence_token=get_incident(conn, incident_id).fence_token + 1)
                _event(conn, incident_id, "reclaimed", now, fence=updated.fence_token); reclaimed.append(incident_id)
            else:
                _cas(conn, incident_id, version, state=HUMAN_BLOCKED, now=now)
                _event(conn, incident_id, HUMAN_BLOCKED, now, reason="evidence deadline elapsed")
                _outbox(conn, incident_id, target, HUMAN_BLOCKED, now); blocked.append(incident_id)
    return TickResult(reclaimed, blocked)


def claim_notification(conn: sqlite3.Connection, *, now: int) -> Optional[Notification]:
    row = conn.execute("SELECT id,incident_id,target,body FROM production_notifications WHERE status='pending' AND next_attempt_at <= ? ORDER BY id LIMIT 1", (now,)).fetchone()
    if not row: return None
    with conn:
        cur = conn.execute("UPDATE production_notifications SET status='leased',lease_until=?,attempts=attempts+1 WHERE id=? AND status='pending'", (now + 60, row[0]))
        if cur.rowcount != 1: return None
    return Notification(*row)


def register_legacy_incidents(conn: sqlite3.Connection, *, now: int) -> list[str]:
    ids = []
    for issue, adapter, retry in ((335, "manual", False), (328, "manual", False), (336, "manual", False)):
        existing = conn.execute("SELECT id FROM production_incidents WHERE task_id=?", (f"legacy-{issue}",)).fetchone()
        if existing: ids.append(existing[0]); continue
        task, incident = admit_p0_task(conn, title=f"fitness-system#{issue}", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=GateSpec("execute approved production gate", "production impact", "follow documented rollback", "capture verifier receipt", f"fitness-system#{issue}", "production"), now=now, adapter_id=adapter, retry_safe=retry)
        conn.execute("UPDATE production_incidents SET task_id=? WHERE id=?", (f"legacy-{issue}", incident)); conn.execute("UPDATE tasks SET id=? WHERE id=?", (f"legacy-{issue}", task)); ids.append(incident)
    return ids
