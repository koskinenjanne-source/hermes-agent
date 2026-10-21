"""Fail-closed, board-local execution gates for production incidents.

This module deliberately does not execute production operations.  It owns the
persistent admission, approval, verifier-receipt, watchdog, and operator-outbox
contracts which an allowlisted adapter must satisfy.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from dataclasses import dataclass, replace
from typing import Callable, Optional, Protocol

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
class OperatorRoute:
    """A named trust root bound to one physical platform destination."""
    target: str
    platform: str
    chat_id: str
    thread_id: str | None = None


@dataclass(frozen=True)
class Receipt:
    incident_id: str
    adapter_id: str
    execution_id: str
    fence_token: int
    spec_digest: str
    attestation: str


class ProductionAdapter(Protocol):
    """Configured adapter boundary; a receipt is trusted only after verify()."""
    adapter_id: str
    retry_safe: bool

    def execute(self, spec: GateSpec, idempotency_key: str, fence_token: int) -> str: ...
    def verify(self, receipt: Receipt) -> bool: ...


class AdapterRegistry:
    """Explicit allowlist.  Task metadata can never select an unregistered adapter."""
    def __init__(self, adapters: Optional[dict[str, ProductionAdapter]] = None):
        self._adapters = dict(adapters or {})

    def get(self, adapter_id: str) -> Optional[ProductionAdapter]:
        return self._adapters.get(adapter_id)


class ConfiguredHmacAdapter:
    """A configured verifier trust root, not an operation implementation.

    The adapter can verify a receipt from a separately configured production
    executor.  It intentionally refuses to execute: enabling a verifier must
    never turn a configuration entry into an ambient production capability.
    """
    def __init__(self, adapter_id: str, secret: str, retry_safe: bool):
        self.adapter_id = adapter_id
        self.retry_safe = retry_safe
        self._secret = secret.encode("utf-8")

    def execute(self, spec: GateSpec, idempotency_key: str, fence_token: int) -> str:
        raise RuntimeError("configured HMAC adapter is verifier-only; no production executor is registered")

    def verify(self, receipt: Receipt) -> bool:
        expected = hmac.new(self._secret, receipt_payload(receipt).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(receipt.attestation, expected)


class ConfiguredManualAdapter(ConfiguredHmacAdapter):
    """Explicitly enabled manual-execution lifecycle with HMAC receipts.

    ``execute`` does not perform the gate action. It only creates a stable
    execution identity for an operator to attest after completing the approved
    procedure. Completion remains impossible without a receipt verified by the
    configured trust root.
    """

    manual_executor = True

    def execute(self, spec: GateSpec, idempotency_key: str, fence_token: int) -> str:
        token = hashlib.sha256(
            f"manual-v1:{idempotency_key}:{fence_token}".encode("utf-8")
        ).hexdigest()[:24]
        return f"manual:{fence_token}:{token}"


def configured_adapter_registry(config: object, *, secret_resolver: Callable[[str], Optional[str]]) -> AdapterRegistry:
    """Build the runtime verifier registry solely from configured trust roots."""
    if not isinstance(config, dict):
        raise ValueError("production incident configuration must be a mapping")
    adapters = config.get("adapters", [])
    if not isinstance(adapters, list):
        raise ValueError("production incident adapters must be a list")
    registered: dict[str, ProductionAdapter] = {}
    for item in adapters:
        if not isinstance(item, dict):
            raise ValueError("production incident adapter must be a mapping")
        adapter_id = str(item.get("id", "")).strip()
        secret_env = str(item.get("secret_env", "")).strip()
        if not adapter_id or not secret_env or adapter_id in registered:
            raise ValueError("production incident adapter requires a unique id and secret_env")
        secret = secret_resolver(secret_env)
        if not secret:
            raise ValueError(f"production incident adapter secret is unavailable: {secret_env}")
        execution = str(item.get("execution", "verifier")).strip().lower()
        if execution == "manual":
            adapter_type = ConfiguredManualAdapter
        elif execution == "verifier":
            adapter_type = ConfiguredHmacAdapter
        else:
            raise ValueError("production incident adapter execution must be verifier or manual")
        registered[adapter_id] = adapter_type(adapter_id, secret, bool(item.get("retry_safe", False)))
    return AdapterRegistry(registered)


@dataclass(frozen=True)
class TickResult:
    reclaimed: list[str]
    blocked: list[str]
    dispatched: list[str]


def receipt_payload(receipt: Receipt) -> str:
    """Stable attestation payload; excludes the signature itself."""
    return json.dumps({
        "adapter_id": receipt.adapter_id, "execution_id": receipt.execution_id,
        "fence_token": receipt.fence_token, "incident_id": receipt.incident_id,
        "spec_digest": receipt.spec_digest,
    }, sort_keys=True, separators=(",", ":"))


def spec_digest(spec: GateSpec) -> str:
    values = {key: getattr(spec, key).strip() for key in GateSpec.__dataclass_fields__}
    if any(not value for value in values.values()):
        raise ValueError("production gate spec requires non-empty action, risk, rollback, verification_procedure, target, and environment")
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


_OPERATOR_DESTINATION_RE = re.compile(r"^operator(?:[-_][a-z0-9][a-z0-9_-]{0,62})?$")
_OPERATOR_PLATFORM_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def _parse_operator_target(target: object) -> tuple[str, str] | None:
    """Parse only named operator trust roots; never chat/topic identifiers."""
    if not isinstance(target, str) or target != target.strip():
        return None
    platform, separator, destination = target.partition(":")
    if not separator or ":" in destination:
        return None
    platform = platform.lower()
    destination = destination.lower()
    if not _OPERATOR_PLATFORM_RE.fullmatch(platform):
        return None
    # Numeric Telegram chat IDs and ``chat_id:topic_id`` are deliberately not
    # routing identities for this controller. A named operator trust root is
    # provisioned separately, which prevents a coaching group/topic from being
    # selected just by knowing its opaque destination id.
    if not _OPERATOR_DESTINATION_RE.fullmatch(destination):
        return None
    return platform, destination


def operator_target_is_safe(target: str, *, trusted_targets: object | None = None) -> bool:
    """Require a canonical named operator route and, when supplied, its trust root.

    ``trusted_targets`` is the configured route allowlist used by bootstrap,
    command ingress, and delivery. It is compared canonically and cannot bless
    opaque numeric or topic-shaped Telegram destinations.
    """
    route = _parse_operator_target(target)
    if route is None:
        return False
    if trusted_targets is None:
        return True
    if not isinstance(trusted_targets, (list, tuple, set, frozenset)):
        return False
    roots = {
        parsed
        for item in trusted_targets
        if (parsed := _parse_operator_target(item)) is not None
    }
    return route in roots


def configured_operator_routes(config: object) -> dict[str, OperatorRoute]:
    """Resolve named operator roots to physical routes from operator config only.

    Incident rows and task metadata retain the symbolic trust-root name.  The
    numeric chat/topic values appear only in this operator-owned mapping, so a
    task cannot redirect P0 ingress or egress by supplying an opaque Telegram
    destination.
    """
    if not isinstance(config, dict):
        raise ValueError("production incident configuration must be a mapping")
    targets = config.get("operator_targets", [])
    raw_routes = config.get("operator_routes", {})
    if not isinstance(targets, list) or not isinstance(raw_routes, dict):
        raise ValueError("production incident operator targets and routes must be configured")
    parsed_targets: dict[str, tuple[str, str]] = {}
    for target in targets:
        parsed = _parse_operator_target(target)
        if parsed is None:
            raise ValueError("operator target must be a named operator trust root")
        canonical = f"{parsed[0]}:{parsed[1]}"
        if canonical in parsed_targets:
            raise ValueError("production incident operator targets must be unique")
        parsed_targets[canonical] = parsed
    if set(raw_routes) != set(parsed_targets):
        raise ValueError("production incident operator routes must map every named trust root exactly once")
    routes: dict[str, OperatorRoute] = {}
    for target, (platform, _destination) in parsed_targets.items():
        route = raw_routes[target]
        if not isinstance(route, dict):
            raise ValueError("production incident operator route must be a mapping")
        chat_id = str(route.get("chat_id", "")).strip()
        raw_thread_id = route.get("thread_id")
        thread_id = str(raw_thread_id).strip() if raw_thread_id is not None else None
        if not chat_id or (raw_thread_id is not None and not thread_id):
            raise ValueError("production incident operator route requires a chat_id and optional non-empty thread_id")
        # Telegram's physical address is numeric.  Rejecting symbolic and
        # compound values here prevents a named route from smuggling a second
        # target or delegating resolution to the adapter.
        if platform == "telegram":
            if not re.fullmatch(r"-?\d+", chat_id) or (thread_id is not None and not re.fullmatch(r"\d+", thread_id)):
                raise ValueError("Telegram operator route requires numeric chat_id and thread_id")
        routes[target] = OperatorRoute(target, platform, chat_id, thread_id)
    return routes


def resolve_operator_route(target: str, *, config: object) -> OperatorRoute | None:
    """Return the configured physical route for one named trust root only."""
    try:
        return configured_operator_routes(config).get(target)
    except ValueError:
        return None


def operator_route_matches_source(
    route: OperatorRoute,
    *,
    platform: object,
    chat_id: object,
    thread_id: object = None,
) -> bool:
    """Require ingress to match the configured physical route exactly."""
    return (
        str(platform).strip().lower() == route.platform
        and str(chat_id).strip() == route.chat_id
        and (str(thread_id).strip() if thread_id is not None else None) == route.thread_id
    )


def configured_operator_route_for_source(
    config: object,
    *,
    platform: object,
    chat_id: object,
    thread_id: object = None,
) -> OperatorRoute | None:
    """Find the sole configured trust root bound to an authenticated source."""
    try:
        routes = configured_operator_routes(config).values()
    except ValueError:
        return None
    matches = [
        route for route in routes
        if operator_route_matches_source(route, platform=platform, chat_id=chat_id, thread_id=thread_id)
    ]
    return matches[0] if len(matches) == 1 else None


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
    CREATE TABLE IF NOT EXISTS production_executions (
      incident_id TEXT NOT NULL, execution_id TEXT NOT NULL, fence_token INTEGER NOT NULL,
      spec_digest TEXT NOT NULL, adapter_id TEXT NOT NULL, dispatched_at INTEGER NOT NULL,
      PRIMARY KEY(incident_id, execution_id, fence_token)
    );
    CREATE TABLE IF NOT EXISTS production_execution_claims (
      incident_id TEXT NOT NULL, fence_token INTEGER NOT NULL,
      spec_digest TEXT NOT NULL, adapter_id TEXT NOT NULL,
      idempotency_key TEXT NOT NULL, claimed_at INTEGER NOT NULL,
      PRIMARY KEY(incident_id, fence_token)
    );
    CREATE TABLE IF NOT EXISTS production_incident_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, kind TEXT NOT NULL,
      payload TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS production_notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, target TEXT NOT NULL,
      dedupe_key TEXT NOT NULL UNIQUE, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      lease_until INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
      acknowledged_at INTEGER, dead_letter_at INTEGER, last_error TEXT, last_error_at INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS production_required_insert_before_dispatch
    BEFORE INSERT ON tasks WHEN NEW.production_incident_required = 1
      AND NEW.status IN ('ready','running')
      AND NOT EXISTS (SELECT 1 FROM production_incidents i WHERE i.task_id=NEW.id
          AND i.state = 'approved_executing')
    BEGIN SELECT RAISE(ABORT, 'P0 task requires approved production execution'); END;
    CREATE TRIGGER IF NOT EXISTS production_required_insert_before_done
    BEFORE INSERT ON tasks WHEN NEW.production_incident_required = 1 AND NEW.status='done'
      AND NOT EXISTS (SELECT 1 FROM production_incidents i WHERE i.task_id=NEW.id
          AND i.state = 'production_completed')
    BEGIN SELECT RAISE(ABORT, 'P0 task lacks verified production completion'); END;
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
    notification_cols = {row[1] for row in conn.execute("PRAGMA table_info(production_notifications)")}
    if "last_error" not in notification_cols:
        conn.execute("ALTER TABLE production_notifications ADD COLUMN last_error TEXT")
    if "last_error_at" not in notification_cols:
        conn.execute("ALTER TABLE production_notifications ADD COLUMN last_error_at INTEGER")


def _event(conn: sqlite3.Connection, incident_id: str, kind: str, now: int, **payload: object) -> None:
    conn.execute("INSERT INTO production_incident_events (incident_id,kind,payload,created_at) VALUES (?,?,?,?)", (incident_id, kind, json.dumps(payload, sort_keys=True), now))


def _outbox(
    conn: sqlite3.Connection,
    incident_id: str,
    target: str,
    kind: str,
    now: int,
    *,
    body: str | None = None,
) -> None:
    if not operator_target_is_safe(target):
        raise ValueError("operator target must be a named operator trust root")
    conn.execute("INSERT OR IGNORE INTO production_notifications (incident_id,target,dedupe_key,body,next_attempt_at,created_at) VALUES (?,?,?,?,?,?)", (incident_id, target, f"{incident_id}:{kind}", body or f"P0 {incident_id}: {kind}", now, now))


def admit_p0_task(conn: sqlite3.Connection, *, title: str, assignee: str, owner: str, operator_target: str, gate_spec: GateSpec, now: int, adapter_id: str = "manual", retry_safe: bool = False, task_id: Optional[str] = None, incident_id: Optional[str] = None) -> tuple[str, str]:
    if not operator_target_is_safe(operator_target):
        raise ValueError("operator target must be a named operator trust root")
    digest = spec_digest(gate_spec)
    task_id = task_id or "p0_" + secrets.token_hex(8)
    incident_id = incident_id or "pi_" + secrets.token_hex(8)
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


def grant_approval(conn: sqlite3.Connection, incident_id: str, *, principal: str, expected_version: int, expires_at: int, now: int, allowed_principals: Optional[set[str]] = None) -> Incident:
    """Grant only from a gateway-provisioned principal allowlist, never task data."""
    if not allowed_principals or principal.strip() not in allowed_principals or expires_at <= now:
        raise ValueError("approval requires an allowlisted principal and future expiry")
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


def accept_adapter_receipt(conn: sqlite3.Connection, receipt: Receipt, *, registry: AdapterRegistry, now: int) -> Incident:
    """Persist only a verifier-authenticated receipt bound to the active fence."""
    adapter = registry.get(receipt.adapter_id)
    if adapter is None:
        raise ValueError("receipt adapter is not allowlisted")
    try:
        verified = adapter.verify(receipt)
    except Exception as exc:
        raise ValueError("receipt verifier unavailable") from exc
    if not verified:
        raise ValueError("receipt attestation rejected")
    with conn:
        incident = get_incident(conn, receipt.incident_id)
        if incident.adapter_id != receipt.adapter_id or incident.fence_token != receipt.fence_token or incident.spec_digest != receipt.spec_digest:
            raise StateConflict("stale or foreign receipt")
        if incident.state not in {"approved_executing", "verifying"}:
            raise StateConflict("receipt requires approved execution")
        if incident.evidence_deadline <= now:
            raise StateConflict("evidence deadline elapsed")
        execution = conn.execute("SELECT 1 FROM production_executions WHERE incident_id=? AND execution_id=? AND fence_token=? AND spec_digest=? AND adapter_id=?", (receipt.incident_id, receipt.execution_id, receipt.fence_token, receipt.spec_digest, receipt.adapter_id)).fetchone()
        if not execution:
            raise StateConflict("receipt is not bound to an approved adapter execution")
        conn.execute("INSERT INTO production_evidence (incident_id,adapter_id,execution_id,fence_token,spec_digest,attestation,accepted_at) VALUES (?,?,?,?,?,?,?)", (receipt.incident_id, receipt.adapter_id, receipt.execution_id, receipt.fence_token, receipt.spec_digest, receipt.attestation, now))
        # Make the deadline check part of the completion write itself.  A
        # verifier may finish just as the watchdog fences the incident; the
        # stale receipt must then roll back its evidence insert rather than win
        # based on an earlier read of the deadline.
        completed = conn.execute(
            "UPDATE production_incidents SET state=?,version=version+1,updated_at=?,evidence_deadline=? "
            "WHERE id=? AND version=? AND state IN ('approved_executing','verifying') "
            "AND adapter_id=? AND fence_token=? AND spec_digest=? AND evidence_deadline>?",
            (
                COMPLETED, now, now + EVIDENCE_WINDOW_SECONDS, receipt.incident_id,
                incident.version, receipt.adapter_id, receipt.fence_token,
                receipt.spec_digest, now,
            ),
        )
        if completed.rowcount != 1:
            raise StateConflict("evidence deadline elapsed or incident state changed")
        incident = get_incident(conn, receipt.incident_id)
        _event(conn, receipt.incident_id, "evidence_accepted", now, execution_id=receipt.execution_id, receipt_digest=hashlib.sha256(receipt.attestation.encode()).hexdigest())
    return incident


def accept_verified_receipt(conn: sqlite3.Connection, **_: object) -> Incident:
    """Removed unsafe compatibility route: raw worker strings are never evidence."""
    raise ValueError("raw attestations are not accepted; use a registered adapter verifier")


def _gate_spec(conn: sqlite3.Connection, incident: Incident) -> GateSpec:
    row = conn.execute("SELECT action,risk,rollback,verification_procedure,target,environment FROM production_gate_specs WHERE incident_id=? AND version=? AND digest=?", (incident.id, incident.version, incident.spec_digest)).fetchone()
    if not row:
        # The incident version increments for state transitions; retrieve the immutable
        # spec by digest instead, then reject ambiguity rather than guessing.
        row = conn.execute("SELECT action,risk,rollback,verification_procedure,target,environment FROM production_gate_specs WHERE incident_id=? AND digest=?", (incident.id, incident.spec_digest)).fetchone()
    if not row:
        raise StateConflict("active gate spec is missing")
    return GateSpec(*row)


def _quarantine_normal_task(conn: sqlite3.Connection, task_id: str, *, now: int) -> None:
    """Fence an expired P0 execution out of the ordinary Kanban worker path."""
    row = conn.execute(
        "SELECT status,current_run_id FROM tasks WHERE id=?", (task_id,)
    ).fetchone()
    if not row or row["status"] not in {"ready", "running"}:
        return
    run_id = row["current_run_id"]
    if run_id is not None:
        conn.execute(
            """
            UPDATE task_runs
               SET status='reclaimed', outcome='reclaimed', ended_at=?,
                   claim_lock=NULL, claim_expires=NULL, worker_pid=NULL,
                   summary=COALESCE(summary, 'production execution fence superseded')
             WHERE id=? AND ended_at IS NULL
            """,
            (now, run_id),
        )
    conn.execute(
        """
        UPDATE tasks
           SET status='triage', claim_lock=NULL, claim_expires=NULL,
               worker_pid=NULL, last_heartbeat_at=NULL, current_run_id=NULL
         WHERE id=? AND status IN ('ready','running')
        """,
        (task_id,),
    )


def _block_incident(conn: sqlite3.Connection, incident: Incident, *, now: int, reason: str, error: str | None = None) -> Incident:
    """Fence a runnable task before atomically recording a human-only block."""
    _quarantine_normal_task(conn, incident.task_id, now=now)
    payload = {"reason": reason}
    if error:
        payload["error"] = error[:200]
    blocked = _cas(conn, incident.id, incident.version, state=HUMAN_BLOCKED, now=now)
    _event(conn, incident.id, HUMAN_BLOCKED, now, **payload)
    target = conn.execute(
        "SELECT operator_target FROM production_incidents WHERE id=?", (incident.id,),
    ).fetchone()[0]
    _outbox(conn, incident.id, target, HUMAN_BLOCKED, now)
    return blocked


def _claim_adapter_execution(conn: sqlite3.Connection, incident_id: str, *, expected_version: int, now: int) -> Incident:
    """Persist sole adapter ownership before any external execution can begin."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        incident = get_incident(conn, incident_id)
        if (
            incident.version != expected_version
            or incident.state != "approved_executing"
            or incident.evidence_deadline <= now
        ):
            raise StateConflict("incident is not eligible for adapter dispatch")
        idempotency_key = f"{incident.id}:{incident.spec_digest}"
        conn.execute(
            "INSERT INTO production_execution_claims VALUES (?,?,?,?,?,?)",
            (incident.id, incident.fence_token, incident.spec_digest, incident.adapter_id, idempotency_key, now),
        )
        _quarantine_normal_task(conn, incident.task_id, now=now)
        claimed = _cas(conn, incident.id, expected_version, state="adapter_dispatching", now=now)
        _event(conn, incident.id, "adapter_claimed", now, fence=incident.fence_token)
        conn.execute("COMMIT")
        return claimed
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _record_adapter_execution(conn: sqlite3.Connection, incident: Incident, execution_id: str, *, now: int) -> Incident:
    """Bind an adapter result to the exact committed claim before verification."""
    with conn:
        current = get_incident(conn, incident.id)
        claim = conn.execute(
            "SELECT spec_digest,adapter_id,idempotency_key FROM production_execution_claims "
            "WHERE incident_id=? AND fence_token=?",
            (incident.id, incident.fence_token),
        ).fetchone()
        if (
            current.version != incident.version
            or current.state != "adapter_dispatching"
            or current.fence_token != incident.fence_token
            or current.spec_digest != incident.spec_digest
            or not claim
            or tuple(claim) != (incident.spec_digest, incident.adapter_id, f"{incident.id}:{incident.spec_digest}")
        ):
            raise StateConflict("adapter result does not match the active execution claim")
        conn.execute(
            "INSERT INTO production_executions VALUES (?,?,?,?,?,?)",
            (incident.id, execution_id, incident.fence_token, incident.spec_digest, incident.adapter_id, now),
        )
        verified = _cas(conn, incident.id, incident.version, state="verifying", now=now)
        _event(conn, incident.id, "adapter_dispatched", now, execution_id=execution_id, fence=incident.fence_token)
        target = conn.execute(
            "SELECT operator_target FROM production_incidents WHERE id=?", (incident.id,),
        ).fetchone()[0]
        _outbox(
            conn, incident.id, target, f"receipt_required:{execution_id}", now,
            body=f"P0 {incident.id}: receipt required for execution {execution_id}",
        )
    return verified


def _execution_claim_is_live(conn: sqlite3.Connection, incident: Incident) -> bool:
    """Last fail-closed check before adapter I/O after a separately committed claim."""
    current = get_incident(conn, incident.id)
    claim = conn.execute(
        "SELECT 1 FROM production_execution_claims "
        "WHERE incident_id=? AND fence_token=? AND spec_digest=? AND adapter_id=? "
        "AND idempotency_key=?",
        (incident.id, incident.fence_token, incident.spec_digest, incident.adapter_id,
         f"{incident.id}:{incident.spec_digest}"),
    ).fetchone()
    return bool(
        claim
        and current.version == incident.version
        and current.state == "adapter_dispatching"
        and current.fence_token == incident.fence_token
        and current.spec_digest == incident.spec_digest
    )


def controller_tick(conn: sqlite3.Connection, *, now: int, registry: Optional[AdapterRegistry] = None, estop_engaged: bool = False) -> TickResult:
    reclaimed: list[str] = []; blocked: list[str] = []; dispatched: list[str] = []
    # e-stop is fail-closed for every non-terminal P0 incident: create an
    # operator-visible human block rather than silently leaving an obligation runnable.
    if estop_engaged:
        rows = conn.execute("SELECT id,version,operator_target FROM production_incidents WHERE state NOT IN (?,?)", (COMPLETED, HUMAN_BLOCKED)).fetchall()
        for incident_id, version, target in rows:
            with conn:
                incident = get_incident(conn, incident_id)
                if incident.version != version:
                    continue
                _block_incident(conn, incident, now=now, reason="global emergency stop engaged")
                blocked.append(incident_id)
        return TickResult(reclaimed, blocked, dispatched)
    rows = conn.execute("SELECT id,version,state,retry_safe,operator_target FROM production_incidents WHERE state NOT IN (?,?) AND evidence_deadline <= ?", (COMPLETED, HUMAN_BLOCKED, now)).fetchall()
    for incident_id, version, state, retry_safe, target in rows:
        with conn:
            incident = get_incident(conn, incident_id)
            if incident.version != version or incident.state != state:
                continue
            if state == "adapter_dispatching" or not retry_safe:
                _block_incident(conn, incident, now=now, reason="evidence deadline elapsed")
                blocked.append(incident_id)
            elif retry_safe:
                _quarantine_normal_task(conn, incident.task_id, now=now)
                updated = _cas(conn, incident_id, version, state="reclaiming", now=now, fence_token=incident.fence_token + 1)
                _event(conn, incident_id, "reclaimed", now, fence=updated.fence_token); reclaimed.append(incident_id)
    if registry:
        rows = conn.execute("SELECT id,version FROM production_incidents WHERE state='approved_executing'").fetchall()
        for incident_id, version in rows:
            try:
                incident = _claim_adapter_execution(conn, incident_id, expected_version=version, now=now)
            except StateConflict:
                continue
            adapter = registry.get(incident.adapter_id)
            if adapter is None:
                with conn:
                    _block_incident(conn, get_incident(conn, incident_id), now=now, reason="configured adapter unavailable")
                blocked.append(incident_id)
                continue
            try:
                if not _execution_claim_is_live(conn, incident):
                    continue
                execution_id = adapter.execute(_gate_spec(conn, incident), f"{incident.id}:{incident.spec_digest}", incident.fence_token)
                if not execution_id:
                    raise ValueError("adapter returned no execution identity")
                _record_adapter_execution(conn, incident, str(execution_id), now=now)
                dispatched.append(incident_id)
            except Exception as exc:
                with conn:
                    current = get_incident(conn, incident_id)
                    if current.state != HUMAN_BLOCKED:
                        _block_incident(conn, current, now=now, reason="adapter dispatch failed", error=str(exc))
                blocked.append(incident_id)
    return TickResult(reclaimed, blocked, dispatched)


def claim_notification(conn: sqlite3.Connection, *, now: int, lease_seconds: int = 60) -> Optional[Notification]:
    # Expired leases are reclaimable; no subscriber cursor is involved.
    conn.execute("UPDATE production_notifications SET status='pending', lease_until=NULL WHERE status='leased' AND lease_until<=?", (now,))
    row = conn.execute("SELECT id,incident_id,target,body FROM production_notifications WHERE status='pending' AND next_attempt_at <= ? ORDER BY id LIMIT 1", (now,)).fetchone()
    if not row: return None
    with conn:
        cur = conn.execute("UPDATE production_notifications SET status='leased',lease_until=?,attempts=attempts+1 WHERE id=? AND status='pending'", (now + lease_seconds, row[0]))
        if cur.rowcount != 1: return None
    return Notification(*row)


def acknowledge_notification(conn: sqlite3.Connection, notification_id: int, *, now: int) -> bool:
    with conn:
        return conn.execute("UPDATE production_notifications SET status='acknowledged', acknowledged_at=?, lease_until=NULL WHERE id=? AND status='leased'", (now, notification_id)).rowcount == 1


def fail_notification(conn: sqlite3.Connection, notification_id: int, *, now: int, error: str, max_attempts: int = 5) -> bool:
    with conn:
        row = conn.execute("SELECT attempts FROM production_notifications WHERE id=? AND status='leased'", (notification_id,)).fetchone()
        if not row:
            return False
        attempts = int(row[0])
        error = str(error)[:1000]
        if attempts >= max_attempts:
            return conn.execute("UPDATE production_notifications SET status='dead_letter', dead_letter_at=?, lease_until=NULL, last_error=?, last_error_at=? WHERE id=? AND status='leased'", (now, error, now, notification_id)).rowcount == 1
        backoff = min(300, 2 ** attempts)
        return conn.execute("UPDATE production_notifications SET status='pending', lease_until=NULL, next_attempt_at=?, last_error=?, last_error_at=? WHERE id=? AND status='leased'", (now + backoff, error, now, notification_id)).rowcount == 1


def register_legacy_incidents(conn: sqlite3.Connection, *, now: int, operator_target: str = "telegram:operator", owner: str = "operator", adapter_id: str = "manual", retry_safe: bool = False) -> list[str]:
    ids = []
    for issue in (335, 328, 336):
        existing = conn.execute("SELECT id FROM production_incidents WHERE task_id=?", (f"legacy-{issue}",)).fetchone()
        if existing: ids.append(existing[0]); continue
        _, incident = admit_p0_task(conn, title=f"fitness-system#{issue}", assignee="executor", owner=owner, operator_target=operator_target, gate_spec=GateSpec("execute approved production gate", "production impact", "follow documented rollback", "capture verifier receipt", f"fitness-system#{issue}", "production"), now=now, adapter_id=adapter_id, retry_safe=retry_safe, task_id=f"legacy-{issue}")
        ids.append(incident)
    return ids


def bootstrap_configured_legacy_incidents(conn: sqlite3.Connection, *, config: object, now: int) -> list[str]:
    """Register the three retrospective gates on every configured board once.

    No task data selects the owner or delivery route.  Missing trust roots are
    a hard error so startup cannot silently create unroutable P0 obligations.
    """
    if not isinstance(config, dict) or not config.get("legacy_registrations", False):
        return []
    targets = config.get("operator_targets")
    principals = config.get("approval_principals")
    adapters = config.get("adapters")
    adapter_id = str(config.get("legacy_adapter_id", "")).strip()
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(principals, list) or not principals or not isinstance(adapters, list) or not adapter_id:
        raise ValueError("production incident configured legacy bootstrap requires exactly one operator target and approval trust roots")
    target = str(targets[0]).strip()
    routes = configured_operator_routes(config)
    if target not in routes:
        raise ValueError("operator target must be a named operator trust root")
    adapter_config = next(
        (item for item in adapters if isinstance(item, dict) and str(item.get("id", "")).strip() == adapter_id),
        None,
    )
    if adapter_config is None:
        raise ValueError("production incident configured legacy bootstrap requires a configured legacy adapter")
    if str(adapter_config.get("execution", "verifier")).strip().lower() != "manual":
        raise ValueError("production incident configured legacy bootstrap requires a manual executor")
    owner = str(config.get("legacy_owner", "operator")).strip()
    if not owner:
        raise ValueError("production incident legacy owner is required")
    return register_legacy_incidents(
        conn, now=now, operator_target=target, owner=owner, adapter_id=adapter_id,
        retry_safe=bool(adapter_config.get("retry_safe", False)),
    )
