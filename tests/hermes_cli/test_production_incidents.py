from __future__ import annotations

import hashlib
import hmac
import sqlite3
import asyncio
import threading
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import production_incidents as pi


class OperatorAdapter:
    async def send(self, chat_id, text, metadata=None):
        self.sent = (chat_id, text, metadata)


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    path = tmp_path / "kanban.db"
    kb.init_db(path)
    with kb.connect(path) as conn:
        yield conn


def spec():
    return pi.GateSpec(
        action="reload approved shared gateway",
        risk="brief routing interruption",
        rollback="restore prior registration and reload",
        verification_procedure="verify dedicated receipt",
        target="shared-gateway",
        environment="production",
    )


class SignedAdapter:
    adapter_id = "signed"
    retry_safe = False

    def __init__(self, key=b"test-key"):
        self.key = key
        self.executions = []

    def execute(self, spec, idempotency_key, fence_token):
        self.executions.append((spec, idempotency_key, fence_token))
        return "execution-1"

    def verify(self, receipt):
        expected = hmac.new(self.key, pi.receipt_payload(receipt).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(receipt.attestation, expected)


class BlockingAdapter(SignedAdapter):
    """Makes overlapping controller dispatch attempts observable without I/O."""

    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self._lock = threading.Lock()

    def execute(self, spec, idempotency_key, fence_token):
        with self._lock:
            self.executions.append((spec, idempotency_key, fence_token))
            self.entered.set()
        assert self.entered.wait(timeout=0.5)
        return "execution-1"


def _approved_execution(board, *, adapter_id="signed"):
    _, incident_id = pi.admit_p0_task(board, title="P0", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=spec(), now=0, adapter_id=adapter_id)
    incident = pi.require_approval(board, incident_id, expected_version=1, now=1)
    incident = pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=100, now=1, allowed_principals={"ops"})
    return pi.begin_approved_execution(board, incident_id, expected_version=incident.version, now=1)


def test_receipt_requires_registered_verifier_and_authenticated_provenance(board):
    incident = _approved_execution(board)
    adapter = SignedAdapter()
    registry = pi.AdapterRegistry({adapter.adapter_id: adapter})
    pi.controller_tick(board, now=2, registry=registry)
    incident = pi.get_incident(board, incident.id)
    receipt = pi.Receipt(incident.id, "signed", "execution-1", incident.fence_token, incident.spec_digest, "")
    signed = receipt.__class__(**{**receipt.__dict__, "attestation": hmac.new(adapter.key, pi.receipt_payload(receipt).encode(), hashlib.sha256).hexdigest()})
    accepted = pi.accept_adapter_receipt(board, signed, registry=registry, now=3)
    assert accepted.state == pi.COMPLETED
    with pytest.raises((pi.StateConflict, ValueError)):
        pi.accept_adapter_receipt(board, signed, registry=registry, now=4)


def test_outbox_claim_ack_retry_and_dead_letter_are_durable(board):
    _, incident_id = pi.admit_p0_task(board, title="P0", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=spec(), now=0)
    note = pi.claim_notification(board, now=0, lease_seconds=5)
    assert note and note.incident_id == incident_id
    pi.fail_notification(board, note.id, now=1, error="network", max_attempts=2)
    assert pi.claim_notification(board, now=1) is None
    note = pi.claim_notification(board, now=3)
    assert note
    pi.fail_notification(board, note.id, now=3, error="network", max_attempts=2)
    row = board.execute("SELECT status,last_error,last_error_at FROM production_notifications WHERE id=?", (note.id,)).fetchone()
    assert tuple(row) == ("dead_letter", "network", 3)


def test_controller_dispatches_only_approved_adapter_and_estop_fails_closed(board):
    adapter = SignedAdapter()
    registry = pi.AdapterRegistry({adapter.adapter_id: adapter})
    incident = _approved_execution(board)
    dispatched = pi.controller_tick(board, now=2, registry=registry, estop_engaged=False)
    assert dispatched.dispatched == [incident.id]
    assert adapter.executions and pi.get_incident(board, incident.id).state == "verifying"
    _, blocked_id = pi.admit_p0_task(board, title="P0", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=spec(), now=0)
    result = pi.controller_tick(board, now=2, registry=registry, estop_engaged=True)
    assert blocked_id in result.blocked


def test_concurrent_controller_ticks_execute_non_retry_safe_adapter_once(board):
    incident = _approved_execution(board)
    adapter = BlockingAdapter()
    registry = pi.AdapterRegistry({adapter.adapter_id: adapter})
    db_path = board.execute("PRAGMA database_list").fetchone()[2]
    failures = []

    def tick():
        with kb.connect(Path(db_path)) as conn:
            try:
                pi.controller_tick(conn, now=2, registry=registry)
            except Exception as exc:
                failures.append(exc)

    first = threading.Thread(target=tick)
    second = threading.Thread(target=tick)
    first.start()
    assert adapter.entered.wait(timeout=1)
    second.start()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert len(adapter.executions) == 1
    assert pi.get_incident(board, incident.id).state == "verifying"


@pytest.mark.parametrize("estop_engaged", [True, False])
def test_blocking_paths_quarantine_running_p0_task(board, estop_engaged):
    task_id, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
        retry_safe=False,
    )
    incident = pi.require_approval(board, incident_id, expected_version=1, now=1)
    incident = pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=100, now=1, allowed_principals={"ops"})
    pi.begin_approved_execution(board, incident_id, expected_version=incident.version, now=1)
    assert kb.claim_task(board, task_id, claimer="test-worker")

    pi.controller_tick(
        board,
        now=2 if estop_engaged else pi.EVIDENCE_WINDOW_SECONDS,
        estop_engaged=estop_engaged,
    )

    task = board.execute("SELECT status,current_run_id,claim_lock,worker_pid FROM tasks WHERE id=?", (task_id,)).fetchone()
    assert tuple(task) == ("triage", None, None, None)
    assert pi.get_incident(board, incident_id).state == pi.HUMAN_BLOCKED


def test_gateway_controller_acknowledges_only_configured_operator_outbox(board, monkeypatch):
    from gateway.config import Platform
    from gateway.run import GatewayRunner
    import hermes_cli.config as config

    _, incident_id = pi.admit_p0_task(board, title="P0", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=spec(), now=0)
    operator = OperatorAdapter()
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.adapters = {Platform.TELEGRAM: operator}
    runner._production_adapter_registry = pi.AdapterRegistry()
    db_path = board.execute("PRAGMA database_list").fetchone()[2]
    monkeypatch.setenv("HERMES_KANBAN_DB", db_path)
    monkeypatch.setattr(config, "load_config", lambda: {"production_incidents": {"operator_targets": ["telegram:operator"], "approval_principals": ["ops"]}})
    asyncio.run(runner._production_incident_tick())
    assert operator.sent[0] == "operator"
    assert board.execute("SELECT status FROM production_notifications WHERE incident_id=?", (incident_id,)).fetchone()[0] == "acknowledged"


def test_gateway_bootstraps_configured_legacy_incidents_and_registry(board, monkeypatch):
    from gateway.config import Platform
    from gateway.run import GatewayRunner
    import hermes_cli.config as config

    runner = GatewayRunner.__new__(GatewayRunner)
    runner.adapters = {Platform.TELEGRAM: OperatorAdapter()}
    db_path = board.execute("PRAGMA database_list").fetchone()[2]
    monkeypatch.setenv("HERMES_KANBAN_DB", db_path)
    monkeypatch.setenv("P0_RECEIPT_KEY", "receipt-key")
    monkeypatch.setattr(config, "load_config", lambda: {"production_incidents": {
        "operator_targets": ["telegram:operator"], "approval_principals": ["telegram:42"],
        "legacy_registrations": True,
        "legacy_adapter_id": "ops-hmac",
        "adapters": [{"id": "ops-hmac", "secret_env": "P0_RECEIPT_KEY", "execution": "manual"}],
    }})
    asyncio.run(runner._production_incident_tick())
    assert board.execute("SELECT COUNT(*) FROM production_incidents").fetchone()[0] == 3
    assert runner._production_adapter_registry.get("ops-hmac") is not None


def test_gateway_approval_command_uses_authenticated_configured_principal(board, monkeypatch):
    from gateway.config import Platform
    from gateway.platforms.base import MessageEvent
    from gateway.run import GatewayRunner
    from gateway.session import SessionSource
    import hermes_cli.config as config

    _, incident_id = pi.admit_p0_task(board, title="P0", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=spec(), now=0)
    pi.require_approval(board, incident_id, expected_version=1, now=1)
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._is_user_authorized = lambda source: True
    db_path = board.execute("PRAGMA database_list").fetchone()[2]
    monkeypatch.setenv("HERMES_KANBAN_DB", db_path)
    monkeypatch.setattr(config, "load_config", lambda: {"production_incidents": {
        "operator_targets": ["telegram:operator"], "approval_principals": ["telegram:42"],
    }})
    event = MessageEvent(text=f"/production-approve {incident_id} 2 4000000000", source=SessionSource(platform=Platform.TELEGRAM, chat_id="operator", chat_type="dm", user_id="42"))
    assert asyncio.run(runner._handle_production_approve_command(event)) == "Production approval recorded."
    assert pi.get_incident(board, incident_id).state == "approved_dispatching"


def test_p0_admission_is_bound_and_completion_requires_verified_evidence(board):
    task_id, incident_id = pi.admit_p0_task(board, title="P0 gate", assignee="executor", owner="operator", operator_target="telegram:operator", gate_spec=spec(), now=100, adapter_id="signed")
    assert board.execute("SELECT production_incident_required FROM tasks WHERE id=?", (task_id,)).fetchone()[0] == 1
    assert not kb.complete_task(board, task_id, summary="worker prose is not evidence")
    incident = pi.require_approval(board, incident_id, expected_version=pi.get_incident(board, incident_id).version, now=101)
    incident = pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=200, now=101, allowed_principals={"ops"})
    incident = pi.begin_approved_execution(board, incident_id, expected_version=incident.version, now=101)
    adapter = SignedAdapter()
    registry = pi.AdapterRegistry({"signed": adapter})
    pi.controller_tick(board, now=101, registry=registry)
    incident = pi.get_incident(board, incident_id)
    unsigned = pi.Receipt(incident_id, "signed", "execution-1", incident.fence_token, pi.spec_digest(spec()), "")
    receipt = unsigned.__class__(**{**unsigned.__dict__, "attestation": hmac.new(adapter.key, pi.receipt_payload(unsigned).encode(), hashlib.sha256).hexdigest()})
    pi.accept_adapter_receipt(board, receipt, registry=registry, now=101)
    assert kb.complete_task(board, task_id, summary="now gated by verifier")


def test_approval_and_receipt_are_cas_bound_and_spec_updates_invalidate(board):
    _, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=100,
    )
    incident = pi.get_incident(board, incident_id)
    pi.require_approval(board, incident_id, expected_version=incident.version, now=100)
    incident = pi.get_incident(board, incident_id)
    pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=200, now=101, allowed_principals={"ops"})
    with pytest.raises(pi.StateConflict):
        pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=200, now=102, allowed_principals={"ops"})
    pi.update_gate_spec(board, incident_id, spec().replace(action="different action"), expected_version=pi.get_incident(board, incident_id).version, now=103)
    assert board.execute("SELECT COUNT(*) FROM production_approvals WHERE incident_id=? AND invalidated_at IS NOT NULL", (incident_id,)).fetchone()[0] == 1


def test_watchdog_preserves_deadline_and_only_reclaims_safe_adapters(board):
    _, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
        adapter_id="safe", retry_safe=True,
    )
    result = pi.controller_tick(board, now=1801)
    assert result.reclaimed == [incident_id]
    assert pi.get_incident(board, incident_id).evidence_deadline == 1800
    assert pi.claim_notification(board, now=1801).incident_id == incident_id


def test_coaching_target_and_direct_unbound_ready_transition_are_rejected(board):
    with pytest.raises(ValueError):
        pi.admit_p0_task(board, title="P0", assignee="executor", owner="operator", operator_target="telegram:masa:coaching", gate_spec=spec(), now=0)
    board.execute("INSERT INTO tasks (id,title,status,created_at,production_incident_required) VALUES ('p0','bad','triage',0,1)")
    with pytest.raises(sqlite3.IntegrityError):
        board.execute("UPDATE tasks SET status='ready' WHERE id='p0'")


@pytest.mark.parametrize("status", ["ready", "running", "done"])
def test_direct_insert_of_p0_task_in_dispatchable_state_requires_bound_incident(board, status):
    with pytest.raises(sqlite3.IntegrityError, match="P0 task"):
        board.execute(
            "INSERT INTO tasks (id,title,status,created_at,production_incident_required) VALUES (?,?,?,0,1)",
            (f"unbound-{status}", "unbound P0", status),
        )


def test_legacy_registration_is_idempotent(board):
    first = pi.register_legacy_incidents(board, now=0)
    second = pi.register_legacy_incidents(board, now=1)
    assert first == second
    assert len(first) == 3


def test_configured_legacy_bootstrap_and_hmac_adapter_are_fail_closed(board):
    config = {
        "operator_targets": ["telegram:operator"],
        "approval_principals": ["telegram:42"],
        "legacy_registrations": True,
        "legacy_adapter_id": "ops-hmac",
        "adapters": [{"id": "ops-hmac", "secret_env": "P0_RECEIPT_KEY", "execution": "manual", "retry_safe": False}],
    }
    registry = pi.configured_adapter_registry(config, secret_resolver=lambda key: "receipt-key" if key == "P0_RECEIPT_KEY" else None)
    assert registry.get("ops-hmac") is not None
    assert len(pi.bootstrap_configured_legacy_incidents(board, config=config, now=0)) == 3
    assert len(pi.bootstrap_configured_legacy_incidents(board, config=config, now=1)) == 3
    assert board.execute("SELECT COUNT(*) FROM production_incidents").fetchone()[0] == 3
    with pytest.raises(ValueError, match="secret"):
        pi.configured_adapter_registry(config, secret_resolver=lambda _: None)
    with pytest.raises(ValueError, match="trust roots"):
        pi.bootstrap_configured_legacy_incidents(board, config={"legacy_registrations": True}, now=2)


def test_configured_legacy_manual_executor_completes_only_after_a_verified_receipt(board):
    config = {
        "operator_targets": ["telegram:operator"],
        "approval_principals": ["telegram:42"],
        "legacy_registrations": True,
        "legacy_adapter_id": "manual-receipt",
        "adapters": [{
            "id": "manual-receipt",
            "secret_env": "P0_RECEIPT_KEY",
            "execution": "manual",
            "retry_safe": False,
        }],
    }
    registry = pi.configured_adapter_registry(
        config, secret_resolver=lambda key: "receipt-key" if key == "P0_RECEIPT_KEY" else None,
    )
    incident_id = pi.bootstrap_configured_legacy_incidents(board, config=config, now=0)[0]
    incident = pi.require_approval(board, incident_id, expected_version=1, now=1)
    incident = pi.grant_approval(
        board, incident_id, principal="telegram:42", expected_version=incident.version,
        expires_at=100, now=1, allowed_principals={"telegram:42"},
    )
    pi.begin_approved_execution(board, incident_id, expected_version=incident.version, now=1)

    dispatched = pi.controller_tick(board, now=2, registry=registry)
    assert dispatched.dispatched == [incident_id]
    verifying = pi.get_incident(board, incident_id)
    assert verifying.state == "verifying"
    execution_id = board.execute(
        "SELECT execution_id FROM production_executions WHERE incident_id=?", (incident_id,)
    ).fetchone()[0]
    assert board.execute(
        "SELECT body FROM production_notifications WHERE incident_id=? AND dedupe_key LIKE ?",
        (incident_id, f"%receipt_required:{execution_id}"),
    ).fetchone()[0] == f"P0 {incident_id}: receipt required for execution {execution_id}"
    unsigned = pi.Receipt(
        incident_id, "manual-receipt", execution_id, verifying.fence_token,
        verifying.spec_digest, "",
    )
    receipt = unsigned.__class__(**{
        **unsigned.__dict__,
        "attestation": hmac.new(
            b"receipt-key", pi.receipt_payload(unsigned).encode(), hashlib.sha256,
        ).hexdigest(),
    })
    assert pi.accept_adapter_receipt(board, receipt, registry=registry, now=3).state == pi.COMPLETED


@pytest.mark.parametrize(
    "adapter, match",
    [
        ({"id": "manual", "secret_env": "P0_RECEIPT_KEY"}, "manual executor"),
        ({"id": "other", "secret_env": "P0_RECEIPT_KEY", "execution": "manual"}, "legacy adapter"),
    ],
)
def test_legacy_bootstrap_rejects_unconfigured_or_verifier_only_manual_execution(board, adapter, match):
    config = {
        "operator_targets": ["telegram:operator"],
        "approval_principals": ["telegram:42"],
        "legacy_registrations": True,
        "legacy_adapter_id": "manual",
        "adapters": [adapter],
    }
    with pytest.raises(ValueError, match=match):
        pi.bootstrap_configured_legacy_incidents(board, config=config, now=0)


def test_configured_verifier_only_adapter_dispatch_fails_closed(board):
    config = {"adapters": [{"id": "verify-only", "secret_env": "P0_RECEIPT_KEY"}]}
    registry = pi.configured_adapter_registry(config, secret_resolver=lambda _: "receipt-key")
    incident = _approved_execution(board, adapter_id="verify-only")

    result = pi.controller_tick(board, now=2, registry=registry)

    assert result.blocked == [incident.id]
    assert pi.get_incident(board, incident.id).state == pi.HUMAN_BLOCKED


@pytest.mark.parametrize(
    "target",
    [
        "telegram:masa",
        "telegram:coaching",
        "telegram:-1003727537327",
        "telegram:-1003727537327:435",
    ],
)
def test_masa_and_numeric_telegram_targets_are_rejected_even_when_listed_as_trust_roots(board, target):
    with pytest.raises(ValueError, match="operator target"):
        pi.admit_p0_task(
            board, title="P0", assignee="executor", owner="operator", operator_target=target,
            gate_spec=spec(), now=0,
        )
    config = {
        "operator_targets": [target],
        "approval_principals": ["telegram:42"],
        "legacy_registrations": True,
        "legacy_adapter_id": "manual",
        "adapters": [{"id": "manual", "secret_env": "P0_RECEIPT_KEY", "execution": "manual"}],
    }
    with pytest.raises(ValueError, match="operator target"):
        pi.bootstrap_configured_legacy_incidents(board, config=config, now=0)


@pytest.mark.parametrize("target", ["telegram:masa", "telegram:-1003727537327:435"])
def test_gateway_delivery_dead_letters_unsafe_telegram_target_even_when_configured(board, monkeypatch, target):
    from gateway.config import Platform
    from gateway.run import GatewayRunner
    import hermes_cli.config as config

    _, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
    )
    board.execute("UPDATE production_notifications SET target=? WHERE incident_id=?", (target, incident_id))
    operator = OperatorAdapter()
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.adapters = {Platform.TELEGRAM: operator}
    db_path = board.execute("PRAGMA database_list").fetchone()[2]
    monkeypatch.setenv("HERMES_KANBAN_DB", db_path)
    monkeypatch.setattr(config, "load_config", lambda: {"production_incidents": {
        "operator_targets": [target], "approval_principals": ["ops"],
    }})

    asyncio.run(runner._production_incident_tick())

    assert not hasattr(operator, "sent")
    assert board.execute(
        "SELECT status,last_error FROM production_notifications WHERE incident_id=?", (incident_id,)
    ).fetchone()[0:2] == ("dead_letter", "unconfigured operator target")


def test_unapproved_p0_task_never_enters_normal_dispatch(board):
    task_id, _ = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
    )
    assert board.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()[0] == "triage"
    with pytest.raises(sqlite3.IntegrityError, match="approved production execution"):
        board.execute("UPDATE tasks SET status='ready' WHERE id=?", (task_id,))


def test_direct_mutation_cannot_clear_p0_guard_or_complete_human_block(board):
    task_id, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
    )
    with pytest.raises(sqlite3.IntegrityError, match="P0 guard cannot be removed"):
        board.execute("UPDATE tasks SET production_incident_required=0 WHERE id=?", (task_id,))
    pi.controller_tick(board, now=pi.EVIDENCE_WINDOW_SECONDS)
    assert pi.get_incident(board, incident_id).state == pi.HUMAN_BLOCKED
    with pytest.raises(sqlite3.IntegrityError, match="verified production completion"):
        board.execute("UPDATE tasks SET status='done' WHERE id=?", (task_id,))


def test_receipt_requires_live_approved_execution(board):
    _, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
    )
    with pytest.raises(ValueError, match="raw attestations"):
        pi.accept_verified_receipt(board, incident_id=incident_id, adapter_id="manual", execution_id="forged", fence_token=1, spec_digest=pi.spec_digest(spec()), attestation="verified:forged", now=1)


def test_retry_safe_timeout_reclaims_normal_task_run_before_fencing(board):
    task_id, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=0,
        retry_safe=True,
    )
    incident = pi.require_approval(board, incident_id, expected_version=1, now=1)
    incident = pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=100, now=1, allowed_principals={"ops"})
    pi.begin_approved_execution(board, incident_id, expected_version=incident.version, now=1)
    assert kb.claim_task(board, task_id, claimer="test-worker")
    old_run_id = board.execute("SELECT current_run_id FROM tasks WHERE id=?", (task_id,)).fetchone()[0]

    assert pi.controller_tick(board, now=pi.EVIDENCE_WINDOW_SECONDS + 1).reclaimed == [incident_id]

    task = board.execute("SELECT status,current_run_id,claim_lock FROM tasks WHERE id=?", (task_id,)).fetchone()
    run = board.execute("SELECT status,outcome,ended_at FROM task_runs WHERE id=?", (old_run_id,)).fetchone()
    assert tuple(task) == ("triage", None, None)
    assert run[0:2] == ("reclaimed", "reclaimed") and run[2] is not None
    assert pi.get_incident(board, incident_id).fence_token == 2
