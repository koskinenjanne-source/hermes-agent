from __future__ import annotations

import hashlib
import hmac
import sqlite3
import asyncio

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
    assert board.execute("SELECT status FROM production_notifications WHERE id=?", (note.id,)).fetchone()[0] == "dead_letter"


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


def test_legacy_registration_is_idempotent(board):
    first = pi.register_legacy_incidents(board, now=0)
    second = pi.register_legacy_incidents(board, now=1)
    assert first == second
    assert len(first) == 3


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
