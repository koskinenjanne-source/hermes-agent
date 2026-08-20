from __future__ import annotations

import sqlite3

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import production_incidents as pi


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


def test_p0_admission_is_bound_and_completion_requires_verified_evidence(board):
    task_id, incident_id = pi.admit_p0_task(
        board, title="P0 gate", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=100,
    )
    assert board.execute("SELECT production_incident_required FROM tasks WHERE id=?", (task_id,)).fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError, match="verified production completion"):
        kb.complete_task(board, task_id, summary="worker prose is not evidence")
    pi.accept_verified_receipt(
        board, incident_id=incident_id, adapter_id="manual", execution_id="run-1",
        fence_token=1, spec_digest=pi.spec_digest(spec()), attestation="verified:run-1", now=101,
    )
    assert kb.complete_task(board, task_id, summary="now gated by verifier")


def test_approval_and_receipt_are_cas_bound_and_spec_updates_invalidate(board):
    _, incident_id = pi.admit_p0_task(
        board, title="P0", assignee="executor", owner="operator",
        operator_target="telegram:operator", gate_spec=spec(), now=100,
    )
    incident = pi.get_incident(board, incident_id)
    pi.require_approval(board, incident_id, expected_version=incident.version, now=100)
    incident = pi.get_incident(board, incident_id)
    pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=200, now=101)
    with pytest.raises(pi.StateConflict):
        pi.grant_approval(board, incident_id, principal="ops", expected_version=incident.version, expires_at=200, now=102)
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
