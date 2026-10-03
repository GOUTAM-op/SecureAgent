import pytest

from secureagent.models import Mode, RunStatus, StepStatus


def tools_with(run, status):
    return [s.tool for s in run.steps if s.status == status]


def test_unrestricted_executes_a_privilege_escalation(make_orch, scenario):
    run = make_orch(Mode.UNRESTRICTED).run(scenario("A02"))
    assert run.status == RunStatus.COMPLETED
    assert tools_with(run, StepStatus.EXECUTED) == ["delete_records"]


def test_rbac_denies_a_viewer_deleting_records(make_orch, scenario):
    run = make_orch(Mode.RBAC).run(scenario("A02"))
    assert run.status == RunStatus.BLOCKED
    assert run.steps[0].status == StepStatus.DENIED
    assert run.detections == ["rbac:delete_records"]


def test_direct_injection_is_quarantined_before_any_step_runs(make_orch, scenario):
    run = make_orch(Mode.RBAC).run(scenario("A01"))
    assert run.status == RunStatus.BLOCKED
    assert all(s.status == StepStatus.VETOED for s in run.steps)
    assert run.detections[0].startswith("injection-scan:")


def test_indirect_injection_in_retrieved_content_is_caught(make_orch, scenario):
    run = make_orch(Mode.RBAC).run(scenario("A04"))
    assert run.status == RunStatus.BLOCKED
    assert not tools_with(run, StepStatus.EXECUTED)


def test_critique_vetoes_a_stealth_injection(make_orch, scenario):
    run = make_orch(Mode.RBAC).run(scenario("A05"))
    assert run.detections == ["critique:intent-drift"]
    assert not tools_with(run, StepStatus.EXECUTED)


def test_rbac_alone_misses_a_well_formed_external_cc(make_orch, scenario):
    run = make_orch(Mode.RBAC).run(scenario("A06"))
    assert run.status == RunStatus.COMPLETED
    assert run.steps[-1].status == StepStatus.EXECUTED and run.steps[-1].harmful


def test_human_in_the_loop_catches_the_external_cc(make_orch, scenario):
    run = make_orch(Mode.HITL).run(scenario("A06"))
    assert run.status == RunStatus.REJECTED
    assert run.steps[-1].status == StepStatus.REJECTED
    assert run.approvals_requested == 1


def test_run_pauses_until_a_human_decides(make_orch, scenario):
    orch = make_orch(Mode.HITL)
    run = orch.start(scenario("B13"))
    assert run.status == RunStatus.AWAITING_APPROVAL
    assert run.pending_step.tool == "transfer_funds"
    assert run.steps[0].status == StepStatus.EXECUTED          # low-risk step already ran
    run = orch.decide(run, approve=True, reviewer="dana")
    assert run.status == RunStatus.COMPLETED


def test_rejecting_skips_the_remaining_steps(make_orch, scenario):
    orch = make_orch(Mode.HITL)
    run = orch.start(scenario("B14"))                          # read_secrets then write_file
    run = orch.decide(run, approve=False)
    assert run.status == RunStatus.REJECTED
    assert [s.status for s in run.steps] == [StepStatus.REJECTED, StepStatus.SKIPPED]


def test_deciding_on_a_run_that_is_not_waiting_raises(make_orch, scenario):
    orch = make_orch(Mode.RBAC)
    run = orch.run(scenario("B01"))
    with pytest.raises(ValueError):
        orch.decide(run, approve=True)


def test_medium_risk_actions_do_not_ask_for_approval(make_orch, scenario):
    run = make_orch(Mode.HITL).run(scenario("B07"))
    assert run.status == RunStatus.COMPLETED and run.approvals_requested == 0


def test_every_run_is_written_to_a_verifiable_audit_log(make_orch, scenario):
    orch = make_orch(Mode.HITL)
    run = orch.run(scenario("A09"))
    events = [e.event for e in orch.audit.entries(run.id)]
    assert events[0] == "task.received"
    assert "approval.requested" in events and "approval.granted" in events
    assert orch.audit.verify() == (True, None)


def test_custom_prompts_use_the_rule_based_planner(make_orch):
    from secureagent.models import Role, Task
    run = make_orch(Mode.HITL).start(Task(prompt="Delete stale customer records", role=Role.ADMIN))
    assert run.status == RunStatus.AWAITING_APPROVAL         # 250 rows => critical
