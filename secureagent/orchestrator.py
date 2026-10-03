"""Central orchestrator. Agents never call each other; everything flows through here."""
from __future__ import annotations

from typing import Callable, Optional

from .agents import (CritiqueAgent, ExecutorAgent, PlannerAgent, ResearchAgent,
                     SecurityAgent)
from .approvals import default_reviewer
from .audit import AuditLog
from .models import Mode, Risk, Run, RunStatus, Step, StepStatus, Task
from .rbac import RBACPolicy
from .validation import APPROVAL_THRESHOLD, assess


def _fmt_args(args: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in args.items())


class Orchestrator:
    """Runs one task through planner -> research -> security -> critique -> executor.

    Modes:
      UNRESTRICTED  no checks at all (baseline)
      RBAC          injection scan, permission check, critique veto, action validation
      HITL          RBAC + human approval for HIGH / CRITICAL actions
    """

    def __init__(self, mode: Mode = Mode.HITL, rbac: Optional[RBACPolicy] = None,
                 audit: Optional[AuditLog] = None, planner: Optional[PlannerAgent] = None):
        self.mode = Mode(mode)
        self.rbac = rbac or RBACPolicy()
        self.audit = audit if audit is not None else AuditLog()
        self.planner = planner or PlannerAgent()
        self.research = ResearchAgent()
        self.security = SecurityAgent(self.rbac)
        self.critique = CritiqueAgent()
        self.executor = ExecutorAgent()

    # ------------------------------------------------------------------ public API

    def start(self, task: Task) -> Run:
        run = Run(task=task, mode=self.mode)
        self._log(run, f"user:{task.role.value}", "task.received", task.prompt)

        run.steps = self.planner.plan(task)
        for s in run.steps:
            s.risk, s.flags = assess(s)
        self._log(run, "planner", "plan.created",
                  " -> ".join(s.tool for s in run.steps) or "(empty)")

        context = self.research.gather(task)
        self._log(run, "research", "context.retrieved", f"{len(context)} chars of untrusted content")

        if self.mode == Mode.UNRESTRICTED:
            self._log(run, "security", "guard.bypassed",
                      "no permission checks or scans in this configuration", "warn")
        elif not self._guard(run, context):
            return run
        return self._advance(run)

    def decide(self, run: Run, approve: bool, reviewer: str = "human") -> Run:
        """Resolve a pending approval. Approving executes the step and continues the run."""
        step = run.pending_step
        if step is None:
            raise ValueError("run is not awaiting approval")
        actor = f"reviewer:{reviewer}"
        if approve:
            self._log(run, actor, "approval.granted", step.tool, "allow")
            self._execute(run, step)
            run.status = RunStatus.RUNNING
            return self._advance(run)
        self._log(run, actor, "approval.denied", step.tool, "block")
        step.status = StepStatus.REJECTED
        for s in run.steps[run.cursor + 1:]:
            s.status = StepStatus.SKIPPED
        run.detections.append(f"human-rejected:{step.tool}")
        run.status = RunStatus.REJECTED
        return run

    def run(self, task: Task, reviewer: Callable[[Step], bool] = default_reviewer) -> Run:
        """Run to completion, answering approval requests with `reviewer`."""
        run = self.start(task)
        while run.status == RunStatus.AWAITING_APPROVAL:
            run = self.decide(run, reviewer(run.pending_step), reviewer="scripted")
        return run

    # ----------------------------------------------------------------- internals

    def _log(self, run: Run, actor: str, event: str, detail: str, decision: str = "info"):
        return self.audit.append(run.id, actor, event, detail, decision)

    def _guard(self, run: Run, context: str) -> bool:
        """Security scan -> permission check -> critique. Returns False if the run is stopped."""
        hits = self.security.scan(f"{run.task.prompt}\n{context}")
        if hits:
            return self._stop(run, StepStatus.VETOED, "security", "injection.quarantined",
                              "injection-scan:" + ",".join(hits),
                              "matched signatures: " + ", ".join(hits))

        denied = self.security.denied_steps(run.task.role, run.steps)
        if denied:
            for i, s in enumerate(run.steps):
                s.status = StepStatus.DENIED if i in denied else StepStatus.SKIPPED
            tools = ",".join(run.steps[i].tool for i in denied)
            self._log(run, "security", "rbac.denied",
                      f"role '{run.task.role.value}' lacks permission for {tools}", "block")
            run.detections.append("rbac:" + tools)
            run.status = RunStatus.BLOCKED
            return False
        self._log(run, "security", "rbac.passed",
                  f"role '{run.task.role.value}' holds every required permission", "allow")

        findings = self.critique.review(run.task.prompt, run.steps)
        if findings:
            for f in findings:
                self._log(run, "critique", f"finding.{f.kind}", f"step {f.step_index + 1}: {f.message}", "warn")
            kinds = ",".join(sorted({f.kind for f in findings}))
            return self._stop(run, StepStatus.VETOED, "critique", "plan.vetoed",
                              "critique:" + kinds, "plan does not match the user's request")
        self._log(run, "critique", "plan.approved", "every step traces back to the request", "allow")
        return True

    def _stop(self, run: Run, status: StepStatus, actor: str, event: str,
              detection: str, detail: str) -> bool:
        for s in run.steps:
            s.status = status
        run.detections.append(detection)
        run.status = RunStatus.BLOCKED
        self._log(run, actor, event, detail, "block")
        return False

    def _execute(self, run: Run, step: Step) -> None:
        step.result = self.executor.execute(step)
        step.status = StepStatus.EXECUTED
        self._log(run, "executor", f"tool.{step.tool}", f"{_fmt_args(step.args)} -> {step.result}", "allow")
        run.cursor += 1

    def _advance(self, run: Run) -> Run:
        while run.cursor < len(run.steps):
            step = run.steps[run.cursor]
            if self.mode == Mode.HITL and step.risk >= APPROVAL_THRESHOLD:
                step.status = StepStatus.AWAITING_APPROVAL
                run.status = RunStatus.AWAITING_APPROVAL
                run.approvals_requested += 1
                self._log(run, "security", "approval.requested",
                          f"{step.tool} ({step.risk.name.lower()}): {'; '.join(step.flags) or 'high-risk tool'}",
                          "warn")
                return run
            self._execute(run, step)
        run.status = RunStatus.COMPLETED
        self._log(run, "orchestrator", "run.completed", f"{len(run.steps)} steps executed", "allow")
        return run
