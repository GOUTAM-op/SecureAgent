"""FastAPI service exposing the orchestrator, policy, audit log and evaluation harness."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .agents import PlannerAgent
from .audit import AuditLog
from .evaluation import compare, evaluate
from .models import Mode, Role, Run, Task
from .orchestrator import Orchestrator
from .rbac import RBACPolicy, TOOLS
from .scenarios import build_scenarios, get_scenario

UI_FILE = Path(__file__).resolve().parent.parent / "ui" / "index.html"


class RunRequest(BaseModel):
    prompt: Optional[str] = None
    role: Role = Role.VIEWER
    mode: Mode = Mode.HITL
    context: str = ""
    scenario_id: Optional[str] = None


class DecisionRequest(BaseModel):
    approve: bool
    reviewer: str = "human"


class GrantRequest(BaseModel):
    role: Role
    permission: str
    granted: bool


class EvaluateRequest(BaseModel):
    mode: Optional[Mode] = None


def create_app(planner: Optional[PlannerAgent] = None) -> FastAPI:
    app = FastAPI(title="SecureAgent", version="1.0.0",
                  description="Permission-aware multi-agent orchestration")
    audit = AuditLog()
    rbac = RBACPolicy()
    runs: dict[str, Run] = {}
    orchestrators: dict[Mode, Orchestrator] = {
        m: Orchestrator(mode=m, rbac=rbac, audit=audit, planner=planner) for m in Mode
    }

    def get_run(run_id: str) -> Run:
        if run_id not in runs:
            raise HTTPException(404, f"unknown run '{run_id}'")
        return runs[run_id]

    @app.get("/", include_in_schema=False)
    def index():
        if UI_FILE.exists():
            return FileResponse(UI_FILE)
        return {"service": "secureagent", "docs": "/docs"}

    @app.get("/health")
    def health():
        return {"status": "ok", "audit_entries": len(audit)}

    # ------------------------------------------------------------------ policy
    @app.get("/policy")
    def policy():
        return {
            "tools": {n: {"permission": t.permission, "base_risk": t.base_risk.name.lower(),
                          "description": t.description} for n, t in TOOLS.items()},
            "matrix": rbac.matrix(),
        }

    @app.put("/policy/grants")
    def set_grant(req: GrantRequest):
        if req.permission not in {t.permission for t in TOOLS.values()}:
            raise HTTPException(422, f"unknown permission '{req.permission}'")
        (rbac.grant if req.granted else rbac.revoke)(req.role, req.permission)
        return {"matrix": rbac.matrix()}

    # --------------------------------------------------------------- scenarios
    @app.get("/scenarios")
    def scenarios():
        return [{"id": t.id, "title": t.title, "kind": t.kind, "role": t.role.value,
                 "prompt": t.prompt} for t in build_scenarios()]

    # -------------------------------------------------------------------- runs
    @app.post("/runs")
    def create_run(req: RunRequest):
        if req.scenario_id:
            try:
                task = get_scenario(req.scenario_id)
            except KeyError:
                raise HTTPException(404, f"unknown scenario '{req.scenario_id}'")
            task.role = req.role if "role" in req.model_fields_set else task.role
        elif req.prompt:
            task = Task(prompt=req.prompt, role=req.role, context=req.context)
        else:
            raise HTTPException(422, "provide either 'prompt' or 'scenario_id'")
        run = orchestrators[req.mode].start(task)
        runs[run.id] = run
        return run.to_dict()

    @app.get("/runs/{run_id}")
    def read_run(run_id: str):
        return get_run(run_id).to_dict()

    @app.post("/runs/{run_id}/decision")
    def decide(run_id: str, req: DecisionRequest):
        run = get_run(run_id)
        if run.pending_step is None:
            raise HTTPException(409, "run is not awaiting approval")
        return orchestrators[run.mode].decide(run, req.approve, req.reviewer).to_dict()

    # ------------------------------------------------------------------- audit
    @app.get("/audit")
    def read_audit(run_id: Optional[str] = Query(None)):
        return [e.to_dict() for e in audit.entries(run_id)]

    @app.get("/audit/verify")
    def verify_audit():
        ok, bad = audit.verify()
        return {"ok": ok, "first_bad_seq": bad, "entries": len(audit)}

    # -------------------------------------------------------------- evaluation
    @app.post("/evaluate")
    def run_evaluation(req: EvaluateRequest = EvaluateRequest()):
        if req.mode:
            return {req.mode.value: evaluate(req.mode, rbac=rbac)}
        return compare(rbac=rbac)

    return app


app = create_app()
