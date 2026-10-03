"""Core data models shared by every component."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Optional


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


class Mode(str, Enum):
    """The three configurations compared in the evaluation."""
    UNRESTRICTED = "unrestricted"   # agents may call any tool, nothing is checked
    RBAC = "rbac"                   # permissions + injection scan + critique + validation
    HITL = "hitl"                   # RBAC plus human approval for high-risk actions


class Risk(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class StepStatus(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTED = "executed"
    DENIED = "denied"        # RBAC said no
    VETOED = "vetoed"        # injection scan or critique vetoed the plan
    REJECTED = "rejected"    # a human said no
    SKIPPED = "skipped"      # never reached


class RunStatus(str, Enum):
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    REJECTED = "rejected"


@dataclass
class Step:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    # Ground-truth labels. Only the evaluation harness reads these; no agent does.
    origin: str = "user"              # "user" | "injected"
    harmful: bool = False
    reviewer: Optional[str] = None    # scripted human decision: "approve" | "deny"
    # Filled in by the pipeline.
    risk: Risk = Risk.LOW
    flags: list[str] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    result: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "args": self.args, "origin": self.origin,
            "risk": self.risk.name.lower(), "flags": self.flags,
            "status": self.status.value, "result": self.result,
        }


@dataclass
class Task:
    prompt: str
    role: Role
    context: str = ""                 # untrusted content the research agent retrieves
    steps: Optional[list[Step]] = None  # scripted plan (stands in for LLM output)
    id: str = "custom"
    title: str = "Custom task"
    kind: str = "benign"              # "benign" | "attack"
    hint: str = ""                    # extra context shown to a human reviewer


@dataclass
class Run:
    task: Task
    mode: Mode
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    steps: list[Step] = field(default_factory=list)
    status: RunStatus = RunStatus.RUNNING
    cursor: int = 0
    detections: list[str] = field(default_factory=list)
    approvals_requested: int = 0

    @property
    def pending_step(self) -> Optional[Step]:
        if self.status == RunStatus.AWAITING_APPROVAL:
            return self.steps[self.cursor]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "mode": self.mode.value, "status": self.status.value,
            "role": self.task.role.value, "prompt": self.task.prompt,
            "steps": [s.to_dict() for s in self.steps],
            "detections": self.detections,
            "approvals_requested": self.approvals_requested,
            "pending_step": self.cursor if self.pending_step else None,
        }
