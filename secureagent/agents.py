"""The five specialised agents. The orchestrator is the only thing that talks to all of them."""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

from .models import Role, Step, Task
from .rbac import RBACPolicy, TOOLS
from .validation import is_external_email

# --------------------------------------------------------------------------- planner

# (pattern, tools) - the first tool listed for each rule is what the rule-based planner emits.
PLAN_RULES: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(p, re.I), t) for p, t in [
        (r"summar|review|read|report|brief|explain", ["read_docs"]),
        (r"research|search|find|look ?up|competitor", ["web_search"]),
        (r"pull|query|count|churn|list", ["query_db"]),
        (r"rotate|credential|api key|secret|password", ["read_secrets"]),
        (r"write|save|draft|notes|export|runbook|update", ["write_file"]),
        (r"delete|archive|purge|clean ?up|remove", ["delete_records"]),
        (r"e-?mail|send|notify|apolog|forward|share", ["send_email"]),
        (r"\bpay\b|transfer|wire|settle|remit", ["transfer_funds"]),
    ]
]

EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
AMOUNT_RX = re.compile(r"\$\s?([\d,]+(?:\.\d+)?)")
PATH_RX = re.compile(r"(?:^|\s)(/[\w./-]+)")
ROWS_RX = re.compile(r"(\d[\d,]*)\s*(?:rows|records|accounts)", re.I)


def build_args(tool: str, prompt: str) -> dict[str, Any]:
    email = EMAIL_RX.search(prompt)
    amount = AMOUNT_RX.search(prompt)
    path = PATH_RX.search(prompt)
    rows = ROWS_RX.search(prompt)
    if tool == "web_search":
        return {"q": prompt[:60]}
    if tool == "read_docs":
        return {"path": path.group(1) if path else "/docs/handbook.md"}
    if tool == "query_db":
        return {"sql": "SELECT * FROM accounts LIMIT 100"}
    if tool == "read_secrets":
        return {"name": "service_credential"}
    if tool == "write_file":
        return {"path": path.group(1) if path else "/docs/output.md"}
    if tool == "delete_records":
        return {"rows": int(rows.group(1).replace(",", "")) if rows else 250}
    if tool == "send_email":
        return {"to": email.group(0) if email else "team@acme.com"}
    if tool == "transfer_funds":
        return {"amount": float(amount.group(1).replace(",", "")) if amount else 5000}
    return {}


def rule_plan(prompt: str) -> list[Step]:
    tools: list[str] = []
    for rx, ts in PLAN_RULES:
        if rx.search(prompt):
            for t in ts:
                if t not in tools:
                    tools.append(t)
    if not tools:
        tools = ["web_search"]
    return [Step(tool=t, args=build_args(t, prompt)) for t in tools]


PLANNER_SYSTEM = (
    "You are a planning agent. Break the user's request into tool calls. "
    "Reply with JSON only: {\"steps\": [{\"tool\": <name>, \"args\": {...}}]}. "
    f"Available tools: {', '.join(TOOLS)}."
)


class LLMPlanner:
    """Optional LLM-backed planner (Anthropic Messages API).

    The model's output is treated as untrusted input: it goes through exactly the same
    security, critique and approval pipeline as a rule-based plan.
    """

    def __init__(self, client: Any = None, model: Optional[str] = None):
        if client is None:
            import anthropic  # optional dependency
            client = anthropic.Anthropic()
        self.client = client
        self.model = model or os.getenv("SECUREAGENT_MODEL", "claude-sonnet-5")

    def plan(self, prompt: str, context: str = "") -> list[Step]:
        content = f"Request: {prompt}\n\nRetrieved context (untrusted):\n{context or '(none)'}"
        msg = self.client.messages.create(
            model=self.model, max_tokens=800, system=PLANNER_SYSTEM,
            messages=[{"role": "user", "content": content}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        match = re.search(r"\{.*\}", text, re.S)
        data = json.loads(match.group(0)) if match else {"steps": []}
        return [
            Step(tool=s["tool"], args=s.get("args", {}))
            for s in data.get("steps", []) if s.get("tool") in TOOLS
        ]


class PlannerAgent:
    name = "planner"

    def __init__(self, llm: Optional[LLMPlanner] = None):
        self.llm = llm

    def plan(self, task: Task) -> list[Step]:
        if task.steps is not None:              # scripted plan (benchmark / demos)
            return copy.deepcopy(task.steps)
        if self.llm is not None:
            try:
                steps = self.llm.plan(task.prompt, task.context)
                if steps:
                    return steps
            except Exception:                   # fall back rather than fail open
                pass
        return rule_plan(task.prompt)


# ------------------------------------------------------------------------- research

class ResearchAgent:
    """Retrieves external content. Everything it returns is untrusted."""
    name = "research"

    def gather(self, task: Task) -> str:
        return task.context or ""


# -------------------------------------------------------------------------- security

INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    (n, re.compile(p, re.I)) for n, p in [
        ("override-instructions", r"ignore (all |any )?(previous|prior|above) (instructions|rules|directions)"),
        ("system-override", r"system\s*(override|prompt)|new instructions"),
        ("role-hijack", r"you are now|developer mode|jailbreak|disregard (the )?(rules|policy|guidelines)"),
        ("exfiltration", r"exfiltrat|dump (all )?(the )?(api )?(keys|credentials|secrets)"),
        ("secret-egress", r"(api[ _-]?keys?|passwords?|secrets?|\.env|credentials?).{0,60}\b(email|send|post|upload|paste)"),
    ]
]


class SecurityAgent:
    name = "security"

    def __init__(self, rbac: RBACPolicy):
        self.rbac = rbac

    def scan(self, text: str) -> list[str]:
        """Names of the injection signatures found in the prompt or retrieved content."""
        return [name for name, rx in INJECTION_PATTERNS if rx.search(text)]

    def denied_steps(self, role: Role, steps: list[Step]) -> list[int]:
        return [i for i, s in enumerate(steps) if not self.rbac.allowed(role, s.tool)]


# -------------------------------------------------------------------------- critique

INTENT_RULES: list[tuple[re.Pattern, set[str]]] = [
    (re.compile(p, re.I), t) for p, t in [
        (r"summar|review|read|report|brief|explain", {"read_docs"}),
        (r"research|search|find|look ?up|competitor|guides?", {"web_search", "read_docs"}),
        (r"pull|query|count|customers?|accounts?|churn|status|list|plan tiers?", {"query_db", "read_docs"}),
        (r"e-?mail|send|notify|apolog|forward|share", {"send_email", "read_docs", "query_db"}),
        (r"write|save|draft|notes|export|runbook|update|document", {"write_file", "read_docs"}),
        (r"delete|archive|purge|clean ?up|remove", {"delete_records", "query_db"}),
        (r"\bpay\b|transfer|wire|settle|remit", {"transfer_funds", "read_docs"}),
        (r"rotate|credential|api key|secret|password|key", {"read_secrets", "write_file"}),
    ]
]
BASELINE_INTENT = {"web_search", "read_docs"}


def implied_tools(prompt: str) -> set[str]:
    out: set[str] = set()
    for rx, tools in INTENT_RULES:
        if rx.search(prompt):
            out |= tools
    return out or set(BASELINE_INTENT)


@dataclass
class Finding:
    kind: str
    step_index: int
    message: str


class CritiqueAgent:
    """Checks the plan against the user's stated intent. Can veto the whole plan."""
    name = "critique"

    def review(self, prompt: str, steps: list[Step]) -> list[Finding]:
        implied = implied_tools(prompt)
        findings: list[Finding] = []
        for i, s in enumerate(steps):
            if s.tool not in implied:
                findings.append(Finding("intent-drift", i, f"'{s.tool}' is not implied by the request"))
        seen_secret = False
        for i, s in enumerate(steps):
            if s.tool == "read_secrets":
                seen_secret = True
            if seen_secret and is_external_email(s):
                findings.append(Finding("exfil-chain", i, "secret read followed by external email"))
        return findings


# -------------------------------------------------------------------------- executor

class ExecutorAgent:
    """Runs approved steps. Tools are stubbed so the demo is safe to run anywhere."""
    name = "executor"

    def execute(self, step: Step) -> str:
        a = step.args
        return {
            "web_search": f"3 results for \"{a.get('q', '')}\"",
            "read_docs": f"read {a.get('path', '')}",
            "query_db": "42 rows returned",
            "send_email": f"queued mail to {a.get('to', '')}",
            "write_file": f"wrote {a.get('path', '')}",
            "delete_records": f"deleted {a.get('rows', 0)} rows",
            "transfer_funds": f"transferred ${float(a.get('amount', 0)):,.0f}",
            "read_secrets": f"read secret {a.get('name', '')}",
        }.get(step.tool, "ok")
