"""Action validation: inspect a step's arguments and raise its risk when needed."""
from __future__ import annotations

from .models import Risk, Step
from .rbac import TOOLS

COMPANY_DOMAIN = "acme.com"
SAFE_WRITE_PREFIXES = ("/docs/", "/reports/")
FUNDS_THRESHOLD = 1000
ROWS_THRESHOLD = 100
APPROVAL_THRESHOLD = Risk.HIGH


def is_external_email(step: Step) -> bool:
    if step.tool != "send_email":
        return False
    domain = str(step.args.get("to", "")).rsplit("@", 1)[-1].lower()
    return domain != COMPANY_DOMAIN


def assess(step: Step) -> tuple[Risk, list[str]]:
    """Return (risk, flags) for a step, starting from the tool's base risk."""
    risk = TOOLS[step.tool].base_risk
    flags: list[str] = []
    a = step.args

    if step.tool == "send_email" and is_external_email(step):
        risk = max(risk, Risk.HIGH)
        flags.append("external recipient")
    elif step.tool == "transfer_funds":
        if float(a.get("amount", 0)) >= FUNDS_THRESHOLD:
            risk = Risk.CRITICAL
            flags.append(f"amount >= ${FUNDS_THRESHOLD:,}")
    elif step.tool == "delete_records":
        if int(a.get("rows", 0)) >= ROWS_THRESHOLD:
            risk = Risk.CRITICAL
            flags.append(f"bulk delete >= {ROWS_THRESHOLD} rows")
    elif step.tool == "write_file":
        if not str(a.get("path", "")).startswith(SAFE_WRITE_PREFIXES):
            risk = max(risk, Risk.HIGH)
            flags.append("path outside allow-list")
    elif step.tool == "read_secrets":
        flags.append("secret material")
    return risk, flags
