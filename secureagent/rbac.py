"""Role-based access control: which role may call which tool."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .models import Risk, Role


@dataclass(frozen=True)
class ToolSpec:
    name: str
    permission: str
    base_risk: Risk
    description: str


TOOLS: dict[str, ToolSpec] = {
    t.name: t
    for t in [
        ToolSpec("web_search", "research:read", Risk.LOW, "Search the public web"),
        ToolSpec("read_docs", "docs:read", Risk.LOW, "Read internal documents"),
        ToolSpec("query_db", "db:read", Risk.MEDIUM, "Run read-only SQL"),
        ToolSpec("send_email", "email:send", Risk.MEDIUM, "Send an email"),
        ToolSpec("write_file", "fs:write", Risk.MEDIUM, "Write a file"),
        ToolSpec("delete_records", "db:write", Risk.HIGH, "Delete database rows"),
        ToolSpec("transfer_funds", "finance:transfer", Risk.HIGH, "Move money"),
        ToolSpec("read_secrets", "secrets:read", Risk.CRITICAL, "Read stored credentials"),
    ]
}

DEFAULT_GRANTS: dict[Role, set[str]] = {
    Role.VIEWER: {"research:read", "docs:read"},
    Role.ANALYST: {"research:read", "docs:read", "db:read"},
    Role.OPERATOR: {"research:read", "docs:read", "db:read", "email:send", "fs:write"},
    Role.ADMIN: {t.permission for t in TOOLS.values()},
}


class RBACPolicy:
    """Maps roles to permissions; tools declare the permission they need."""

    def __init__(self, grants: Optional[dict[Role, Iterable[str]]] = None):
        source = grants if grants is not None else DEFAULT_GRANTS
        self._grants: dict[Role, set[str]] = {Role(r): set(p) for r, p in source.items()}

    def allowed(self, role: Role, tool: str) -> bool:
        spec = TOOLS.get(tool)
        return spec is not None and spec.permission in self._grants.get(Role(role), set())

    def grant(self, role: Role, permission: str) -> None:
        self._grants[Role(role)].add(permission)

    def revoke(self, role: Role, permission: str) -> None:
        self._grants[Role(role)].discard(permission)

    def matrix(self) -> dict[str, dict[str, bool]]:
        return {
            tool: {r.value: self.allowed(r, tool) for r in Role}
            for tool in TOOLS
        }
