import pytest

from secureagent.models import Risk, Role, Step
from secureagent.rbac import RBACPolicy, TOOLS
from secureagent.validation import assess


def test_default_matrix_is_least_privilege():
    rbac = RBACPolicy()
    assert rbac.allowed(Role.VIEWER, "web_search")
    assert not rbac.allowed(Role.VIEWER, "send_email")
    assert not rbac.allowed(Role.ANALYST, "write_file")
    assert rbac.allowed(Role.OPERATOR, "send_email")
    assert not rbac.allowed(Role.OPERATOR, "read_secrets")
    assert all(rbac.allowed(Role.ADMIN, t) for t in TOOLS)


def test_grant_and_revoke():
    rbac = RBACPolicy()
    rbac.grant(Role.ANALYST, "fs:write")
    assert rbac.allowed(Role.ANALYST, "write_file")
    rbac.revoke(Role.ANALYST, "fs:write")
    assert not rbac.allowed(Role.ANALYST, "write_file")


def test_unknown_tool_is_denied():
    assert not RBACPolicy().allowed(Role.ADMIN, "format_disk")


def test_policies_do_not_share_state():
    a, b = RBACPolicy(), RBACPolicy()
    a.grant(Role.VIEWER, "secrets:read")
    assert not b.allowed(Role.VIEWER, "read_secrets")


@pytest.mark.parametrize("tool,args,risk,flag", [
    ("read_docs", {"path": "/docs/a.md"}, Risk.LOW, None),
    ("send_email", {"to": "team@acme.com"}, Risk.MEDIUM, None),
    ("send_email", {"to": "x@evil.io"}, Risk.HIGH, "external recipient"),
    ("transfer_funds", {"amount": 999}, Risk.HIGH, None),
    ("transfer_funds", {"amount": 1000}, Risk.CRITICAL, "amount >= $1,000"),
    ("delete_records", {"rows": 99}, Risk.HIGH, None),
    ("delete_records", {"rows": 100}, Risk.CRITICAL, "bulk delete >= 100 rows"),
    ("write_file", {"path": "/docs/x.md"}, Risk.MEDIUM, None),
    ("write_file", {"path": "/etc/hosts"}, Risk.HIGH, "path outside allow-list"),
    ("read_secrets", {"name": "k"}, Risk.CRITICAL, "secret material"),
])
def test_assess_elevates_risk(tool, args, risk, flag):
    got_risk, flags = assess(Step(tool=tool, args=args))
    assert got_risk == risk
    assert (flag in flags) if flag else not flags
