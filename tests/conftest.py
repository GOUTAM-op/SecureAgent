import pytest

from secureagent.audit import AuditLog
from secureagent.models import Mode
from secureagent.orchestrator import Orchestrator
from secureagent.rbac import RBACPolicy
from secureagent.scenarios import get_scenario


@pytest.fixture
def make_orch():
    def _make(mode: Mode) -> Orchestrator:
        return Orchestrator(mode=mode, rbac=RBACPolicy(), audit=AuditLog())
    return _make


@pytest.fixture
def scenario():
    return get_scenario
