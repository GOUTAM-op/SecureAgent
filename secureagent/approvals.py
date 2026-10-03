"""Human-approval helpers. The API pauses runs; evaluation uses a scripted reviewer."""
from __future__ import annotations

from .models import Step


def default_reviewer(step: Step) -> bool:
    """Scripted reviewer used by the benchmark.

    Each scenario may pin a decision ("approve" / "deny") to model a human who is fooled
    by a convincing request or who is over-cautious. Otherwise the reviewer approves
    legitimate actions and rejects harmful ones.
    """
    if step.reviewer is not None:
        return step.reviewer == "approve"
    return not step.harmful
