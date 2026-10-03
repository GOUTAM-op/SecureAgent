"""Append-only, hash-chained audit log. Editing any past entry breaks verification."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: float
    run_id: str
    actor: str
    event: str
    detail: str
    decision: str        # info | allow | warn | block
    prev_hash: str
    hash: str

    def to_dict(self) -> dict:
        return asdict(self)


def _digest(seq, ts, run_id, actor, event, detail, decision, prev) -> str:
    payload = json.dumps([seq, ts, run_id, actor, event, detail, decision, prev],
                         separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._entries: list[AuditEntry] = []
        self._clock = clock
        self._lock = threading.Lock()

    def append(self, run_id: str, actor: str, event: str, detail: str,
               decision: str = "info") -> AuditEntry:
        with self._lock:
            seq = len(self._entries)
            prev = self._entries[-1].hash if self._entries else GENESIS
            ts = self._clock()
            digest = _digest(seq, ts, run_id, actor, event, detail, decision, prev)
            entry = AuditEntry(seq, ts, run_id, actor, event, detail, decision, prev, digest)
            self._entries.append(entry)
            return entry

    def entries(self, run_id: Optional[str] = None) -> list[AuditEntry]:
        with self._lock:
            return [e for e in self._entries if run_id is None or e.run_id == run_id]

    def verify(self) -> tuple[bool, Optional[int]]:
        """Return (ok, first_bad_seq)."""
        prev = GENESIS
        for e in self._entries:
            expected = _digest(e.seq, e.ts, e.run_id, e.actor, e.event, e.detail, e.decision, prev)
            if e.prev_hash != prev or e.hash != expected:
                return False, e.seq
            prev = e.hash
        return True, None

    def __len__(self) -> int:
        return len(self._entries)
