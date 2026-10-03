import dataclasses

from secureagent.audit import AuditLog


def _log():
    log = AuditLog(clock=iter(range(1000, 2000)).__next__)
    for i in range(5):
        log.append("r1", "planner", f"event.{i}", f"detail {i}")
    return log


def test_chain_verifies():
    assert _log().verify() == (True, None)


def test_entries_link_to_previous_hash():
    entries = _log().entries()
    for prev, cur in zip(entries, entries[1:]):
        assert cur.prev_hash == prev.hash


def test_tampering_with_a_detail_is_detected():
    log = _log()
    log._entries[2] = dataclasses.replace(log._entries[2], detail="nothing to see here")
    assert log.verify() == (False, 2)


def test_deleting_an_entry_is_detected():
    log = _log()
    del log._entries[1]
    ok, bad = log.verify()
    assert not ok and bad == 2  # seq numbers no longer line up


def test_filter_by_run():
    log = AuditLog()
    log.append("a", "x", "e", "d")
    log.append("b", "x", "e", "d")
    assert len(log.entries("a")) == 1
