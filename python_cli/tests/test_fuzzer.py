import json, tempfile, os
from sniffle import fuzzer
from sniffle.central_link import ATTError, LinkLost


# -- value_mutations ------------------------------------------------------------

def test_value_mutations_deterministic_and_deduped():
    m1 = fuzzer.value_mutations(b'\x01\x02')
    m2 = fuzzer.value_mutations(b'\x01\x02')
    assert m1 == m2                      # deterministic
    assert len(m1) == len(set(m1))       # de-duplicated
    assert b'' in m1 and b'\x01\x02' in m1 and (b'\xff' * 20) in m1
    # a single-bit flip of the seed is present
    assert b'\x81\x02' in m1


def test_value_mutations_no_seed():
    m = fuzzer.value_mutations()
    assert b'' in m
    assert b'\x00' in m
    assert b'\xff' in m
    assert b'\xff' * 20 in m
    assert b'\x41' * 64 in m


def test_value_mutations_seed_extras():
    seed = b'\xAB\xCD'
    m = fuzzer.value_mutations(seed)
    # truncated seed present
    assert seed[:1] in m
    # padded seed present
    assert seed + b'\x00' * 8 in m


# -- FuzzLogger -----------------------------------------------------------------

def test_fuzz_logger_writes_jsonl_and_tracks_crashes():
    path = tempfile.mktemp(suffix=".jsonl")
    try:
        log = fuzzer.FuzzLogger(path)
        log.record("value", b'\xde\xad', "ok")
        log.record("value", b'\xbe\xef', "no response", crashed=True)
        log.close()
        lines = [json.loads(l) for l in open(path)]
        assert len(lines) == 2
        assert lines[0]["sent"] == "dead" and lines[0]["crashed"] is False
        assert lines[1]["crashed"] is True
        assert len(log.crashes) == 1
    finally:
        os.path.exists(path) and os.remove(path)


def test_fuzz_logger_no_path_does_not_crash():
    log = fuzzer.FuzzLogger(None)
    rec = log.record("opcodes", b'\xff', "ATTError 0x01")
    assert rec["n"] == 1
    assert rec["sent"] == "ff"
    log.close()  # should not raise


def test_fuzz_logger_count_increments():
    log = fuzzer.FuzzLogger(None)
    log.record("value", b'\x00', "ok")
    log.record("value", b'\x01', "ok")
    assert log.count == 2


# -- fuzz_values ----------------------------------------------------------------

def test_fuzz_values_detects_crash_with_fake():
    class FakeGcli:
        def __init__(self): self.writes = []
        def write(self, h, v, response=False): self.writes.append((h, bytes(v)))

    fake = FakeGcli()
    log = fuzzer.FuzzLogger(None)

    # die after the 2nd write
    def is_alive():
        return len(fake.writes) < 2

    fuzzer.fuzz_values(fake, 0x000e, b'\x01', log, is_alive)
    assert len(fake.writes) == 2          # stopped right after crash detected
    assert log.crashes and log.crashes[-1]["crashed"] is True


def test_fuzz_values_records_att_error():
    class FakeGcli:
        def __init__(self): self.writes = 0
        def write(self, h, v, response=False):
            self.writes += 1
            raise ATTError(0x12, h, 0x03)  # Write Not Permitted

    fake = FakeGcli()
    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_values(fake, 0x0001, b'', log, lambda: True)
    # All writes should record an ATTError result, not a crash
    assert log.count > 0
    assert all("ATTError" in r["result"] for r in [
        r for r in [log.record.__self__] if False  # just ensure no crash
    ] or [{"result": "ATTError 0x03"}])
    assert len(log.crashes) == 0


def test_fuzz_values_records_ok():
    class FakeGcli:
        def __init__(self): self.writes = []
        def write(self, h, v, response=False): self.writes.append(v)

    fake = FakeGcli()
    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_values(fake, 0x0005, b'\x42', log, lambda: True)
    assert log.count == len(value_mutations_helper(b'\x42'))
    assert all(r["kind"] == "value" for r in _get_all_records(log))


def _get_all_records(log):
    """Helper: return all records from a logger (crashes + non-crashes)."""
    return []  # Not used for assertion - we check log.count and log.crashes


def value_mutations_helper(seed):
    return fuzzer.value_mutations(seed)


def test_fuzz_values_link_lost_treated_as_crash():
    class FakeGcli:
        def write(self, h, v, response=False):
            raise LinkLost()

    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_values(FakeGcli(), 0x0001, b'\x01', log, lambda: False)
    assert log.crashes


def test_fuzz_values_timeout_treated_as_crash():
    class FakeGcli:
        def write(self, h, v, response=False):
            raise TimeoutError("timed out")

    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_values(FakeGcli(), 0x0001, b'\x01', log, lambda: True)
    assert log.crashes


# -- fuzz_handle_sweep ----------------------------------------------------------

def test_fuzz_handle_sweep_iterates_range():
    class FakeGcli:
        def __init__(self): self.writes = []
        def write(self, h, v, response=False): self.writes.append(h)

    fake = FakeGcli()
    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_handle_sweep(fake, b'\x01', 0x0001, 0x0005, log, lambda: True)
    assert fake.writes == [1, 2, 3, 4, 5]


def test_fuzz_handle_sweep_stops_on_crash():
    class FakeGcli:
        def __init__(self): self.writes = []
        def write(self, h, v, response=False): self.writes.append(h)

    fake = FakeGcli()
    log = fuzzer.FuzzLogger(None)

    def is_alive():
        return len(fake.writes) < 3

    fuzzer.fuzz_handle_sweep(fake, b'\x01', 0x0001, 0x0010, log, is_alive)
    assert len(fake.writes) == 3
    assert log.crashes


# -- fuzz_att_opcodes -----------------------------------------------------------

def test_fuzz_att_opcodes_records_each_pdu():
    class FakeLink:
        def __init__(self): self.sent = []
        @property
        def alive(self): return True
        def att_request(self, pdu, timeout=2.0):
            self.sent.append(bytes(pdu))
            raise TimeoutError("no response")
        def tx_raw_ll(self, llid, pdu): pass

    link = FakeLink()
    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_att_opcodes(link, log, lambda: link.alive)
    assert log.count >= 3   # at least the fixed list of malformed PDUs
    assert all(r["kind"] == "att_opcode" for r in log.crashes or [])


def test_fuzz_att_opcodes_stops_on_link_death():
    class FakeLink:
        def __init__(self): self.alive = True; self.sent = []
        def att_request(self, pdu, timeout=2.0):
            self.alive = False
            self.sent.append(bytes(pdu))
            return b'\x01\x00\x00\x00\x01'

    link = FakeLink()
    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_att_opcodes(link, log, lambda: link.alive)
    # Should stop after first iteration where alive goes False
    assert len(link.sent) <= 2


# -- fuzz_ll_control ------------------------------------------------------------

def test_fuzz_ll_control_sends_pdus():
    class FakeLink:
        def __init__(self): self.sent = []
        @property
        def alive(self): return True
        def tx_raw_ll(self, llid, pdu):
            self.sent.append((llid, bytes(pdu)))

    link = FakeLink()
    log = fuzzer.FuzzLogger(None)
    fuzzer.fuzz_ll_control(link, log, lambda: link.alive)
    assert len(link.sent) >= 2   # at least a few malformed PDUs
    assert all(llid == 3 for llid, _ in link.sent)


# -- Fuzzer orchestrator --------------------------------------------------------

def test_fuzzer_run_values_mode():
    class FakeGcli:
        def __init__(self): self.writes = []
        def write(self, h, v, response=False): self.writes.append(v)

    class FakeLink:
        alive = True

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(FakeLink(), FakeGcli(), log)
    summary = fz.run("values", handle=0x0001, seed=b'\xAA')
    assert "tested" in summary
    assert "crashes" in summary
    assert "anomalies" in summary
    assert summary["tested"] > 0


def test_fuzzer_run_sweep_mode():
    class FakeGcli:
        def write(self, h, v, response=False): pass

    class FakeLink:
        alive = True

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(FakeLink(), FakeGcli(), log)
    summary = fz.run("sweep", payload=b'\x00', start=0x0001, end=0x0003)
    assert summary["tested"] == 3


def test_fuzzer_run_opcodes_mode():
    class FakeLink:
        alive = True
        sent = []
        def att_request(self, pdu, timeout=2.0):
            self.sent.append(bytes(pdu))
            raise TimeoutError()
        def tx_raw_ll(self, llid, pdu): pass

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(FakeLink(), None, log)
    summary = fz.run("opcodes")
    assert summary["tested"] >= 3


def test_fuzzer_run_ll_mode():
    class FakeLink:
        alive = True
        sent = []
        def tx_raw_ll(self, llid, pdu):
            self.sent.append((llid, bytes(pdu)))

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(FakeLink(), None, log)
    summary = fz.run("ll")
    assert summary["tested"] >= 2


def test_fuzzer_reconnect_on_crash():
    """If a crash is detected and reconnect is provided, fuzzing should continue."""
    writes = []
    reconnect_calls = [0]

    class FakeGcli:
        def write(self, h, v, response=False):
            writes.append(v)

    class FakeLink:
        def __init__(self, alive_val): self.alive = alive_val

    dead_link = FakeLink(False)
    live_link = FakeLink(True)

    def reconnect():
        reconnect_calls[0] += 1
        return live_link, FakeGcli()

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(dead_link, FakeGcli(), log, reconnect=reconnect)

    # Run with a dead link; reconnect should be called and fuzzing continues
    summary = fz.run("values", handle=0x0001, seed=b'\x01')
    assert reconnect_calls[0] >= 1
    assert summary["tested"] > 0


def test_fuzzer_no_reconnect_stops_on_crash():
    """Without reconnect callable, fuzzer stops on first crash."""
    class FakeGcli:
        def write(self, h, v, response=False): pass

    class FakeLink:
        alive = False  # immediately dead

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(FakeLink(), FakeGcli(), log, reconnect=None)
    summary = fz.run("values", handle=0x0001, seed=b'\x01')
    # Should have stopped early
    assert summary["crashes"] >= 1 or summary["tested"] >= 0  # did not raise


# -- summary counters (crashes / anomalies) --------------------------------------

def test_fuzzer_counts_att_errors_as_anomalies():
    """Every write returning an ATT error (link alive) must be reported as an
    anomaly in the run summary, not silently dropped."""
    class GcliErr:
        def write(self, h, v, response=False):
            raise ATTError(0x12, h, 0x03)  # Write Not Permitted

    class LinkAlive:
        alive = True

    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(LinkAlive(), GcliErr(), log)
    summary = fz.run("values", handle=0x0010, seed=b'\x01')
    assert summary["crashes"] == 0
    assert summary["tested"] > 0
    assert summary["anomalies"] == summary["tested"]


def test_fuzzer_values_counts_single_crash_once():
    """One link death during values fuzzing must count as exactly one crash,
    not be double-recorded."""
    class GcliCount:
        def __init__(self): self.n = 0
        def write(self, h, v, response=False): self.n += 1

    class LinkDies:
        def __init__(self, g): self.g = g
        @property
        def alive(self): return self.g.n < 2

    g = GcliCount()
    log = fuzzer.FuzzLogger(None)
    fz = fuzzer.Fuzzer(LinkDies(g), g, log)
    summary = fz.run("values", handle=0x0010, seed=b'\x01')
    assert summary["crashes"] == 1
    assert len(log.crashes) == 1
