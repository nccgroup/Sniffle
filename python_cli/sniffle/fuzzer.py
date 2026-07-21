"""
sniffle/fuzzer.py - multi-layer BLE fuzzer with crash/anomaly detection and
crash-resume for the bluecat toolchain.

Targets:
  - ATT characteristic values (fuzz_values)
  - GATT handle sweep (fuzz_handle_sweep)
  - Raw ATT opcodes (fuzz_att_opcodes)
  - LL control PDUs (fuzz_ll_control)

Detection: link.alive going False, ATT error responses, TimeoutError.
Crash-resume: a reconnect callable re-establishes the link and fuzzing
continues from where it left off.
"""

import json
import time
from . import att
from .central_link import ATTError, LinkLost


# -- Mutation engine ------------------------------------------------------------

def value_mutations(seed=b''):
    """Deterministic ordered, de-duplicated set of mutated payloads from a seed."""
    muts = [b'', b'\x00', b'\xff']
    if seed:
        muts.append(seed)
        for i in range(len(seed)):
            b = bytearray(seed); b[i] ^= 0x80; muts.append(bytes(b))
        muts.append(seed + b'\x00' * 8)
        muts.append(seed[:max(0, len(seed) - 1)])
    muts += [b'\xff' * 20, b'\xff' * 244, b'\x41' * 64]
    seen, out = set(), []
    for m in muts:
        if m not in seen:
            seen.add(m); out.append(m)
    return out


# -- Logger ---------------------------------------------------------------------

class FuzzLogger:
    def __init__(self, path=None):
        self.path = path
        self.f = open(path, 'a') if path else None
        self.count = 0
        self.crashes = []
        self.anomalies = 0

    def record(self, kind, sent, result, crashed=False):
        self.count += 1
        rec = {
            "n": self.count,
            "kind": kind,
            "sent": sent.hex() if isinstance(sent, (bytes, bytearray)) else sent,
            "result": result,
            "crashed": crashed,
        }
        if crashed:
            self.crashes.append(rec)
        elif isinstance(result, str) and "ATTError" in result:
            self.anomalies += 1
        if self.f:
            self.f.write(json.dumps(rec) + "\n")
            self.f.flush()
        return rec

    def close(self):
        if self.f:
            self.f.close()


# -- Strategy: ATT characteristic value fuzzing --------------------------------

def fuzz_values(gcli, handle, seed, logger, is_alive):
    """Fuzz a single characteristic handle with value mutations.

    For each mutation: write -> record ok/ATTError -> check is_alive().
    Stops and records crash if the link dies or a transport exception is raised.
    """
    for m in value_mutations(seed):
        try:
            gcli.write(handle, m, response=True)
            result = "ok"
        except ATTError as e:
            result = "ATTError 0x%02X" % e.code
        except (LinkLost, TimeoutError):
            logger.record("value", m, "link lost / timeout", crashed=True)
            return

        logger.record("value", m, result)
        if not is_alive():
            logger.record("value", m, result + " [crash detected]", crashed=True)
            return


# -- Strategy: GATT handle sweep -----------------------------------------------

def fuzz_handle_sweep(gcli, payload, start, end, logger, is_alive):
    """Try writing payload to every handle in [start, end].

    Stops and records a crash if the link dies during the sweep.
    """
    for handle in range(start, end + 1):
        try:
            gcli.write(handle, payload, response=True)
            result = "ok"
        except ATTError as e:
            result = "ATTError 0x%02X" % e.code
        except (LinkLost, TimeoutError):
            logger.record("sweep", payload, "link lost / timeout on handle 0x%04X" % handle,
                          crashed=True)
            return

        logger.record("sweep", payload, "handle 0x%04X: %s" % (handle, result))
        if not is_alive():
            logger.record("sweep", payload,
                          "handle 0x%04X: crash detected" % handle, crashed=True)
            return


# -- Strategy: Raw ATT opcode fuzzing ------------------------------------------

# Fixed set of malformed ATT PDUs to send
_ATT_MALFORMED_PDUS = [
    # Unknown opcode 0xFF with no payload
    b'\xff',
    # Read Request with no handle field (truncated)
    b'\x0a',
    # Truncated Write Request (handle only, no value)
    b'\x12\x03',
    # Over-long Find Info Request (two handles + padding bytes)
    b'\x04\x01\x00\xff\xff\xde\xad\xbe\xef',
    # ATT_MTU_REQ with zero MTU
    b'\x02\x00\x00',
    # Opcode 0x00 (reserved/invalid)
    b'\x00\x01\x02\x03',
    # Execute Write Request with reserved flag
    b'\x18\x02',
]


def fuzz_att_opcodes(link, logger, is_alive):
    """Send a fixed list of malformed ATT PDUs and record responses.

    Uses link.att_request() so responses (or timeouts) are captured.
    Stops if the link dies.
    """
    for pdu in _ATT_MALFORMED_PDUS:
        try:
            link.att_request(pdu)
            result = "ok"
        except ATTError as e:
            result = "ATTError 0x%02X" % e.code
        except (LinkLost, TimeoutError):
            result = "no response / link lost"

        logger.record("att_opcode", pdu, result)
        if not is_alive():
            logger.record("att_opcode", pdu, "crash detected", crashed=True)
            return


# -- Strategy: LL control PDU fuzzing -----------------------------------------

# Fixed set of malformed LL control PDUs
_LL_MALFORMED_PDUS = [
    # Unknown control opcode 0xFF
    b'\xff\x00',
    # Zero-length PDU
    b'',
    # Over-long PDU (255 bytes, opcode 0xFF)
    b'\xff' + b'\x00' * 30,
    # LL_UNKNOWN_RSP for an unknown opcode
    b'\x07\xff',
    # LL_LENGTH_REQ with edge values
    b'\x14\xfb\x00\xfb\x00\x00\x00\x00\x00',
    # LL_FEATURE_REQ with all-zero features
    b'\x08' + b'\x00' * 8,
]


def fuzz_ll_control(link, logger, is_alive):
    """Send a fixed list of malformed LL control PDUs via tx_raw_ll.

    Uses LLID=3 (LL control). Records each send and checks is_alive() after a
    brief settle period to allow the peer to react.
    """
    for pdu in _LL_MALFORMED_PDUS:
        link.tx_raw_ll(3, pdu)
        logger.record("ll_control", pdu, "sent")
        time.sleep(0.01)   # brief settle
        if not is_alive():
            logger.record("ll_control", pdu, "crash detected", crashed=True)
            return


# -- Fuzzer orchestrator --------------------------------------------------------

class Fuzzer:
    """Orchestrates multi-layer BLE fuzzing with optional crash-resume.

    Parameters
    ----------
    link      : CentralLink (or compatible)
    gcli      : GattClient (or compatible); may be None for ll/opcodes modes
    logger    : FuzzLogger
    reconnect : Optional callable that returns (new_link, new_gcli) after a
                crash.  If None, fuzzing stops on the first crash.
    """

    def __init__(self, link, gcli, logger, reconnect=None):
        self.link = link
        self.gcli = gcli
        self.logger = logger
        self.reconnect = reconnect

    def _is_alive(self):
        return self.link.alive

    def run(self, mode, **kw):
        """Dispatch to a fuzzing strategy by name.

        Modes: "values", "sweep", "opcodes", "ll"

        Keyword arguments are forwarded to the strategy function.

        Returns a summary dict: {tested, crashes, anomalies}.
        """
        before = self.logger.count
        before_crashes = len(self.logger.crashes)
        before_anomalies = self.logger.anomalies

        if mode == "values":
            handle = kw.get("handle", 0x0001)
            seed = kw.get("seed", b'')
            self._run_with_resume(
                lambda: fuzz_values(self.gcli, handle, seed, self.logger, self._is_alive)
            )
        elif mode == "sweep":
            payload = kw.get("payload", b'\x00')
            start = kw.get("start", 0x0001)
            end = kw.get("end", 0x00FF)
            self._run_with_resume(
                lambda: fuzz_handle_sweep(self.gcli, payload, start, end,
                                          self.logger, self._is_alive)
            )
        elif mode == "opcodes":
            self._run_with_resume(
                lambda: fuzz_att_opcodes(self.link, self.logger, self._is_alive)
            )
        elif mode == "ll":
            self._run_with_resume(
                lambda: fuzz_ll_control(self.link, self.logger, self._is_alive)
            )
        else:
            raise ValueError("Unknown fuzzing mode: %r" % mode)

        tested = self.logger.count - before
        new_crashes = len(self.logger.crashes) - before_crashes
        anomalies = self.logger.anomalies - before_anomalies
        return {"tested": tested, "crashes": new_crashes, "anomalies": anomalies}

    def _run_with_resume(self, strategy_fn):
        """Run strategy_fn; if a crash is detected and reconnect is set,
        call reconnect() to get a fresh link/gcli and retry once."""
        prev_crash_count = len(self.logger.crashes)
        strategy_fn()
        new_crashes = len(self.logger.crashes) - prev_crash_count

        if new_crashes > 0 and self.reconnect is not None:
            try:
                new_link, new_gcli = self.reconnect()
                self.link = new_link
                if new_gcli is not None:
                    self.gcli = new_gcli
                # Continue with fresh link - run the strategy once more
                strategy_fn()
            except Exception:
                pass  # reconnect failed; stop gracefully
