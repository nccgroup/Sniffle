"""
test_scan_audit.py - unit tests for recon.scan_and_audit orchestration.

No real hardware is used. Both _scan_channel and audit.audit_device are
monkeypatched to return canned data so the tests exercise only the
orchestration logic inside scan_and_audit.
"""

import pytest
from sniffle.recon import Device, scan_and_audit
from sniffle.audit import Finding, HIGH, INFO


# ---------------------------------------------------------------------------
# Fixture: canned devices
# ---------------------------------------------------------------------------

@pytest.fixture
def dev_a():
    return Device(mac="AA:BB:CC:DD:EE:FF", addr_type="Public", name="DevA", rssi=-50)


@pytest.fixture
def dev_b():
    return Device(mac="BB:CC:DD:EE:FF:00", addr_type="RPA", name="DevB", rssi=-60)


@pytest.fixture
def dev_c():
    return Device(mac="CC:DD:EE:FF:00:11", addr_type="Static", name="DevC", rssi=-70)


@pytest.fixture
def canned_finding():
    return Finding(HIGH, "no-encryption", "GATT readable without encryption", "")


# ---------------------------------------------------------------------------
# Helper: build a fake _scan_channel that returns pre-canned results per call.
# calls[i] -> list of Device returned on the i-th invocation.
# ---------------------------------------------------------------------------

def make_scan_channel_stub(*per_call_lists):
    """Return a replacement for recon._scan_channel.

    On the n-th call it pops and returns per_call_lists[n].
    Also populates the *seen* dict so scan_and_audit's dedup works correctly.
    """
    call_iter = iter(per_call_lists)

    def _stub(hw, ch, duration, seen, best_rssi):
        try:
            new_devs = list(next(call_iter))
        except StopIteration:
            new_devs = []
        result = []
        for dev in new_devs:
            if dev.mac not in seen:
                seen[dev.mac] = dev
                best_rssi[dev.mac] = dev.rssi
                result.append(dev)
            # if already in seen (dup across channels) don't add to result
        return result

    return _stub


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScanAndAuditOrchestration:

    def test_all_three_channels_audited_once_each(
            self, monkeypatch, dev_a, dev_b, dev_c, canned_finding):
        """Devices discovered on channels 37/38/39 are each audited exactly once."""
        audited_macs = []

        # ch37 -> [A, B], ch38 -> [A again (dup), C], ch39 -> []
        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_a, dev_b], [dev_a, dev_c], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: (audited_macs.append(dev.mac), [canned_finding])[1],
        )

        results = scan_and_audit(hw=None)

        assert len(results) == 3, "Expected 3 unique devices audited, got %d" % len(results)
        assert sorted(audited_macs) == sorted([dev_a.mac, dev_b.mac, dev_c.mac])

    def test_duplicate_not_re_audited(
            self, monkeypatch, dev_a, dev_b, canned_finding):
        """A device seen on multiple channels is audited only once."""
        audit_call_count = {"n": 0}

        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_a, dev_b], [dev_a], [dev_a]),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: (
                audit_call_count.__setitem__("n", audit_call_count["n"] + 1),
                [canned_finding],
            )[1],
        )

        results = scan_and_audit(hw=None)

        assert audit_call_count["n"] == 2, (
            "Expected 2 audits (A once, B once); got %d" % audit_call_count["n"])
        assert len(results) == 2

    def test_rpa_audited_when_include_private_true(
            self, monkeypatch, dev_b, canned_finding):
        """RPA device IS audited when include_private=True (default)."""
        audited_macs = []

        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_b], [], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: (audited_macs.append(dev.mac), [canned_finding])[1],
        )

        results = scan_and_audit(hw=None, include_private=True)

        assert dev_b.mac in audited_macs, "RPA device should be audited with include_private=True"
        assert len(results) == 1

    def test_rpa_skipped_when_include_private_false(
            self, monkeypatch, dev_a, dev_b, dev_c, canned_finding):
        """RPA device is SKIPPED and Public/Static ARE audited when include_private=False."""
        audited_macs = []

        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_a, dev_b], [dev_c], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: (audited_macs.append(dev.mac), [canned_finding])[1],
        )

        results = scan_and_audit(hw=None, include_private=False)

        assert dev_b.mac not in audited_macs, "RPA device should be skipped when include_private=False"
        assert dev_a.mac in audited_macs, "Public device should be audited"
        assert dev_c.mac in audited_macs, "Static device should be audited"
        assert len(results) == 2

    def test_on_discover_callback_called(
            self, monkeypatch, dev_a, dev_b, canned_finding):
        """on_discover callback is called for each newly discovered device."""
        discovered = []

        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_a], [dev_b], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: [canned_finding],
        )

        scan_and_audit(hw=None, on_discover=lambda d: discovered.append(d.mac))

        assert sorted(discovered) == sorted([dev_a.mac, dev_b.mac])

    def test_on_result_callback_called(
            self, monkeypatch, dev_a, canned_finding):
        """on_result callback is called after auditing each device."""
        results_cb = []

        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_a], [], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: [canned_finding],
        )

        scan_and_audit(
            hw=None,
            on_result=lambda d, f: results_cb.append((d.mac, f)),
        )

        assert len(results_cb) == 1
        mac, findings = results_cb[0]
        assert mac == dev_a.mac
        assert findings == [canned_finding]

    def test_return_value_structure(
            self, monkeypatch, dev_a, dev_c, canned_finding):
        """scan_and_audit returns list of (Device, findings) tuples."""
        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_a, dev_c], [], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: [canned_finding],
        )

        results = scan_and_audit(hw=None)

        assert isinstance(results, list)
        for item in results:
            assert isinstance(item, tuple) and len(item) == 2
            device, findings = item
            assert isinstance(device, Device)
            assert isinstance(findings, list)

    def test_single_channel_mode(
            self, monkeypatch, dev_a, canned_finding):
        """When advchan is specified only that channel is scanned."""
        scan_calls = []

        def _stub(hw, ch, duration, seen, best_rssi):
            scan_calls.append(ch)
            if ch == 38:
                seen[dev_a.mac] = dev_a
                best_rssi[dev_a.mac] = dev_a.rssi
                return [dev_a]
            return []

        monkeypatch.setattr("sniffle.recon._scan_channel", _stub)
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: [canned_finding],
        )

        results = scan_and_audit(hw=None, advchan=38)

        assert scan_calls == [38], "Only channel 38 should be scanned; got: %s" % scan_calls
        assert len(results) == 1

    def test_empty_scan_returns_empty_results(self, monkeypatch):
        """If no devices are found, scan_and_audit returns an empty list."""
        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([], [], []),
        )
        # audit_device should never be called
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: (_ for _ in ()).throw(
                AssertionError("audit_device should not be called when no devices found")
            ),
        )

        results = scan_and_audit(hw=None)
        assert results == []

    def test_nrpa_skipped_when_include_private_false(
            self, monkeypatch, canned_finding):
        """NRPA device is also skipped when include_private=False."""
        dev_nrpa = Device(mac="DD:EE:FF:00:11:22", addr_type="NRPA", name="nrpa", rssi=-55)
        audited_macs = []

        monkeypatch.setattr(
            "sniffle.recon._scan_channel",
            make_scan_channel_stub([dev_nrpa], [], []),
        )
        monkeypatch.setattr(
            "sniffle.audit.audit_device",
            lambda hw, dev, aggressive=False: (audited_macs.append(dev.mac), [canned_finding])[1],
        )

        results = scan_and_audit(hw=None, include_private=False)

        assert dev_nrpa.mac not in audited_macs, "NRPA should be skipped with include_private=False"
        assert results == []
