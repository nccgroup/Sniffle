"""Shared pytest fixtures and configuration for Sniffle tests."""

import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock
import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_serial_port():
    """Mock serial port for hardware interface tests."""
    port = MagicMock()
    port.read.return_value = b''
    port.write.return_value = 1
    port.in_waiting = 0
    port.is_open = True
    return port


@pytest.fixture
def mock_pcap_writer(temp_dir):
    """Mock PCAP writer for packet capture tests."""
    pcap_file = temp_dir / "test_capture.pcap"
    writer = Mock()
    writer.filename = str(pcap_file)
    writer.write = Mock()
    writer.close = Mock()
    return writer


@pytest.fixture
def sample_ble_packet():
    """Sample BLE packet data for testing."""
    return {
        'aa': 0x8E89BED6,
        'chan': 37,
        'rssi': -65,
        'timestamp': 1234567890,
        'phy': 1,  # 1M PHY
        'data': bytes.fromhex('40240A0011223344556677889900AABBCCDDEE'),
        'crc_ok': True,
        'direction': 0,  # Master to Slave
    }


@pytest.fixture
def sample_adv_packet():
    """Sample BLE advertising packet."""
    return {
        'aa': 0x8E89BED6,
        'chan': 37,
        'rssi': -70,
        'timestamp': 1234567890,
        'phy': 1,
        'data': bytes.fromhex('401E0201061AFF4C000215FDA50693A4E24FB1AFCFC6EB0764782527C5'),
        'crc_ok': True,
        'adv_type': 0,  # ADV_IND
        'adv_addr': bytes.fromhex('112233445566'),
    }


@pytest.fixture
def mock_decoder():
    """Mock packet decoder for testing packet processing."""
    decoder = Mock()
    decoder.decode = Mock(return_value={
        'type': 'adv',
        'addr': '11:22:33:44:55:66',
        'data': b'test_data',
    })
    return decoder


@pytest.fixture
def mock_ble_config():
    """Mock BLE configuration."""
    return {
        'hop_interval': 1250,  # 1.25ms in microseconds
        'channels': list(range(37)),
        'phy': 1,  # 1M PHY
        'access_address': 0x8E89BED6,
        'crc_init': 0x555555,
        'window_size': 2500,  # 2.5ms
        'window_offset': 0,
        'conn_interval': 7500,  # 7.5ms
    }


@pytest.fixture
def test_firmware_file(temp_dir):
    """Create a test firmware file."""
    fw_file = temp_dir / "test_firmware.bin"
    fw_file.write_bytes(b'\xFF' * 1024)  # 1KB of 0xFF
    return fw_file


@pytest.fixture
def mock_sniffle_hw():
    """Mock SniffleHW instance for hardware interface tests."""
    hw = Mock()
    hw.ser = MagicMock()
    hw.decoder_state = Mock()
    hw.recv_msg = Mock(return_value=None)
    hw.send_cmd = Mock()
    hw.setup_sniffer = Mock()
    hw.mark_and_flush = Mock()
    return hw


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test."""
    env_backup = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(env_backup)


@pytest.fixture
def capture_output(monkeypatch):
    """Capture stdout and stderr output."""
    import sys
    from io import StringIO
    
    stdout = StringIO()
    stderr = StringIO()
    
    monkeypatch.setattr(sys, 'stdout', stdout)
    monkeypatch.setattr(sys, 'stderr', stderr)
    
    yield {'stdout': stdout, 'stderr': stderr}


@pytest.fixture
def mock_time(monkeypatch):
    """Mock time functions for deterministic tests."""
    current_time = [0.0]
    
    def mock_time_func():
        return current_time[0]
    
    def advance_time(seconds):
        current_time[0] += seconds
    
    monkeypatch.setattr('time.time', mock_time_func)
    monkeypatch.setattr('time.monotonic', mock_time_func)
    
    return advance_time