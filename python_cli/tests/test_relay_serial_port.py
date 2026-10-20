"""Regression check for two relay processes claiming one serial port."""

import os
import pty
import subprocess
import sys
import unittest
from pathlib import Path

from serial import Serial


CLI = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "requires a POSIX pseudo-terminal")
class RelaySerialPortTest(unittest.TestCase):
    def test_relay_scripts_reject_port_owned_by_another_process(self):
        master_fd, slave_fd = pty.openpty()
        port = os.ttyname(slave_fd)
        try:
            with Serial(port, 115200, exclusive=True):
                for script, extra_args in (
                    ("relay_master.py", ["-m", "CA:FE:13:37:00:23"]),
                    ("relay_slave.py", []),
                ):
                    with self.subTest(script=script):
                        result = subprocess.run(
                            [sys.executable, str(CLI / script), "-s", port,
                             *extra_args],
                            cwd=CLI, capture_output=True, text=True,
                            timeout=5,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("Could not open Sniffle device", result.stderr)
                        self.assertIn("different -s ports", result.stderr)
                        self.assertNotIn("Traceback", result.stderr)
        finally:
            os.close(slave_fd)
            os.close(master_fd)


if __name__ == "__main__":
    unittest.main()
