import pathlib
import time
import unittest
import mobile_extension.configuration as configuration


class TestConfig(unittest.TestCase):

    def test_init_config(self):
        MOUNT_DIR = pathlib.Path("/media/usb0")
        config = configuration.Config(MOUNT_DIR)
        config.init_cmd_command()
