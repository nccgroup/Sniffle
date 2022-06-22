import unittest

from python_cli import sniff_receiver_adapter


class TestSnifferAdapter(unittest.TestCase):

    def test_optional_arguments(self):

        args = sniff_receiver_adapter.OptionalArguments()
        attrs = vars(args)
        for attr in attrs:
            print(attr)