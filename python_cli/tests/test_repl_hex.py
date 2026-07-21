"""Unit tests for bluecat._hexbytes - pasting sniffed bytes into the REPL."""
import bluecat

def test_space_separated_hex():
    assert bluecat._hexbytes(["7e","07","05","03","f6","00","ff","10","ef"]) \
        == bytes.fromhex("7e070503f600ff10ef")

def test_colon_separated_hex():
    assert bluecat._hexbytes(["7e:07:05"]) == bytes.fromhex("7e0705")

def test_single_blob():
    assert bluecat._hexbytes(["7e070503"]) == bytes.fromhex("7e070503")

def test_empty():
    assert bluecat._hexbytes([]) == b""
