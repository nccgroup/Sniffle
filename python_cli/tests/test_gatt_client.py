from sniffle import att, gatt
from sniffle.central_link import ATTError

class FakeLink:
    """Returns scripted ATT responses (bytes) or raises a scripted ATTError."""
    def __init__(self, script):
        self.script = list(script)
        self.sent = []
    def att_request(self, pdu, timeout=2.0):
        self.sent.append(bytes(pdu))
        rsp = self.script.pop(0)
        if isinstance(rsp, ATTError):
            raise rsp
        return rsp
    def att_command(self, opcode, payload):
        self.sent.append(bytes([opcode]) + bytes(payload))

def test_discover_services():
    link = FakeLink([
        bytes.fromhex("110601000700001808000b000118"),  # 0x1800 @1-7, 0x1801 @8-b
        ATTError(0x10, 0x000c, 0x0A),                    # Attr Not Found -> stop
    ])
    cli = gatt.GattClient(link)
    svcs = cli.discover_services()
    assert len(svcs) == 2
    assert svcs[0].uuid == 0x1800 and svcs[0].start == 0x0001 and svcs[0].end == 0x0007
    assert svcs[1].uuid == 0x1801 and svcs[1].end == 0x000b

def test_discover_characteristics():
    svc = gatt.Service(0x000c, 0x0012, 0xFFF0)
    link = FakeLink([
        bytes.fromhex("09070d00100e00f3ff"),  # decl 0x000d props 0x10 vhandle 0x000e uuid 0xFFF3
        ATTError(0x08, 0x000f, 0x0A),
    ])
    cli = gatt.GattClient(link)
    chars = cli.discover_characteristics(svc)
    assert len(chars) == 1
    assert chars[0].value_handle == 0x000e and chars[0].properties == 0x10 and chars[0].uuid == 0xFFF3

def test_read_strips_opcode():
    link = FakeLink([bytes.fromhex("0b48656c6c6f")])  # Read Rsp "Hello"
    cli = gatt.GattClient(link)
    assert cli.read(0x0003) == b"Hello"

def test_write_no_response_sends_write_cmd():
    link = FakeLink([])
    cli = gatt.GattClient(link)
    cli.write(0x000e, b"\x01\x02", response=False)
    # Write Command 0x52, handle 0x000e LE, value
    assert link.sent[-1] == bytes.fromhex("520e00") + b"\x01\x02"

def test_discover_descriptors_empty_response_no_crash():
    # A short/corrupt Find-Information response (opcode 0x05, format byte, NO
    # entries) parses to []. discover_descriptors must stop, not IndexError on
    # entries[-1]. (Regression for the hijack-enum crash on the ELK-BLEDOM.)
    link = FakeLink([bytes.fromhex("0501")])
    cli = gatt.GattClient(link)
    ch = gatt.Characteristic(0x000d, 0x10, 0x000e, 0xFFF4)
    assert cli.discover_descriptors(ch, next_handle=0x0014) == []

def test_discover_services_empty_response_no_crash():
    link = FakeLink([bytes.fromhex("1106")])  # Read-By-Group Rsp, len byte, no entries
    cli = gatt.GattClient(link)
    assert cli.discover_services() == []
