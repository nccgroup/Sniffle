from sniffle import gatt

def test_format_props():
    assert gatt.format_props(0x02) == "R     "
    assert gatt.format_props(0x0C) == " Ww   "   # write + write-no-resp
    assert gatt.format_props(0x10) == "   N  "

def test_uuid_name_known_and_unknown():
    assert gatt.uuid_name(0x2A00) == "Device Name"
    assert gatt.uuid_name(0x1234) == "0x1234"
    assert gatt.uuid_name("00112233...") == "00112233..."

def test_render_tree_contains_structure():
    svc = gatt.Service(0x000c, 0xffff, 0xFFF0)
    ch = gatt.Characteristic(0x000d, 0x0C, 0x000e, 0xFFF3)
    svc.characteristics.append(ch)
    out = gatt.render_gatt_tree([svc], name="ELK-BLEDOM", mac="BE:96:24:00:07:DA",
                                posture="OPEN", color=False)
    assert "0xFFF0" in out and "0x000E" in out and "OPEN" in out
    assert "Ww" in out  # property flags rendered


def test_render_tree_no_double_uuid():
    # An unknown 16-bit UUID must appear once, not as "0xFFF3 0xFFF3".
    svc = gatt.Service(0x000c, 0xffff, 0xFFF0)
    svc.characteristics.append(gatt.Characteristic(0x000d, 0x06, 0x000e, 0xFFF3))
    out = gatt.render_gatt_tree([svc], color=False)
    assert "0xFFF3 0xFFF3" not in out
    assert "0xFFF0 0xFFF0" not in out

def test_attack_surface_flags_writable_handle():
    svc = gatt.Service(0x000c, 0xffff, 0xFFF0)
    svc.characteristics.append(gatt.Characteristic(0x000d, 0x06, 0x000e, 0xFFF3,
                                                    value=b"SHY"))
    out = gatt.render_attack_surface([svc], color=False)
    assert "send commands" in out
    assert "0x000E" in out
    assert "w 0x000E" in out          # the suggested next step

def test_attack_surface_lists_notify_and_cccd():
    svc = gatt.Service(0x0008, 0x000b, 0x1801)
    ch = gatt.Characteristic(0x0009, 0x10, 0x000a, 0xFFF4)
    ch.descriptors.append(gatt.Descriptor(0x000b, 0x2902))
    svc.characteristics.append(ch)
    out = gatt.render_attack_surface([svc], color=False)
    assert "device replies" in out and "0x000A" in out
    assert "sub 0x000B" in out

def test_attack_surface_empty_when_nothing_actionable():
    svc = gatt.Service(0x0001, 0x0007, 0x1800)
    svc.characteristics.append(gatt.Characteristic(0x0002, 0x02, 0x0003, 0x2A00))
    assert gatt.render_attack_surface([svc], color=False) == ""
