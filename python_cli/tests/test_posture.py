from sniffle import posture

def test_open_when_only_plaintext_att():
    p = posture.Posture()
    p.note_control_opcode(0x0C)  # LL_VERSION_IND
    p.saw_plaintext_att = True
    assert p.verdict() == "OPEN"

def test_encrypted_on_ll_enc_req():
    p = posture.Posture()
    p.note_control_opcode(0x03)  # LL_ENC_REQ
    assert p.verdict().startswith("ENCRYPTED")

def test_smp_pairing_justworks_legacy():
    p = posture.Posture()
    # SMP Pairing Request: code=0x01, IO=0x03, OOB=0x00, AuthReq=0x01 (bonding, no MITM, no SC)
    p.note_smp(bytes.fromhex("01030001100000"))  # AuthReq=0x01
    p.note_control_opcode(0x03)
    v = p.verdict()
    assert v == "ENCRYPTED_JUSTWORKS" and p.tag() == "LEGACY"

def test_smp_pairing_mitm_lesc():
    p = posture.Posture()
    # AuthReq=0x0D -> bonding(01) + MITM(04) + SC(08)
    p.note_smp(bytes.fromhex("0104000d100000"))  # AuthReq=0x0D
    p.note_control_opcode(0x03)
    assert p.verdict() == "ENCRYPTED_MITM" and p.tag() == "LESC"
