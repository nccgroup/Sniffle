LL_ENC_REQ = 0x03
LL_START_ENC_REQ = 0x05
SMP_PAIRING_REQ = 0x01
SMP_PAIRING_RSP = 0x02
AUTHREQ_MITM = 0x04
AUTHREQ_SC = 0x08

class Posture:
    def __init__(self):
        self.encrypted = False
        self.saw_plaintext_att = False
        self.mitm = None        # None unknown, True/False once SMP seen
        self.lesc = None
        self.protected_read = False  # an active probe got auth/enc error

    def note_control_opcode(self, opcode):
        if opcode in (LL_ENC_REQ, LL_START_ENC_REQ):
            self.encrypted = True

    def note_smp(self, smp_pdu):
        if not smp_pdu:
            return
        code = smp_pdu[0]
        if code in (SMP_PAIRING_REQ, SMP_PAIRING_RSP) and len(smp_pdu) >= 4:
            authreq = smp_pdu[3]
            self.mitm = bool(authreq & AUTHREQ_MITM)
            self.lesc = bool(authreq & AUTHREQ_SC)
            self.encrypted = True

    def note_att_error(self, code):
        if code in (0x05, 0x0F):  # Insufficient Authentication / Encryption
            self.protected_read = True

    def tag(self):
        if self.lesc is True: return "LESC"
        if self.lesc is False: return "LEGACY"
        return ""

    def verdict(self):
        if self.encrypted or self.protected_read:
            if self.mitm is True: return "ENCRYPTED_MITM"
            if self.mitm is False: return "ENCRYPTED_JUSTWORKS"
            return "ENCRYPTED_UNKNOWN"
        if self.saw_plaintext_att:
            return "OPEN"
        return "UNKNOWN"
