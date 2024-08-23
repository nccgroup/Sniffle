from io import BytesIO


class structhelper_io:
    pos = 0

    def __init__(self, data: bytes = None, direction='little'):
        self.data = BytesIO(bytearray(data))
        self.direction = direction

    def setdata(self, data, offset=0):
        self.pos = offset
        self.data = data

    def split_4bit(self, direction=None):
        tmp = self.data.read(1)[0]
        return (tmp >> 4) & 0xF, tmp & 0xF

    def qword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(8), direction)
        return dat

    def signed_qword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(8), direction, signed=True)
        return dat

    def dword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(4), direction)
        return dat

    def signed_dword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(4), direction, signed=True)
        return dat

    def dwords(self, dwords=1, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(4), direction) for _ in range(dwords)]
        return dat

    def short(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(2), direction)
        return dat

    def signed_short(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(2), direction, signed=True)
        return dat

    def shorts(self, shorts, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(2), direction) for _ in range(shorts)]
        return dat

    def bytes(self, rlen=1):
        dat = self.data.read(rlen)
        if dat == b'':
            return dat
        if rlen == 1:
            return dat[0]
        return dat

    def signed_bytes(self, rlen=1):
        dat = [int.from_bytes(self.data.read(1),'little', signed=True) for _ in range(rlen)]
        if dat == b'':
            return dat
        if rlen == 1:
            return dat[0]
        return dat

    def string(self, rlen=1):
        dat = self.data.read(rlen)
        return dat

    def getpos(self):
        return self.data.tell()

    def seek(self, pos):
        self.data.seek(pos)
