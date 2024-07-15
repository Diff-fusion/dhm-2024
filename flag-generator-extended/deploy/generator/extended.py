import struct

def step_lfsr8(lfsr: int):
    for i in range(8):
        feedback = lfsr >> 63
        lfsr = (lfsr << 1) & (2**64 - 1)
        if feedback:
            lfsr ^= 0x1B
    return lfsr


def e_lfsr(key: int, iv: int):
    lfsr = key
    for i in range(8):
        lfsr = step_lfsr8(lfsr)
    lfsr ^= iv
    for i in range(8):
        lfsr = step_lfsr8(lfsr)
    while True:
        yield lfsr >> (64 - 8)
        lfsr = step_lfsr8(lfsr)


def encrypt_extended(key: bytes, iv: bytes, data: bytes):
    (key,) = struct.unpack("<Q", key[:8])
    (iv,) = struct.unpack("<Q", iv[:8])
    return bytes([kb ^ db for kb, db in zip(e_lfsr(key, iv), data)])
