import struct
from base64 import b64encode

def load_file_header(data: bytes):
    format = "<ii32s16s"
    size = struct.calcsize(format)
    magic, type, digest, IV = struct.unpack(format, data[:size])
    content = data[size:]
    assert magic == 0x454C4946
    return type, digest, IV, content

def load_generator_header(data: bytes):
    format = "<i20s100s"
    size = struct.calcsize(format)
    magic, name, description = struct.unpack(format, data[:size])
    content = data[size:]
    assert magic == 0x54524E47
    return name, description, content

def recover_lfsr_state(stream: bytes):
    lfsr = 0
    for byte in stream[::-1]:
        lfsr |= byte << 64
        for bit in range(8):
            feedback = (lfsr >> 64) & 1
            if feedback:
                lfsr ^= 0x1B
            lfsr >>= 1
    return lfsr

def rev_lfsr(lfsr: int):
    for i in range(64):
        feedback = lfsr & 1
        if feedback:
            lfsr ^= 0x1000000000000001B
        lfsr >>= 1
    return lfsr

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

enc_data = open("../public/extended_old_encrypted.gen", "rb").read()
dec_data = open("../public/extended_old_decrypted.gen", "rb").read()

enc_type, enc_digest, IV, enc_content = load_file_header(enc_data)
assert enc_type == 1
dec_type, dec_digest, _, dec_content = load_file_header(dec_data)
assert dec_type == 0

# recover key stream
stream = bytes([x ^ y for x, y in zip(enc_content, dec_content[:8])])

# recover lfsr state before generation of key stream
lfsr = recover_lfsr_state(stream)
# reverse steps in key generation
lfsr = rev_lfsr(lfsr)
(iv,) = struct.unpack("<Q", IV[:8])
lfsr ^= iv
lfsr = rev_lfsr(lfsr)
key = lfsr

# only first halve of key is used
key = struct.pack("<Q", key).ljust(16, b"\x00")
# key can be used in website
print("Key:", b64encode(key).decode())

# also decrypte content
data = open("../public/extended.gen", "rb").read()
type, digest, IV, content = load_file_header(data)
assert type == 1
# decryption and encryption are the same
decrypted = encrypt_extended(key, IV, content)

print(load_generator_header(decrypted))
