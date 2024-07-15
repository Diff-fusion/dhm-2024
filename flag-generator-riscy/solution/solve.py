from Crypto.Cipher import AES
from array import array
from base64 import b64encode
import struct

from pwnlib.util.fiddling import hexdump
import random


def aes_enc(key: bytes, data: bytes):
    enc = AES.new(key, AES.MODE_ECB).encrypt(data)
    if False:
        print("encrypt key:", end=" ")
        for j in range(4):
            print(key[j * 4 : j * 4 + 4].hex(), end=" ")
        print("pt:", end=" ")
        for j in range(4):
            print(data[j * 4 : j * 4 + 4].hex(), end=" ")
        print("ct:", end=" ")
        for j in range(4):
            print(enc[j * 4 : j * 4 + 4].hex(), end=" ")
        print()
    return enc


def aes_dec(key: bytes, data: bytes):
    enc = AES.new(key, AES.MODE_ECB).decrypt(data)
    if False:
        print("decrypt key:", end=" ")
        for j in range(4):
            print(key[j * 4 : j * 4 + 4].hex(), end=" ")
        print("ct:", end=" ")
        for j in range(4):
            print(data[j * 4 : j * 4 + 4].hex(), end=" ")
        print("pt:", end=" ")
        for j in range(4):
            print(enc[j * 4 : j * 4 + 4].hex(), end=" ")
        print()
    return enc


def encrypt_riscy(key: bytes, iv_u32: memoryview, data: bytes):
    enc = b""
    for i in range(len(data) // 16):
        enc += aes_enc(key, data[i * 16 : (i + 1) * 16])
        tmp = array("I", key)
        for j in range(4):
            tmp[j] = (tmp[j] * iv_u32[(j + i) % 4]) % 2**32
        key = tmp.tobytes()
    return enc


def decrypt_riscy(key: bytes, iv_u32: memoryview, data: bytes):
    key_u8 = memoryview(bytearray(key))
    key_u32 = key_u8.cast("I")
    dec = b""
    for i in range(len(data) // 16):
        dec += aes_dec(key_u8, data[i * 16 : (i + 1) * 16])
        for j in range(4):
            key_u32[j] = (key_u32[j] * iv_u32[(j + i) % 4]) % 2**32
    return dec


def recover_key(plaintext: bytes, ciphertext: bytes, IV: bytes):
    assert len(plaintext) == len(ciphertext)
    assert len(plaintext) >= 2048
    key_u8 = memoryview(bytearray(16))
    key_u32 = key_u8.cast("I")
    iv_u32 = memoryview(IV).cast("I")
    assert iv_u32[0] % 2 == 1 # must be odd
    assert iv_u32[1] % 2 == 1 # must be odd
    assert iv_u32[2] % 2 == 1 # must be odd
    assert iv_u32[3] % 2 == 0 # must be even
    for i in range(128):
        ind = slice((127 - i) * 16, (128 - i) * 16)
        pt = plaintext[ind]
        ct = ciphertext[ind]

        # invert key where iv has inverse
        for j in range(4):
            idx = ((127 - i) + j) % 4
            if idx == 3:
                continue
            key_u32[j] = (key_u32[j] * pow(iv_u32[idx], -1, 2**32)) % 2**32

        # invert last u32 in subgroup
        ki = i % 4
        key_u32[ki] >>= 1
        key_u32[ki] = (key_u32[ki] * pow(iv_u32[3] >> 1, -1, 2**31)) % 2**31
        # guess remaining bit to get full group
        y = aes_dec(key_u8, ct)
        if y == pt:
            print("found 0")
        else:
            # key_u32[ki] = 1 << (31 - (i >> 2))
            key_u32[ki] |= 1 << 31
            y = aes_dec(key_u8, ct)
            assert y == pt
            print("found 1")
    return key_u8


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


enc_data = open("../public/riscy_old_encrypted.gen", "rb").read()
dec_data = open("../public/riscy_old_decrypted.gen", "rb").read()

enc_type, enc_digest, IV, enc_content = load_file_header(enc_data)
assert enc_type == 3
dec_type, dec_digest, _, dec_content = load_file_header(dec_data)
assert dec_type == 0

key = recover_key(dec_content, enc_content, IV)

KEY3 = bytes.fromhex("138d00a70cd22c0067d6c9c531ab4718")  # A8qS7MU+63fnQ1lS1yf3xg==
assert key == KEY3

# key can be used in website
print("Key:", b64encode(key).decode())

# also decrypte content
data = open("../public/riscy.gen", "rb").read()
type, digest, IV, content = load_file_header(data)
assert type == 3

iv_u32 = memoryview(IV).cast("I")
content = decrypt_riscy(key, iv_u32, content)

print(load_generator_header(content))
