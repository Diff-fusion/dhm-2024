from Crypto.Cipher import AES


def aes_enc(key: bytes, data: bytes):
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def encrypt_riscy(key: bytes, iv: bytes, data: bytes):
    iv_u32 = memoryview(iv).cast("I")
    key_u8 = memoryview(bytearray(key))
    key_u32 = key_u8.cast("I")
    enc = b""
    for i in range(len(data) // 16):
        enc += aes_enc(key_u8, data[i * 16 : (i + 1) * 16])
        for j in range(4):
            key_u32[j] = (key_u32[j] * iv_u32[(j + i) % 4]) % 2**32
    return enc
