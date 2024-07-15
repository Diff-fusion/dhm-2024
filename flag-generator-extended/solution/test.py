#!/usr/bin/env python3
# script to test that the device functions correctly
import requests
from base64 import b64encode
from enum import Enum
import struct

IP = "10.11.12.2"
BASE = f"http://{IP}"
DECRYPT_ENDPOINT = f"{BASE}/decrypt"

KEY1 = bytes.fromhex("2d2441d3d116771923c0516b9f32d2ed")  # LSRB09EWdxkjwFFrnzLS7Q==
KEY2 = bytes.fromhex("1df399efc5d97ee60af29be911f29ef4")  # HfOZ78XZfuYK8pvpEfKe9A==
KEY3 = bytes.fromhex("138d00a70cd22c0067d6c9c531ab4718")  # E40ApwzSLABn1snFMatHGA==

FLAG1 = "DHM{Great you understand Xtensa, now go on and do the other challenges}"
FLAG2 = "DHM{dawg_i_heard_you_like_cpus_so_i_put_some_cpus_in_your_cpu_so_you_can_compute_while_you_compute}"
FLAG3 = "DHM{Xtensa_ULP_RISC-V_y0u_h4v3_1t_4LL}"

SESSION = None

class ENC_TYPE(Enum):
    UNENCRYPTED = 0
    EXTENDED = 1
    FINITE = 2
    RISCY = 3


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


def decrypt(type: ENC_TYPE, key: bytes, iv: bytes, data: bytes):
    while True:
        params = {
            "type": type,
            "key": b64encode(key),
            "iv": b64encode(iv),
        }
        #r = SESSION.post(DECRYPT_ENDPOINT, params=params, data=data)
        try:
            r = requests.post(DECRYPT_ENDPOINT, params=params, data=data, timeout=10)
        except requests.exceptions.Timeout:
            print("[*] Request timeout, retry")
            continue
        break
    return r.content


def test_extended():
    enc_data = open("../public/extended_old_encrypted.gen", "rb").read()
    enc_type, enc_digest, iv, enc_content = load_file_header(enc_data)
    assert enc_type == ENC_TYPE.EXTENDED.value
    decrypted = decrypt("extended", KEY1, iv, enc_content)
    assert b"flag{this is a fake flag}" in decrypted

    enc_data = open("../public/extended.gen", "rb").read()
    enc_type, enc_digest, iv, enc_content = load_file_header(enc_data)
    assert enc_type == ENC_TYPE.EXTENDED.value
    decrypted = decrypt("extended", KEY1, iv, enc_content)
    assert b64encode(FLAG1.encode()) in decrypted

def test_finite():
    enc_data = open("../../flag-generator-finite/public/finite_old_encrypted.gen", "rb").read()
    enc_type, enc_digest, iv, enc_content = load_file_header(enc_data)
    assert enc_type == ENC_TYPE.FINITE.value
    decrypted = decrypt("finite", KEY2, iv, enc_content)
    assert b"flag{this is another fake flag}" in decrypted

    enc_data = open("../../flag-generator-finite/public/finite.gen", "rb").read()
    enc_type, enc_digest, iv, enc_content = load_file_header(enc_data)
    assert enc_type == ENC_TYPE.FINITE.value
    decrypted = decrypt("finite", KEY2, iv, enc_content)
    assert b64encode(FLAG2.encode()) in decrypted

def test_riscy():
    enc_data = open("../../flag-generator-riscy/public/riscy_old_encrypted.gen", "rb").read()
    enc_type, enc_digest, iv, enc_content = load_file_header(enc_data)
    assert enc_type == ENC_TYPE.RISCY.value
    decrypted = decrypt("riscy", KEY3, iv, enc_content)
    assert b"data:image/jpeg;base64" in decrypted

    enc_data = open("../../flag-generator-riscy/public/riscy.gen", "rb").read()
    enc_type, enc_digest, iv, enc_content = load_file_header(enc_data)
    assert enc_type == ENC_TYPE.RISCY.value
    decrypted = decrypt("riscy", KEY3, iv, enc_content)
    assert b"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSE" in decrypted


def test_index():
    r = requests.get(BASE)
    index_data = open("../deploy/challenge/main/www/index.html").read()
    assert index_data == r.text


if __name__ == "__main__":
    SESSION = requests.session()
    test_index()
    print("[+] index")
    test_extended()
    print("[+] extended")
    test_finite()
    print("[+] finite")
    test_riscy()
    print("[+] riscy")
