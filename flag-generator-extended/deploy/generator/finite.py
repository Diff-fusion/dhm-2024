import random
import struct
import array

BLOCK_LEN = 8
N_ROUNDS = 8
KEY_ADD = [35835, 34792, 315, 58643, 57287, 19882, 28091, 14325]


def add_blocks(dst: list[int], src: list[int], dst_offset: int = 0) -> None:
    for i in range(BLOCK_LEN):
        dst[dst_offset + i] = (dst[dst_offset + i] + src[i]) & 0xFFFF


def sub_blocks(dst: list[int], src: list[int], dst_offset: int = 0) -> None:
    for i in range(BLOCK_LEN):
        dst[dst_offset + i] = (dst[dst_offset + i] - src[i]) & 0xFFFF


def mix(data: list[int]) -> None:
    prev = data[-1]
    for i in range(BLOCK_LEN):
        curr = data[i]
        data[i] = (data[i] + prev) & 0xFFFF
        prev = curr


def gen_block(iv: list[int], key: list[int]) -> None:
    add_blocks(iv, key)
    for i in range(N_ROUNDS):
        mix(iv)
        add_blocks(key, KEY_ADD)
        add_blocks(iv, key)


def encrypt_finite(key: bytes, iv: bytes, data: bytes) -> bytes:
    key = memoryview(key).cast("H").tolist()
    iv = memoryview(iv).cast("H").tolist()
    data = memoryview(data).cast("H").tolist()
    for i in range(0, len(data), 8):
        gen_block(iv, key)
        sub_blocks(data, iv, i)
    return array.array("H", data).tobytes()
