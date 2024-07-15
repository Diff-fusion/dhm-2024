def step_lfsr(lfsr: int, n: int) -> int:
    mask = (1<<257) - 1
    for i in range(n):
        feedback = lfsr >> 256
        lfsr = (lfsr << 1) & mask
        if feedback:
            lfsr ^= 0x1001
    return lfsr

locked = 203745769409068536978743361691286385722962785255197588475888648333603407239233
unlocked = step_lfsr(locked, 2**256) # this will never finish MUHAHAHA...
print(unlocked.to_bytes(33, "little").strip(b"\x00").decode())
