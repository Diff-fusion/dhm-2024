import numpy as np
import random

# per http://poincare.matf.bg.ac.rs/~ezivkovm/publications/primpol1.pdf this is a primitive polynomial for 257 bits
def step_lfsr(lfsr: int, n: int) -> int:
    mask = (1<<257) - 1
    for i in range(n):
        feedback = lfsr >> 256
        lfsr = (lfsr << 1) & mask
        if feedback:
            # taps 0 and 12
            lfsr ^= 0x1001
        #if i %256 == 0:
        #print(f"{lfsr:0257b}")
    return lfsr

# create state transition matrix
transition = np.zeros((257, 257), dtype=np.uint8)
# diagonal for shift
for i in range(256):
    transition[i+1,i] = 1
# taps 0 and 12
transition[0,-1] = 1
transition[12,-1] = 1

def step_lfsr_fast(lfsr: int, n:int) -> int:
    # matrix pow uses square and multiply
    t = np.linalg.matrix_power(transition, n) % 2
    # convert lfsr to numpy array with lsb at index 0
    lfsr = np.frombuffer(lfsr.to_bytes(33, "little"), dtype=np.uint8)
    lfsr = np.unpackbits(lfsr, bitorder="little")[:257]
    # do transition
    lfsr = t.dot(lfsr) % 2
    # pack back into int
    lfsr = np.packbits(lfsr, bitorder="little").tobytes()
    return int.from_bytes(lfsr, "little")

def test_equal():
    for i in range(100):
        print(i)
        lfsr = random.randrange(0, 2**257)
        n = random.randrange(0, 100000)
        step_fast = step_lfsr_fast(lfsr, n)
        step_slow = step_lfsr(lfsr, n)
        assert step_fast == step_slow

#test_equal()

FLAG = "DHM{h0w_4r3_y0u_s0_f4st_8374012}"
UNLOCK_STEPS = 2**256

lfsr = int.from_bytes(FLAG.encode(), "little")
locked = step_lfsr_fast(lfsr, 2**257-UNLOCK_STEPS-1)
print(locked.to_bytes(33, "little"))
print(locked)
unlocked = step_lfsr_fast(locked, UNLOCK_STEPS)
#unlocked = step_lfsr(locked, UNLOCK_STEPS)
print(unlocked.to_bytes(33, "little"))
