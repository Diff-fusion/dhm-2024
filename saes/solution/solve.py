from aes import AES, bytes2matrix, matrix2bytes, add_round_key, sub_bytes, shift_rows, mix_columns, s_box, inv_s_box, xor_bytes
from saes import SAES
#import numpy as np
import random
import os
from pwn import *

def step_lfsr(lfsr: int):
    for i in range(127):
        feedback = lfsr >> 126
        lfsr = (lfsr << 1) & (2**127 - 1)
        if feedback:
            lfsr ^= 0x3
    return lfsr

def reverse_key_schedule(round_key, aes_round):
    """reverse the AES-128 key schedule, using a single round_key."""
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    #round_key = np.array(round_key, np.uint8)
    for i in range(aes_round - 1, -1, -1):
        a2 = round_key[0:4]
        b2 = round_key[4:8]
        c2 = round_key[8:12]
        d2 = round_key[12:16]

        d1 = xor_bytes(d2, c2)
        c1 = xor_bytes(c2, b2)
        b1 = xor_bytes(b2, a2)
        d1s = [s_box[b] for b in d1]
        a1 = bytearray(xor_bytes(a2, d1s[1:] + d1s[:1]))
        a1[0] ^= rcon[i]

        round_key = a1 + b1 + c1 + d1

    return round_key

def recover_key(cta: list[bytes], cts: list[bytes]):
    # === 2. Recover first key byte
    # the lfsr is only 127 bit so the MSB can only have the bottom 7 bits flipped

    diffs = {}

    # start guessing on the first block for every key byte
    for guess in range(256):
        inva = inv_s_box[cta[0][0] ^ guess]
        invs = inv_s_box[cts[0][0] ^ guess]
        diff = inva ^ invs
        if diff > 128:
            # lfsr is only 127 bit
            continue

        l = diffs.get(diff, set())
        l.add(guess)
        diffs[diff] = l

    #print(len(diffs), diffs)


    # for the next three blocks check if the diff to key mapping still exists
    for i in range(1, 4):
        diffs_new = {}
        for diff, guesses in diffs.items():
            # translate diff through lfsr
            diff_trans = diff << 120
            for j in range(i):
                diff_trans = step_lfsr(diff_trans)
            diff_trans >>= 120
            diff_trans ^= diff
            diff_trans &= 0x7f

            # check each remaining key guess
            for key_guess in guesses:
                inva = inv_s_box[cta[i][0] ^ key_guess]
                invs = inv_s_box[cts[i][0] ^ key_guess]
                calc_diff = inva ^ invs
                # lose 1 more lsb of information of the lfsr for each block
                for loss in range(2**(i)):
                    # calculate diff after lfsr step + loss
                    next_diff = calc_diff ^ loss ^ diff_trans
                    # only keep diffs that are still possible
                    l = diffs.get(next_diff, None)
                    if l is None:
                        continue
                    if key_guess not in l:
                        continue
                    l = diffs_new.get(next_diff, set())
                    l.add(key_guess)
                    diffs_new[next_diff] = l

        diffs = diffs_new

    print(diffs_new)
    # with very high probability only one diff to key mapping remains
    assert len(diffs_new) == 1
    diff, key_set = diffs_new.popitem()
    assert len(key_set) == 1
    recovered_key = [None] * 16
    recovered_key[0] = key_set.pop()

    recovered_lfsr = diff << 120

    # === 3. Start recovering the key from the last byte and work backwards
    # this is helpfull as we now know the top bits of the lfsr state from the previous step
    # due to the construction the lfsr state in the next blocks is only dependent on theses bits
    for offset in range(15):
        print("Recovering offset", offset)
        # bit offset in lfsr
        bit_offset = offset * 8
        # byte in ciphertext
        byte = ((15 - offset) * 13) % 16
        # next start from the lsb upwards
        diffs = {}

        # start guessing on the first block for every key byte
        for guess in range(256):
            inva = inv_s_box[cta[0][byte] ^ guess]
            invs = inv_s_box[cts[0][byte] ^ guess]
            diff = inva ^ invs
            l = diffs.get(diff, set())
            l.add(guess)
            diffs[diff] = l

        #print(len(diffs), diffs)

        # for the next three blocks check if the diff to key mapping still exists
        for i in range(1, 4):
            diffs_new = {}
            for diff, guesses in diffs.items():
                # translate diff through lfsr
                diff_trans = (diff << bit_offset) | recovered_lfsr
                for j in range(i):
                    diff_trans = step_lfsr(diff_trans)
                diff_trans >>= bit_offset
                diff_trans ^= diff
                diff_trans &= 0xff

                # check each remaining key guess
                for key_guess in guesses:
                    inva = inv_s_box[cta[i][byte] ^ key_guess]
                    invs = inv_s_box[cts[i][byte] ^ key_guess]
                    # calculate diff after lfsr step
                    # don't need loss anymore as we know the previous bits
                    next_diff = inva ^ invs ^ diff_trans
                    # only keep diffs that are still possible
                    l = diffs.get(next_diff, None)
                    if l is None:
                        continue
                    if key_guess not in l:
                        continue
                    l = diffs_new.get(next_diff, set())
                    l.add(key_guess)
                    diffs_new[next_diff] = l

            diffs = diffs_new

        print(diffs_new)
        # with very high probability only one diff to key mapping remains
        assert len(diffs_new) == 1
        diff, key_set = diffs_new.popitem()
        assert len(key_set) == 1
        recovered_key[byte] = key_set.pop()

        recovered_lfsr |= diff << bit_offset

    recovered_key = reverse_key_schedule(recovered_key, 10)

    return recovered_key, recovered_lfsr

def get_ciphertexts(io: tube):
    plaintext = os.urandom(16) * 4
    io.sendlineafter(b"hex> ", plaintext.hex().encode())
    io.recvuntil(b"data: ")
    cta = bytes.fromhex(io.recvline().decode())
    io.recvuntil(b"data: ")
    cts = bytes.fromhex(io.recvline().decode())
    for a, s in zip(cta, cts):
        if a == s:
            # there is a zero diff,
            # it might work but can also fail
            # try with other values
            return None, None

    cta = [cta[i:i+16] for i in range(0, len(cta), 16)]
    cts = [cts[i:i+16] for i in range(0, len(cts), 16)]
    return cta, cts


def test_assert():
    for test in range(100):
        # setup done by server
        key = os.urandom(16)
        lfsr = random.randrange(0, 2**127)
        ciper_a = AES(key)
        ciper_s = SAES(key, lfsr)

        # === 1. gather ciphertexts
        # generate ciphertexts with different inputs
        pt = bytearray(16)
        cta = [] # AES
        cts = [] # SAES
        do_next = False
        for i in range(10):
            pt[0]=i
            blocka = ciper_a.encrypt_block(pt)
            blocks = ciper_s.encrypt_block(pt)
            for a, s in zip(blocka, blocks):
                if a == s:
                    # there is a zero diff,
                    # it might work but can also fail
                    # try with other values
                    do_next = True
                    break
            if do_next:
                break
            cta.append(blocka)
            cts.append(blocks)
        if do_next:
            continue

        recovered_key, recovered_lfsr = recover_key(cta, cts)

        #last_round_key = ciper_a._expand_key(key)[-1]
        #last_round_key = sum([list(x) for x in last_round_key], [])
        #print("Key:", last_round_key)
        print("Key:", key)
        print("Recovered Key:", recovered_key)
        assert recovered_key == key
        assert recovered_lfsr == lfsr

def get_io():
    if args.LOCAL:
        return process("../deploy/chall.py", cwd="../deploy/")
    return remote(args.HOST, args.PORT)

def test(local=True):
    cta = cts = None
    while cta is None:
        io = get_io()
        cta, cts = get_ciphertexts(io)
        if cta is None:
            io.close()

    recovered_key, recovered_lfsr = recover_key(cta, cts)
    io.sendlineafter(b"Key? ", recovered_key.hex().encode())
    io.sendlineafter(b"Sauce? ", str(recovered_lfsr).encode())
    io.stream()

if __name__ == '__main__':
    test()
