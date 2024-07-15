#!/usr/bin/env python3
from aes import AES
from saes import SAES
import secrets

key = secrets.token_bytes(16)
sauce = secrets.randbits(127)
ciper_aes = AES(key)
ciper_secure_aes = SAES(key, sauce)

plaintext = bytes.fromhex(input("Give something to encrypt in hex> "))

if len(plaintext) > 128:
    exit("This is too much")

plaintext += b"\x00" * (-len(plaintext) % 16)
plaintext_blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

aes_blocks = [ciper_aes.encrypt_block(block) for block in plaintext_blocks]
secure_aes_blocks = [ciper_secure_aes.encrypt_block(block) for block in plaintext_blocks]

print("Here is your insecurely encrypted data:", b"".join(aes_blocks).hex())
print("Here is your securely encrypted data:", b"".join(secure_aes_blocks).hex())
print("See how much more secure it is!")

print("If you tell me the key and sauce I'll give you a nice Flag")

key_guess = bytes.fromhex(input("Key? "))
sauce_guess = int(input("Sauce? "))

match [key_guess == key, sauce_guess == sauce]:
    case [True, True]:
        print(open("flag.txt").read())
    case [True, False]:
        print("Key guess is correct, but you have the wrong sauce")
    case [False, True]:
        print("That's the right sauce, but your key is wrong")
    case [False, False]:
        print("Not correct")
