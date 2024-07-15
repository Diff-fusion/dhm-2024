import array
import struct
from base64 import b64encode
from z3 import *

from finite import gen_block, add_blocks


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


enc_data = open("../public/finite_old_encrypted.gen", "rb").read()
dec_data = open("../public/finite_old_decrypted.gen", "rb").read()

enc_type, enc_digest, IV, enc_content = load_file_header(enc_data)
assert enc_type == 2
dec_type, dec_digest, _, dec_content = load_file_header(dec_data)
assert dec_type == 0

# convert bytes to u16 list
enc_data = memoryview(enc_content).cast("H").tolist()
dec_data = memoryview(dec_content).cast("H").tolist()
IV = memoryview(IV).cast("H").tolist()

# recover key stream
stream = [y - x for x, y in zip(enc_data, dec_data[:8])]

# run gen block with symbolic key
key = [BitVec(f"key_{i}", 16) for i in range(8)]
gen_block(IV, key.copy())
# key stream is iv after gen_block
sym_stream = IV

s = Solver()

# set constraints on key stream
for i in range(8):
    s.add(sym_stream[i] == stream[i])

# solver for key
if s.check() == sat:
    model = s.model()
    recovered_key = []
    for k in key:
        recovered_key.append(model[k].as_long())
else:
    print("Z3 is unsat")
    exit()

# key can be used in website
print("Key:", b64encode(array.array("H", recovered_key).tobytes()).decode())

# also decrypte content
data = open("../public/finite.gen", "rb").read()
type, digest, IV, content = load_file_header(data)
assert type == 2
content = memoryview(content).cast("H").tolist()
iv = memoryview(IV).cast("H").tolist()
key = recovered_key.copy()

for i in range(0, len(content), 8):
    gen_block(iv, key)
    add_blocks(content, iv, i)

content = array.array("H", content).tobytes()

print(load_generator_header(content))
