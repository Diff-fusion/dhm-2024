import os
import struct
from enum import Enum
from Crypto.Hash import SHA256
from pathlib import Path
from base64 import b64encode
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO

from extended import encrypt_extended
from finite import encrypt_finite
from riscy import encrypt_riscy


DIR = Path(os.path.dirname(os.path.realpath(__file__)))


class ENC_TYPE(Enum):
    UNENCRYPTED = 0
    EXTENDED = 1
    FINITE = 2
    RISCY = 3


def gen_file_header(type: int, digest: bytes, IV: bytes, content: bytes) -> bytes:
    assert len(IV) == 16
    assert len(digest) == 32
    data = struct.pack("<ii", 0x454C4946, type)
    data += digest + IV + content
    return data


GENERATOR_HEADER_LEN = 4 + 20 + 100


def gen_generator_header(name: str, description: str, content: str) -> bytes:
    data = struct.pack("<i", 0x54524E47)  # magic
    name = name.encode().ljust(20)[:20]
    description = description.encode().ljust(100)[:100]
    data += name + description
    data += content.encode()
    return data


def gen_generator(
    type: ENC_TYPE, name: str, description: str, content: str, key: bytes, iv: bytes, path: str, file: str
):
    assert len(key) == 16
    assert len(iv) == 16
    # align to 16 bytes
    content += " " * ((-((GENERATOR_HEADER_LEN + len(content)) % 16)) % 16)

    generator = gen_generator_header(name, description, content)
    assert len(generator) <= 4096, f"content is to long ({len(generator)})"
    match type:
        case ENC_TYPE.UNENCRYPTED:
            pass
        case ENC_TYPE.EXTENDED:
            generator = encrypt_extended(key, iv, generator)
        case ENC_TYPE.FINITE:
            generator = encrypt_finite(key, iv, generator)
        case ENC_TYPE.RISCY:
            generator = encrypt_riscy(key, iv, generator)
    file_content = gen_file_header(type.value, SHA256.new(content.encode()).digest(), iv, generator)
    open(DIR.joinpath(path, file), "wb").write(file_content)


KEY1 = bytes.fromhex("2d2441d3d116771923c0516b9f32d2ed")  # LSRB09EWdxkjwFFrnzLS7Q==
KEY2 = bytes.fromhex("1df399efc5d97ee60af29be911f29ef4")  # HfOZ78XZfuYK8pvpEfKe9A==
KEY3 = bytes.fromhex("138d00a70cd22c0067d6c9c531ab4718")  # E40ApwzSLABn1snFMatHGA==
IV1 = bytes.fromhex("1ad922963961448c7343a9953b9c93ca")
IV2 = bytes.fromhex("05f20560d2b40553ec0904f49b649257")
IV3 = bytes.fromhex("3f088eb7628ed109414d6603df525a22")
IV4 = bytes.fromhex("3ca24adb113640d8c8c4c4a2481df843")
IV5 = bytes.fromhex("e916f65a907140ca60c920fcc3b39525")
IV6 = bytes.fromhex("e0c4a88f1e3926f67ca8f120caf9585f")
FLAG1 = "DHM{Great you understand Xtensa, now go on and do the other challenges}"
FLAG2 = "DHM{dawg_i_heard_you_like_cpus_so_i_put_some_cpus_in_your_cpu_so_you_can_compute_while_you_compute}"
FLAG3 = "DHM{Xtensa_ULP_RISC-V_y0u_h4v3_1t_4LL}"

extended_base = {
    "name": "Extended generator",
    "description": "This is a basic generator that generates <b>secure</b> flags<br>Version: 1.1",
    "content": "return 'flag{this is a fake flag}';",
    "path": "../../public",
    "key": KEY1,
    "iv": IV1,
}

finite_base = {
    "name": "Finite generator",
    "description": "This is an advanced generator that generates <b>very secure</b> flags<br>Version: 1.1",
    "content": "return 'flag{this is another fake flag}';",
    "path": "../../../flag-generator-finite/public",
    "key": KEY2,
    "iv": IV3,
}

# iv needs special format
tmp = memoryview(bytearray(IV5)).cast("I")
# must be odd
tmp[0] |= 1
tmp[1] |= 1
tmp[2] |= 1
# must be even
tmp[3] &= ~1
# and divisible by 2 only once
tmp[3] |= 2
IV5 = tmp.tobytes()

# generate image for fake flag
fake_image = Image.new("RGB", (400, 100))
draw = ImageDraw.Draw(fake_image)
draw.text((20, 20), "flag{There is no flag here}", font_size=20)
fake_image_data = BytesIO()
fake_image.save(fake_image_data, "png", optimize=True)

logo_size = (30, 30)
# white backgound
logo = Image.new("RGBA", logo_size, color="white")
# put DHM logo on background
logo.alpha_composite(Image.open("../challenge/main/www/favicon.ico").resize(logo_size))
# remove alpha
logo = logo.convert("RGB")

font = ImageFont.truetype("/usr/share/fonts/OTF/ComicShannsMonoNerdFontMono-Regular.otf", size=11.4)

# create image with real flag
real_image = Image.new("RGB", (300, 50), color="white")
# add logo
real_image.paste(logo, (10, 10))
# add flag
draw = ImageDraw.Draw(real_image)
draw.text((60, 10), FLAG3, fill="black", font=font)

real_image_data = BytesIO()
real_image.save(real_image_data, "jpeg", optimize=True)

riscy_base = {
    "name": "Riscy generator",
    "description": "This is a generator that generates flags for the most <b>riscy</b> of people<br>Version: 1.1",
    "content": f"return '<img src=\"data:image/jpeg;base64, {b64encode(fake_image_data.getbuffer()).decode()}\"/>';",
    "path": "../../../flag-generator-riscy/public",
    "key": KEY3,
    "iv": IV5,
}

generators = [
    {
        **extended_base,
        "type": ENC_TYPE.UNENCRYPTED,
        "file": "extended_old_decrypted.gen",
    },
    {
        **extended_base,
        "type": ENC_TYPE.EXTENDED,
        "file": "extended_old_encrypted.gen",
    },
    {
        **extended_base,
        "description": "This is a basic generator that generates <b>secure</b> flags<br>Version: 1.2",
        "content": f"return atob('{b64encode(FLAG1.encode()).decode()}');",
        "type": ENC_TYPE.EXTENDED,
        "file": "extended.gen",
        "iv": IV2,
    },
    {
        **finite_base,
        "type": ENC_TYPE.UNENCRYPTED,
        "file": "finite_old_decrypted.gen",
    },
    {
        **finite_base,
        "type": ENC_TYPE.FINITE,
        "file": "finite_old_encrypted.gen",
    },
    {
        **finite_base,
        "description": "This is an advanced generator that generates <b>very secure</b> flags<br>Version: 1.2",
        "content": f"return atob('{b64encode(FLAG2.encode()).decode()}');",
        "type": ENC_TYPE.FINITE,
        "file": "finite.gen",
        "iv": IV4,
    },
    {
        **riscy_base,
        "type": ENC_TYPE.UNENCRYPTED,
        "file": "riscy_old_decrypted.gen",
    },
    {
        **riscy_base,
        "type": ENC_TYPE.RISCY,
        "file": "riscy_old_encrypted.gen",
    },
    {
        **riscy_base,
        "description": "This is a generator that generates flags for the most <b>riscy</b> of people<br>Version: 1.2",
        "content": f"return '<img src=\"data:image/png;base64, {b64encode(real_image_data.getbuffer()).decode()}\"/>';",
        "type": ENC_TYPE.RISCY,
        "file": "riscy.gen",
        "iv": IV6,
    },
]

for generator in generators:
    gen_generator(**generator)

print("Key1:", b64encode(KEY1))
print("Key2:", b64encode(KEY2))
print("Key3:", b64encode(KEY3))
