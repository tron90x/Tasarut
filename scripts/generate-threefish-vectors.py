"""Independent v5/v4-Threefish vectors, with no Rust or application imports.

Threefish-1024 is implemented directly from Skein 1.3's specification using
Python integer arithmetic. Two published KATs validate the reference primitive:
https://github.com/weidai11/cryptopp/blob/master/TestVectors/threefish.txt
Argon2id uses system libargon2; BLAKE2b and HMAC-SHA3 use hashlib/hmac.
All inputs in this script are public test data, not operational secrets.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import hmac
import struct
import textwrap

MASK = (1 << 64) - 1
ROTATIONS = (
    (24, 13, 8, 47, 8, 17, 22, 37),
    (38, 19, 10, 55, 49, 18, 23, 52),
    (33, 4, 51, 13, 34, 41, 59, 17),
    (5, 20, 48, 41, 47, 28, 16, 25),
    (41, 9, 37, 31, 12, 47, 44, 30),
    (16, 34, 56, 51, 4, 53, 42, 41),
    (31, 44, 47, 46, 19, 42, 44, 25),
    (9, 48, 35, 52, 23, 31, 37, 20),
)
PERMUTATION = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)


def threefish_block(key, tweak, block):
    words = list(struct.unpack("<16Q", key))
    parity = 0x1BD11BDAA9FC1A22
    for word in words:
        parity ^= word
    words.append(parity)
    t0, t1 = struct.unpack("<2Q", tweak)
    tweaks = (t0, t1, t0 ^ t1)
    state = list(struct.unpack("<16Q", block))

    def inject(index):
        for i in range(16):
            state[i] = (state[i] + words[(index + i) % 17]) & MASK
        state[13] = (state[13] + tweaks[index % 3]) & MASK
        state[14] = (state[14] + tweaks[(index + 1) % 3]) & MASK
        state[15] = (state[15] + index) & MASK

    for round_number in range(80):
        if round_number % 4 == 0:
            inject(round_number // 4)
        mixed = []
        for pair, rotation in enumerate(ROTATIONS[round_number % 8]):
            a, b = state[2 * pair:2 * pair + 2]
            a = (a + b) & MASK
            b = ((b << rotation) | (b >> (64 - rotation))) & MASK
            mixed.extend((a, b ^ a))
        state = [mixed[i] for i in PERMUTATION]
    inject(20)
    return struct.pack("<16Q", *state)


ZERO_KAT = """F05C3D0A3D05B304F785DDC7D1E036015C8AA76E2F217B06C6E1544C0BC1A90D
F0ACCB9473C24E0FD54FEA68057F43329CB454761D6DF5CF7B2E9B3614FBD5A2
0B2E4760B40603540D82EABC5482C171C832AFBE68406BC39500367A592943FA
9A5B4A43286CA3C4CF46104B443143D560A4B230488311DF4FEEF7E1DFE8391E"""
TWEAK_KAT = """A6654DDBD73CC3B05DD777105AA849BCE49372EAAFFC5568D254771BAB85531C
94F780E7FFAAE430D5D8AF8C70EEBBE1760F3B42B737A89CB363490D670314BD
8AA41EE63C2E1F45FBD477922F8360B388D6125EA6C7AF0AD7056D01796E90C8
3313F4150A5716B30ED5F569288AE974CE2B4347926FCE57DE44512177DD7CDE"""
assert threefish_block(bytes(128), bytes(16), bytes(128)) == bytes.fromhex(ZERO_KAT)
assert threefish_block(bytes(range(16, 144)), bytes(range(16)), bytes(range(255, 127, -1))) == bytes.fromhex(TWEAK_KAT)


def argon(material, salt, length):
    library = ctypes.CDLL(ctypes.util.find_library("argon2"))
    library.argon2id_hash_raw.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                                        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    output = ctypes.create_string_buffer(length)
    code = library.argon2id_hash_raw(6, 262144, 4, material, len(material), salt, len(salt), output, length)
    if code:
        raise RuntimeError(f"libargon2 returned {code}")
    return output.raw


def prehash(domain, password, keyfiles):
    value = domain + struct.pack("<Q", len(password)) + password + struct.pack("<Q", len(keyfiles))
    for keyfile in keyfiles:
        value += struct.pack("<Q", len(keyfile)) + keyfile
    return hashlib.blake2b(value).digest()


def ctr(plaintext, key, tweak, nonce):
    ciphertext = bytearray()
    for counter, start in enumerate(range(0, len(plaintext), 128)):
        block = nonce + bytes(88) + counter.to_bytes(16, "big")
        stream = threefish_block(key, tweak, block)
        ciphertext.extend(a ^ b for a, b in zip(plaintext[start:start + 128], stream))
    return bytes(ciphertext)


def vector(revocable):
    password = b"Tasarut Threefish reference password"
    keyfiles = [b"first Threefish keyfile", b"second Threefish keyfile"]
    plaintext = bytes(range(256)) * 2 + b"Azul!"
    salt, nonce, tweak = bytes(range(32, 64)), bytes(range(64, 88)), bytes(range(88, 104))
    if revocable:
        identifier, secret, index = bytes(range(32)), bytes(range(128, 160)), 0x015A002A
        auth = argon(prehash(b"Tasarut/v4/TPM-auth/password+keyfiles", password, keyfiles), salt, 64)
        keys = b"".join(hashlib.blake2b(b"Tasarut/v4/payload-keys\0" + bytes([3, i]) + auth
                                     + secret + identifier + struct.pack("<I", index)).digest() for i in range(3))
        header = b"TASARUT\x04\x03\x00" + identifier + struct.pack("<I", index) + salt + nonce + tweak + struct.pack("<Q", len(plaintext))
        serialized = header
    else:
        keys = argon(prehash(b"Tasarut/v5/threefish1024/password+keyfiles", password, keyfiles), salt, 192)
        header = b"TASARUT\x05\x01\x00" + salt + nonce + tweak + struct.pack("<Q", len(plaintext))
        comment = b"public Threefish reference"
        serialized = header + struct.pack("<I", len(comment)) + comment
    ciphertext = ctr(plaintext, keys[:128], tweak, nonce)
    return serialized + ciphertext + hmac.new(keys[128:192], header + ciphertext, hashlib.sha3_512).digest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("format", choices=["v5", "v4"])
    args = parser.parse_args()
    print("\n".join(textwrap.wrap(vector(args.format == "v4").hex(), 64)))
