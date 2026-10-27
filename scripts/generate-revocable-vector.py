"""Independent v4 vector: libargon2, libsodium and Python hashlib, no TPM."""
import ctypes as c
import ctypes.util
import hashlib
import struct


def load(name):
    path = ctypes.util.find_library(name)
    if not path:
        raise RuntimeError(f"Missing reference library: {name}")
    return c.CDLL(path)


def checked(code):
    if code:
        raise RuntimeError(f"Reference primitive error: {code}")


argon = load("argon2")
argon.argon2id_hash_raw.argtypes = [c.c_uint32, c.c_uint32, c.c_uint32,
                                 c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
                                 c.c_void_p, c.c_size_t]
sodium = load("sodium")
sodium.crypto_stream_xchacha20_xor.argtypes = [c.c_void_p, c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_void_p]
checked(sodium.sodium_init())
password = b"Tasarut revocable reference password"
keyfile = b"revocable reference keyfile"
plaintext = b"Revocable file encryption\x00\x01\x02\xff\nAzul!"
identifier = bytes(range(32))
index = 0x015A002A
salt = bytes(range(32, 64))
nonce = bytes(range(64, 88))
iv = bytes(range(88, 96)) + bytes(8)
secret = bytes(range(128, 160))
material = b"Tasarut/v4/TPM-auth/password+keyfiles"
material += struct.pack("<Q", len(password)) + password + struct.pack("<Q", 1)
material += struct.pack("<Q", len(keyfile)) + keyfile
material = hashlib.blake2b(material).digest()
auth = c.create_string_buffer(64)
checked(argon.argon2id_hash_raw(6, 262144, 4, material, len(material), salt, len(salt), auth, 64))
keys = hashlib.blake2b(b"Tasarut/v4/payload-keys\x00" + bytes([1, 0]) + auth.raw + secret + identifier + struct.pack("<I", index)).digest()
header = b"TASARUT\x04" + bytes([1, 0]) + identifier + struct.pack("<I", index) + salt + nonce + iv + struct.pack("<Q", len(plaintext))
ciphertext = c.create_string_buffer(len(plaintext))
checked(sodium.crypto_stream_xchacha20_xor(ciphertext, plaintext, len(plaintext), nonce, keys[:32]))
tag = hashlib.blake2b(header + ciphertext.raw, key=keys[32:]).digest()
print((header + ciphertext.raw + tag).hex())
