"""Independent opaque-envelope vector: libargon2, libsodium and Python hashlib.

Prints deterministic hex for crates/tasarut-core/test-vectors/deniable-v1.hex.
No tasarut-core implementation is imported; no pip dependencies are needed.
"""
import ctypes as c
import ctypes.util
import hashlib
import struct


def load(name):
    path = ctypes.util.find_library(name)
    if not path:
        raise RuntimeError(f"Missing reference library: {name}")
    return c.CDLL(path)


def checked(result):
    if result:
        raise RuntimeError(f"Reference library error: {result}")


argon = load("argon2")
argon.argon2id_hash_raw.argtypes = [c.c_uint32, c.c_uint32, c.c_uint32,
                                 c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
                                 c.c_void_p, c.c_size_t]
argon.argon2id_hash_raw.restype = c.c_int
sodium = load("sodium")
sodium.crypto_stream_xchacha20_xor.argtypes = [c.c_void_p, c.c_void_p, c.c_ulonglong, c.c_void_p, c.c_void_p]
sodium.crypto_stream_xchacha20_xor.restype = c.c_int
checked(sodium.sodium_init())
password = b"Tasarut opaque reference password"
keyfile = b"opaque reference keyfile"
plaintext = b"Opaque file encryption\x00\x01\x02\xff\nAzul!"


def derive(domain, salt, memory, iterations):
    material = domain + struct.pack("<Q", len(password)) + password
    material += struct.pack("<Q", 1) + struct.pack("<Q", len(keyfile)) + keyfile
    material = hashlib.blake2b(material).digest()
    keys = c.create_string_buffer(64)
    checked(argon.argon2id_hash_raw(iterations, memory, 4, material, len(material),
                                  salt, len(salt), keys, 64))
    return keys.raw


def xchacha(data, key, nonce):
    output = c.create_string_buffer(len(data))
    checked(sodium.crypto_stream_xchacha20_xor(output, data, len(data), nonce, key))
    return output.raw


salt, nonce = bytes(range(32)), bytes(range(32, 56))
keys = derive(b"Tasarut/v1/password+keyfiles", salt, 65536, 3)
header = b"TASARUT\x01\x00" + salt + nonce + struct.pack("<Q", len(plaintext))
ciphertext = xchacha(plaintext, keys[:32], nonce)
tag = hashlib.blake2b(header + ciphertext, key=keys[32:]).digest()
inner = header + struct.pack("<I", 0) + ciphertext + tag
salt, nonce = bytes(range(64, 96)), bytes(range(96, 120))
keys = derive(b"Tasarut/deniable/v1/password+keyfiles", salt, 262144, 6)
prefix = salt + nonce
ciphertext = xchacha(inner, keys[:32], nonce)
message = b"Tasarut/deniable/v1/envelope\x00" + prefix + struct.pack("<Q", len(inner)) + ciphertext
tag = hashlib.blake2b(message, key=keys[32:]).digest()
print((prefix + ciphertext + tag).hex())
