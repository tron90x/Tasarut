"""Independent Tasarut vectors, without importing tasarut-core.

Reference primitives: libargon2, libsodium (XChaCha20), libgcrypt (Serpent CTR),
Python hashlib (BLAKE2b) and hmac/hashlib (HMAC-SHA3-512).
Requires these system libraries, not pip packages. Output is deterministic test data.
"""

import ctypes as c
import ctypes.util
import hashlib
import hmac
import struct


def load(name):
    path = ctypes.util.find_library(name)
    if not path:
        raise RuntimeError(f"Missing reference library: {name}")
    return c.CDLL(path)


def checked(result):
    if result != 0:
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
gcrypt = load("gcrypt")
gcrypt.gcry_check_version.argtypes = [c.c_char_p]
gcrypt.gcry_check_version.restype = c.c_char_p
if not gcrypt.gcry_check_version(None):
    raise RuntimeError("libgcrypt initialization failed")
gcrypt.gcry_cipher_map_name.argtypes = [c.c_char_p]
gcrypt.gcry_cipher_map_name.restype = c.c_int
gcrypt.gcry_cipher_open.argtypes = [c.POINTER(c.c_void_p), c.c_int, c.c_int, c.c_uint]
gcrypt.gcry_cipher_setkey.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
gcrypt.gcry_cipher_setctr.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
gcrypt.gcry_cipher_encrypt.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t]
gcrypt.gcry_cipher_close.argtypes = [c.c_void_p]

password = b"Tasarut reference password"
plaintext = b"Individual file encryption\x00\x01\x02\xff\nAzul!"
comment = "Azul — public".encode()
salt = bytes(range(32))
nonce = bytes(range(32, 56))
iv = bytes(range(56, 64)) + bytes(8)
keyfiles = [b"first keyfile", b"second keyfile"]


def vector(paranoid):
    domain = b"Tasarut/v2/paranoid/password+keyfiles" if paranoid else b"Tasarut/v1/password+keyfiles"
    selected = keyfiles if paranoid else []
    material = domain + struct.pack("<Q", len(password)) + password + struct.pack("<Q", len(selected))
    for keyfile in selected:
        material += struct.pack("<Q", len(keyfile)) + keyfile
    material = hashlib.blake2b(material).digest()
    keys = c.create_string_buffer(128 if paranoid else 64)
    checked(argon.argon2id_hash_raw(6 if paranoid else 3, 262144 if paranoid else 65536, 4,
                                 material, len(material), salt, len(salt), keys, len(keys)))
    keys = keys.raw
    ciphertext = c.create_string_buffer(len(plaintext))
    checked(sodium.crypto_stream_xchacha20_xor(ciphertext, plaintext, len(plaintext), nonce, keys[:32]))
    header = b"TASARUT" + bytes([2 if paranoid else 1])
    if paranoid:
        header += b"\x01"  # suite ID
    header += b"\x00" + salt + nonce
    if paranoid:
        header += iv
        handle = c.c_void_p()
        algorithm = gcrypt.gcry_cipher_map_name(b"SERPENT256")
        if not algorithm:
            raise RuntimeError("Serpent-256 unavailable in libgcrypt")
        checked(gcrypt.gcry_cipher_open(c.byref(handle), algorithm, 6, 0))  # GCRY_CIPHER_MODE_CTR
        try:
            checked(gcrypt.gcry_cipher_setkey(handle, keys[32:64], 32))
            checked(gcrypt.gcry_cipher_setctr(handle, iv, 16))
            checked(gcrypt.gcry_cipher_encrypt(handle, ciphertext, len(plaintext), None, 0))
        finally:
            gcrypt.gcry_cipher_close(handle)
    header += struct.pack("<Q", len(plaintext))
    message = header + ciphertext.raw
    tag = hmac.new(keys[64:], message, hashlib.sha3_512).digest() if paranoid else hashlib.blake2b(message, key=keys[32:]).digest()
    return header + struct.pack("<I", len(comment)) + comment + ciphertext.raw + tag


for paranoid in (False, True):
    print(f"{'v2-paranoid' if paranoid else 'v1-standard'}: {vector(paranoid).hex()}")
