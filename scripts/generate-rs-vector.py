"""Independent systematic RS(136,128) encoder vector; no Rust or external modules."""


def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
    return result


generator = [1]
root = 1
for _ in range(8):
    result = [0] * (len(generator) + 1)
    for i, coefficient in enumerate(generator):
        result[i] ^= coefficient
        result[i + 1] ^= mul(coefficient, root)
    generator = result
    root = mul(root, 2)

data = bytes(range(128))
remainder = list(data) + [0] * 8
for i in range(128):
    coefficient = remainder[i]
    for j, g in enumerate(generator):
        remainder[i + j] ^= mul(coefficient, g)
print((data + bytes(remainder[-8:])).hex())
