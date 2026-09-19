"""RFC 1320 MD4 (used for ED2K file hashes of small fixtures).

stdlib hashlib.md4 is not always present (OpenSSL 3). This copy is only for
harmless generated interop fixtures, not for production protocol code.
"""

from __future__ import annotations

import struct
from typing import Union


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | ((~x) & z)


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def _rotl(v: int, n: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def md4(data: Union[bytes, bytearray]) -> bytes:
    message = bytes(data)
    orig_len_bits = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    message += b"\x80"
    while (len(message) % 64) != 56:
        message += b"\x00"
    message += struct.pack("<Q", orig_len_bits)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for offset in range(0, len(message), 64):
        x = list(struct.unpack("<16I", message[offset : offset + 64]))
        a, b, c, d = a0, b0, c0, d0

        s1 = (3, 7, 11, 19)
        for i in range(16):
            k = i
            a, b, c, d = d, _rotl(a + _f(b, c, d) + x[k], s1[i % 4]), b, c

        s2 = (3, 5, 9, 13)
        idx2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for i in range(16):
            a, b, c, d = (
                d,
                _rotl((a + _g(b, c, d) + x[idx2[i]] + 0x5A827999) & 0xFFFFFFFF, s2[i % 4]),
                b,
                c,
            )

        s3 = (3, 9, 11, 15)
        idx3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in range(16):
            a, b, c, d = (
                d,
                _rotl((a + _h(b, c, d) + x[idx3[i]] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[i % 4]),
                b,
                c,
            )

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def md4_hex(data: Union[bytes, bytearray]) -> str:
    return md4(data).hex()
