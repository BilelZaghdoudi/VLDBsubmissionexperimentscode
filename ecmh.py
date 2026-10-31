"""
ecmh.py

Elliptic Curve Multiset Hash (ECMH) over NIST P-256, used for level hashing
(Section 3 of the paper).

  * hash-to-curve follows RFC 9380, suite P256_XMD:SHA-256_SSWU_RO_
    (expand_message_xmd + simplified SWU map, cofactor 1);
  * the multiset hash of a set S is the sum of the curve points of its
    elements, so it is order-independent and supports O(1) incremental
    updates: H(S + {v}) = H(S) (+) phi(v).

Pure Python, no dependency beyond hashlib.
"""
import hashlib
from typing import Iterable, Optional, Tuple

# NIST P-256 (secp256r1)
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# RFC 9380, Section 8.2: P256_XMD:SHA-256_SSWU_RO_
Z = P - 10
L = 48
SQRT_EXP = (P + 1) // 4  # P = 3 mod 4

DEFAULT_DST = b"VERDICT-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_"

Point = Optional[Tuple[int, int]]  # None is the point at infinity (identity)


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """RFC 9380, Section 5.3.1 with H = SHA-256."""
    b_in_bytes, s_in_bytes = 32, 64
    ell = -(-len_in_bytes // b_in_bytes)
    if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd: invalid lengths")
    dst_prime = dst + bytes([len(dst)])
    msg_prime = bytes(s_in_bytes) + msg + len_in_bytes.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = hashlib.sha256(msg_prime).digest()
    bi = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    out = [bi]
    for i in range(2, ell + 1):
        bi = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, bi)) + bytes([i]) + dst_prime).digest()
        out.append(bi)
    return b"".join(out)[:len_in_bytes]


def hash_to_field(msg: bytes, count: int, dst: bytes):
    uniform = expand_message_xmd(msg, dst, count * L)
    return [int.from_bytes(uniform[L * i:L * (i + 1)], "big") % P for i in range(count)]


def _inv(x: int) -> int:
    return pow(x, -1, P)


def map_to_curve_sswu(u: int) -> Tuple[int, int]:
    """Simplified SWU map for P-256 (RFC 9380, Section 6.6.2)."""
    zu2 = Z * u * u % P
    tv1 = (zu2 * zu2 + zu2) % P
    if tv1 == 0:
        x1 = B * _inv(Z * A % P) % P
    else:
        x1 = (P - B) * _inv(A) % P * (1 + _inv(tv1)) % P
    gx1 = (x1 * x1 * x1 + A * x1 + B) % P
    y1 = pow(gx1, SQRT_EXP, P)
    if y1 * y1 % P == gx1:
        x, y = x1, y1
    else:
        x = zu2 * x1 % P
        gx2 = (x * x * x + A * x + B) % P
        y = pow(gx2, SQRT_EXP, P)
    if (u & 1) != (y & 1):
        y = P - y
    return x, y


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def point_neg(p: Point) -> Point:
    return None if p is None else (p[0], (P - p[1]) % P)


def is_on_curve(p: Point) -> bool:
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + A * x + B)) % P == 0


def hash_to_curve(msg: bytes, dst: bytes = DEFAULT_DST) -> Tuple[int, int]:
    """RFC 9380 hash_to_curve for P256_XMD:SHA-256_SSWU_RO_."""
    u0, u1 = hash_to_field(msg, 2, dst)
    return point_add(map_to_curve_sswu(u0), map_to_curve_sswu(u1))


def encode_point(p: Point) -> bytes:
    """SEC1 compressed encoding; the identity is encoded as a single zero byte."""
    if p is None:
        return b"\x00"
    x, y = p
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


class ECMH:
    """Elliptic Curve Multiset Hash: H(S) = sum of hash_to_curve(s) for s in S."""

    __slots__ = ("point",)

    def __init__(self, elements: Iterable[bytes] = ()):
        self.point: Point = None
        for e in elements:
            self.add(e)

    def add(self, element: bytes) -> "ECMH":
        self.point = point_add(self.point, hash_to_curve(element))
        return self

    def remove(self, element: bytes) -> "ECMH":
        self.point = point_add(self.point, point_neg(hash_to_curve(element)))
        return self

    def digest(self) -> bytes:
        return encode_point(self.point)
