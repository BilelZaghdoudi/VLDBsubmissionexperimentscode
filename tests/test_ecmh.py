"""
ECMH checks: RFC 9380 test vectors (Appendices J.1.1 and K.1), order
independence, incremental update and removal.
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ecmh  # noqa: E402

RFC_DST = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
RFC_VECTORS = [
    (b"",
     "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
     "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"),
    (b"abc",
     "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
     "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"),
    (b"abcdef0123456789",
     "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
     "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"),
]


def test_expand_message_xmd_rfc_vectors():
    dst = b"QUUX-V01-CS02-with-expander-SHA256-128"
    assert ecmh.expand_message_xmd(b"", dst, 0x20).hex() == \
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
    assert ecmh.expand_message_xmd(b"abc", dst, 0x20).hex() == \
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"


def test_hash_to_field_rfc_vectors():
    u0, u1 = ecmh.hash_to_field(b"", 2, RFC_DST)
    assert f"{u0:064x}" == "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009"
    assert f"{u1:064x}" == "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a"


def test_hash_to_curve_rfc_vectors():
    for msg, px, py in RFC_VECTORS:
        x, y = ecmh.hash_to_curve(msg, RFC_DST)
        assert (f"{x:064x}", f"{y:064x}") == (px, py), msg


def test_ecmh_order_independent():
    elems = [f"node-{i}".encode() for i in range(40)]
    shuffled = elems[:]
    random.Random(3).shuffle(shuffled)
    assert ecmh.ECMH(elems).digest() == ecmh.ECMH(shuffled).digest()


def test_ecmh_incremental_and_remove():
    elems = [f"node-{i}".encode() for i in range(20)]
    acc = ecmh.ECMH(elems[:-1])
    acc.add(elems[-1])
    assert acc.digest() == ecmh.ECMH(elems).digest()
    assert ecmh.is_on_curve(acc.point)
    acc.remove(elems[-1])
    assert acc.digest() == ecmh.ECMH(elems[:-1]).digest()


def test_ecmh_sensitive_to_change():
    elems = [f"node-{i}".encode() for i in range(20)]
    changed = elems[:5] + [b"tampered"] + elems[6:]
    assert ecmh.ECMH(elems).digest() != ecmh.ECMH(changed).digest()
    assert ecmh.ECMH([]).digest() == b"\x00"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
