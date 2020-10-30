from typing import Dict, List

import hashlib
import json


def int_to_bytes(num: int) -> bytes:
    if num < 0xfd:
        return num.to_bytes(1, "little")
    if num <= 0xffff:
        hed = 0xfd
        return hed.to_bytes(1, "little") + num.to_bytes(2, "little")
    if num <= 0xffffffff:
        hed = 0xfe
        return hed.to_bytes(1, "little") + num.to_bytes(4, "little")
    hed = 0xff
    return hed.to_bytes(1, "little") + num.to_bytes(8, "little")


def bits_to_target(bits: int) -> int:
    bitsN = (bits >> 24) & 0xff
    if not (0x03 <= bitsN <= 0x1f):
        raise Exception("First part of bits should be in [0x03, 0x1f]")
    bitsBase = bits & 0xffffff
    if not (0x8000 <= bitsBase <= 0x7fffff):
        raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
    return bitsBase << (8 * (bitsN-3))


def target_to_bits(target: int) -> int:
    c = ("%064x" % target)[2:]
    while c[:2] == '00' and len(c) > 6:
        c = c[2:]
    bitsN, bitsBase = len(c) // 2, int.from_bytes(bytes.fromhex(c[:6]), byteorder='big')
    if bitsBase >= 0x800000:
        bitsN += 1
        bitsBase >>= 8
    return bitsN << 24 | bitsBase


def made_merkle_root(txs: List[bytes]) -> bytes:
    result = []
    one = txs[0]
    for tx in txs[1:]:
        if one is not None:
            result.append(sha256d(one + tx))
            one = None
        else:
            one = tx

    if one is not None:
        if result:
            result.append(sha256d(one + one))
        else:
            result.append(one)

    if len(result) >= 2:
        return made_merkle_root(result)
    else:
        return result[0]


def sha256(x: bytes) -> bytes:
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: bytes) -> bytes:
    return bytes(sha256(sha256(x)))
