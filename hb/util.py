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


def load_and_dump_json(file_name: str, content: Dict) -> None:
    with open(f"../blockchain_data/{file_name}") as f:
        file: List[Dict] = json.loads(f.read())
    file.append(content)
    with open(f"../blockchain_data/{file_name}", "w") as f:
        f.write(json.dumps(file))


def dump_block(block: Dict) -> None:
    load_and_dump_json("blockchain", block)


def dump_tx(tx: Dict) -> None:
    load_and_dump_json("tx", tx)


def sha256(x: bytes) -> bytes:
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: bytes) -> bytes:
    return bytes(sha256(sha256(x)))
