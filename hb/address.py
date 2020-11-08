from typing import Tuple, Optional

from .util import sha256d
from .script import Opcodes


__b58chars = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
assert len(__b58chars) == 58


def base58_decode(v: bytes, length: int = None) -> Optional[bytes]:
    """decode v into a string of len bytes."""
    chars = __b58chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        digit = chars.find(bytes([c]))
        if digit == -1:
            raise ValueError("Forbidden character {}".format(c))
        long_value += digit * (58 ** i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    n_pad = 0
    for c in v:
        if c == chars[0]:
            n_pad += 1
        else:
            break
    result.extend(b"\x00" * n_pad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)


def base_encode(v: bytes) -> str:
    chars = __b58chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * c
    result = bytearray()
    while long_value >= 58:
        div, mod = divmod(long_value, 58)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    n_pad = 0
    for c in v:
        if c == 0x00:
            n_pad += 1
        else:
            break
    result.extend([chars[0]] * n_pad)
    result.reverse()
    return result.decode("ascii")


def b58_address_to_hash160(addr: str) -> Tuple[int, bytes]:
    addr = addr.encode('ascii')
    _bytes = base58_decode(addr, 25)
    if len(_bytes) != 21:
        raise Exception(f'expected 21 payload bytes in base58 address. got: {len(_bytes)}')
    return _bytes[0], _bytes[1:21]


def hash160_to_b58_address(h160: bytes) -> str:
    s = bytes([0]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s)


def address_to_script(addr: str) -> bytes:
    script = bytes([Opcodes.OP_DUP, Opcodes.OP_HASH160])
    script += b58_address_to_hash160(addr)[1]
    script += bytes([Opcodes.OP_EQUALVERIFY, Opcodes.OP_CHECKSIG])
    return script


def script_to_address(script: bytes) -> str:
    if (
            (script_hex := script.hex()).startswith(bytes([Opcodes.OP_DUP, Opcodes.OP_HASH160]).hex()) and
            script_hex.endswith(bytes([Opcodes.OP_EQUALVERIFY, Opcodes.OP_CHECKSIG]).hex())
    ):
        return hash160_to_b58_address(script[2:-2])
    raise Exception("入力値はP2PKHアドレスではない")
