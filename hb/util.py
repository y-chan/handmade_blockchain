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
