"""Small PE post-processor: stamp a plausible timestamp and valid checksum."""

from __future__ import annotations

import struct
import time


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def _pe_offsets(data: bytes) -> tuple[int, int, int]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    nt = _u32(data, 0x3C)
    if nt + 24 > len(data) or data[nt : nt + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    optional = nt + 24
    if optional + 68 > len(data):
        raise ValueError("truncated optional header")
    return nt, optional, optional + 64


def pe_checksum(data: bytes, checksum_offset: int) -> int:
    total = 0
    length = len(data)
    padded = data if length % 2 == 0 else data + b"\0"
    for offset in range(0, len(padded), 2):
        if checksum_offset <= offset < checksum_offset + 4:
            word = 0
        else:
            word = _u16(padded, offset)
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total += length
    return total & 0xFFFFFFFF


def fix_pe(path: str, timestamp: int | None = None) -> None:
    data = bytearray(open(path, "rb").read())
    nt, _, checksum_offset = _pe_offsets(data)
    _put_u32(data, nt + 8, int(time.time()) if timestamp is None else timestamp)
    _put_u32(data, checksum_offset, 0)
    checksum = pe_checksum(bytes(data), checksum_offset)
    _put_u32(data, checksum_offset, checksum)
    with open(path, "wb") as handle:
        handle.write(data)
