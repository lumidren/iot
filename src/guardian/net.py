"""Packet records and small address helpers.

GUARDIAN only looks at packet metadata a gateway can see even when payloads are
encrypted: time, direction, size, protocol, remote address and port, TCP flags.
A window of traffic is a numpy structured array with the ``PACKET`` dtype.
"""

from __future__ import annotations

import ipaddress

import numpy as np

# TCP flag bits (subset).
SYN = 0x01
ACK = 0x02
FIN = 0x04
RST = 0x08

TCP = 6
UDP = 17
ICMP = 1

PACKET = np.dtype(
    [
        ("t", "f8"),  # seconds since simulation/capture start
        ("out", "?"),  # True when the device sent the packet
        ("size", "u2"),  # bytes on the wire
        ("proto", "u1"),  # IP protocol number
        ("peer", "u4"),  # remote IPv4 address as an integer
        ("port", "u2"),  # remote service port
        ("flags", "u1"),  # TCP flags (SYN/ACK/FIN/RST bits above)
    ]
)

EMPTY = np.zeros(0, dtype=PACKET)


def ip(text: str) -> int:
    """Dotted quad -> integer."""
    return int(ipaddress.IPv4Address(text))


def ip_str(value: int) -> str:
    """Integer -> dotted quad."""
    return str(ipaddress.IPv4Address(int(value)))


_PRIVATE = [
    (ip("10.0.0.0"), 8),
    (ip("172.16.0.0"), 12),
    (ip("192.168.0.0"), 16),
    (ip("127.0.0.0"), 8),
    (ip("169.254.0.0"), 16),
    (ip("224.0.0.0"), 4),
]


def is_private(addr: int | np.ndarray) -> bool | np.ndarray:
    """True for RFC 1918, loopback, link-local and multicast addresses."""
    a = np.asarray(addr, dtype=np.uint64)
    result = np.zeros(a.shape, dtype=bool)
    for net, bits in _PRIVATE:
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        result |= (a & mask) == net
    return bool(result) if result.ndim == 0 else result


def prefix24(addr: int | np.ndarray) -> int | np.ndarray:
    """The /24 network an address belongs to."""
    return np.asarray(addr, dtype=np.uint64) & 0xFFFFFF00


def concat(parts: list[np.ndarray]) -> np.ndarray:
    """Concatenate packet arrays and sort them by time."""
    parts = [p for p in parts if len(p)]
    if not parts:
        return EMPTY.copy()
    out = np.concatenate(parts)
    out.sort(order="t", kind="stable")
    return out


def packets(
    times: np.ndarray,
    *,
    out: bool,
    size: np.ndarray | int,
    proto: int,
    peer: int,
    port: int,
    flags: int = 0,
) -> np.ndarray:
    """Build a packet array where every packet shares direction, peer and port."""
    times = np.asarray(times, dtype=np.float64)
    arr = np.zeros(len(times), dtype=PACKET)
    arr["t"] = times
    arr["out"] = out
    arr["size"] = np.clip(np.asarray(size), 40, 1514)
    arr["proto"] = proto
    arr["peer"] = peer
    arr["port"] = port
    arr["flags"] = flags
    return arr
