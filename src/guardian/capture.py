"""Read and write classic pcap files (no third-party dependencies).

``read_windows`` turns a capture taken on the gateway (for example
``tcpdump -i br0 -w home.pcap``) into the same per-device 10-second windows the
simulator produces, so the detector runs unchanged on real traffic.
``write_pcap`` exports simulated traffic so it can be inspected in Wireshark.

Supported: Ethernet (linktype 1) and raw IPv4 (linktype 101) captures, IPv4
with TCP, UDP or ICMP, microsecond or nanosecond timestamps, either byte order.
Everything else is skipped.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from pathlib import Path

import numpy as np

from .net import ICMP, PACKET, TCP, UDP

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D
LINK_ETHERNET = 1
LINK_RAW = 101

# pcap TCP flag bits -> our bits
_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10


def _tcp_flags(raw: int) -> int:
    out = 0
    if raw & _SYN:
        out |= 0x01
    if raw & _ACK:
        out |= 0x02
    if raw & _FIN:
        out |= 0x04
    if raw & _RST:
        out |= 0x08
    return out


def iter_packets(path: str | Path) -> Iterator[tuple[float, int, int, int, int, int, int, int]]:
    """Yield (time, src, dst, proto, sport, dport, flags, wire_length) per IPv4 packet."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            return
        for endian in ("<", ">"):
            magic = struct.unpack(endian + "I", header[:4])[0]
            if magic in (MAGIC_US, MAGIC_NS):
                break
        else:
            raise ValueError(f"{path}: not a classic pcap file")
        scale = 1e-9 if magic == MAGIC_NS else 1e-6
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype not in (LINK_ETHERNET, LINK_RAW):
            raise ValueError(f"{path}: unsupported link type {linktype}")
        rec = struct.Struct(endian + "IIII")
        while True:
            head = fh.read(16)
            if len(head) < 16:
                return
            sec, frac, incl, orig = rec.unpack(head)
            data = fh.read(incl)
            off = 0
            if linktype == LINK_ETHERNET:
                if len(data) < 14:
                    continue
                ethertype = struct.unpack("!H", data[12:14])[0]
                off = 14
                if ethertype == 0x8100 and len(data) >= 18:  # VLAN tag
                    ethertype = struct.unpack("!H", data[16:18])[0]
                    off = 18
                if ethertype != 0x0800:
                    continue
            if len(data) < off + 20 or data[off] >> 4 != 4:
                continue
            ihl = (data[off] & 0x0F) * 4
            proto = data[off + 9]
            src, dst = struct.unpack("!II", data[off + 12:off + 20])
            l4 = off + ihl
            sport = dport = flags = 0
            if proto in (TCP, UDP) and len(data) >= l4 + 4:
                sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
                if proto == TCP and len(data) >= l4 + 14:
                    flags = _tcp_flags(data[l4 + 13])
            elif proto != ICMP:
                continue
            yield sec + frac * scale, src, dst, proto, sport, dport, flags, orig


def read_windows(path: str | Path, devices: dict[str, int], window: float = 10.0,
                 start: float | None = None) -> Iterator[tuple[float, dict[str, np.ndarray]]]:
    """Group a capture into per-device windows of ``PACKET`` records.

    ``devices`` maps a device id to its IPv4 address (as an integer). Times are
    re-based so the first packet's midnight is t = 0 (keeps time-of-day features).
    """
    by_addr = {addr: dev for dev, addr in devices.items()}
    rows: dict[str, list[tuple]] = {dev: [] for dev in devices}
    current = None
    base = None
    for t, src, dst, proto, sport, dport, flags, length in iter_packets(path):
        if base is None:
            base = start if start is not None else t - (t % 86400)
        rel = t - base
        w = int(rel // window)
        if current is None:
            current = w
        while w > current:
            yield current * window, _flush(rows)
            current += 1
        if src in by_addr:
            rows[by_addr[src]].append((rel, True, min(length, 65535), proto, dst, dport, flags))
        if dst in by_addr:
            rows[by_addr[dst]].append((rel, False, min(length, 65535), proto, src, sport, flags))
    if current is not None:
        yield current * window, _flush(rows)


def _flush(rows: dict[str, list[tuple]]) -> dict[str, np.ndarray]:
    out = {}
    for dev, items in rows.items():
        arr = np.array(items, dtype=PACKET) if items else np.zeros(0, dtype=PACKET)
        arr.sort(order="t", kind="stable")
        out[dev] = arr
        items.clear()
    return out


def write_pcap(path: str | Path, windows: Iterable[tuple[str, int, np.ndarray]],
               epoch: float = 1_700_000_000.0) -> int:
    """Write (device id, device address, packets) triples as an Ethernet pcap.

    Payloads are zero-filled to each packet's recorded size, so lengths, timing,
    addresses, ports and TCP flags are faithful while no content is invented.
    """
    records = []
    for _, addr, pkts in windows:
        for p in pkts:
            src, dst = (addr, int(p["peer"])) if p["out"] else (int(p["peer"]), addr)
            dev_port = 40000 + (int(p["port"]) % 20000)
            sport, dport = (dev_port, int(p["port"])) if p["out"] else (int(p["port"]),
                                                                          dev_port)
            records.append((float(p["t"]), src, dst, int(p["proto"]), sport, dport,
                            int(p["flags"]), int(p["size"])))
    records.sort(key=lambda r: r[0])
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", MAGIC_US, 2, 4, 0, 0, 65535, LINK_ETHERNET))
        for t, src, dst, proto, sport, dport, flags, size in records:
            frame = _frame(src, dst, proto, sport, dport, flags, size)
            ts = epoch + t
            sec = int(ts)
            fh.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)) % 1_000_000,
                                 len(frame), len(frame)))
            fh.write(frame)
    return len(records)


def _frame(src: int, dst: int, proto: int, sport: int, dport: int, flags: int,
           size: int) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    if proto == TCP:
        raw = ((flags & 0x01) and _SYN) | ((flags & 0x02) and _ACK) | \
              ((flags & 0x04) and _FIN) | ((flags & 0x08) and _RST)
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, raw, 65535, 0, 0)
    elif proto == UDP:
        l4 = struct.pack("!HHHH", sport, dport, 8, 0)
    else:
        l4 = struct.pack("!BBHI", 8, 0, 0, 0)
    ip_len = max(size - 14, 20 + len(l4))
    payload = b"\x00" * (ip_len - 20 - len(l4))
    if proto == UDP:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    iph = struct.pack("!BBHHHBBHII", 0x45, 0, ip_len, 0, 0, 64, proto, 0, src, dst)
    return eth + iph + l4 + payload
