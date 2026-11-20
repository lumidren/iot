"""Captures from real gateways come in several flavours; all of them must parse."""

import struct

import pytest

from guardian.capture import iter_packets, read_windows
from guardian.net import ip

DEV = ip("192.168.50.104")
CLOUD = ip("47.254.132.10")


def ipv4_tcp(src: int, dst: int, flags: int = 0x18, payload: int = 40) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 50000, 443, 0, 0, 5 << 4, flags, 65535, 0, 0)
    iph = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + len(tcp) + payload, 0, 0, 64, 6, 0, src,
                      dst)
    return iph + tcp + b"\x00" * payload


def ether(payload: bytes, ethertype: int = 0x0800, vlan: bool = False) -> bytes:
    macs = b"\x02" * 6 + b"\x04" * 6
    if vlan:
        return macs + struct.pack("!HHH", 0x8100, 7, ethertype) + payload
    return macs + struct.pack("!H", ethertype) + payload


def pcap(frames: list[tuple[float, bytes]], *, endian: str = "<", nano: bool = False,
         linktype: int = 1) -> bytes:
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for t, frame in frames:
        sec = int(t)
        frac = int(round((t - sec) * (1e9 if nano else 1e6)))
        out += struct.pack(endian + "IIII", sec, frac, len(frame), len(frame)) + frame
    return out


def write(tmp_path, data: bytes):
    path = tmp_path / "c.pcap"
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_byte_order_and_timestamp_resolution(tmp_path, endian, nano):
    frames = [(86400 * 3 + 7.25, ether(ipv4_tcp(DEV, CLOUD, flags=0x02)))]
    pkts = list(iter_packets(write(tmp_path, pcap(frames, endian=endian, nano=nano))))
    assert len(pkts) == 1
    t, src, dst, proto, sport, dport, flags, length = pkts[0]
    assert t == pytest.approx(86400 * 3 + 7.25, abs=1e-6)
    assert (src, dst, proto, dport) == (DEV, CLOUD, 6, 443)
    assert flags == 0x01  # SYN mapped to GUARDIAN's bit


def test_raw_ip_and_vlan_tagged_frames(tmp_path):
    raw = pcap([(1.0, ipv4_tcp(DEV, CLOUD))], linktype=101)
    assert len(list(iter_packets(write(tmp_path, raw)))) == 1
    tagged = pcap([(1.0, ether(ipv4_tcp(DEV, CLOUD), vlan=True))])
    assert len(list(iter_packets(write(tmp_path, tagged)))) == 1


def test_non_ipv4_traffic_is_skipped(tmp_path):
    arp = ether(b"\x00" * 28, ethertype=0x0806)
    ipv6 = ether(b"\x60" + b"\x00" * 39, ethertype=0x86DD)
    frames = [(1.0, arp), (2.0, ipv6), (3.0, ether(ipv4_tcp(DEV, CLOUD)))]
    assert len(list(iter_packets(write(tmp_path, pcap(frames))))) == 1


def test_windows_attribute_direction_per_device(tmp_path):
    frames = [(5.0, ether(ipv4_tcp(DEV, CLOUD))), (5.1, ether(ipv4_tcp(CLOUD, DEV))),
              (25.0, ether(ipv4_tcp(DEV, CLOUD)))]
    windows = list(read_windows(write(tmp_path, pcap(frames)), {"plug": DEV}))
    assert [t for t, _ in windows] == [0.0, 10.0, 20.0]
    first = windows[0][1]["plug"]
    assert first["out"].tolist() == [True, False]
    assert all(first["peer"] == CLOUD)
    assert len(windows[1][1]["plug"]) == 0  # silent windows are kept


def test_not_a_pcap_and_unsupported_links_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="not a classic pcap"):
        list(iter_packets(write(tmp_path, b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)))
    with pytest.raises(ValueError, match="link type"):
        list(iter_packets(write(tmp_path, pcap([], linktype=105))))
