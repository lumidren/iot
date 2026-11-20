"""The 60 behavioral features computed for every device every 10 seconds.

Features fall into seven groups: volume, rates, timing, protocol mix, network
identity (who the device talks to), connection behavior, and time of day. They
use only metadata, so they work the same on encrypted traffic.

Network-identity features compare the window against what the device is known
to talk to (its ``Context``), which is learned during the baseline period.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from .net import ACK, FIN, ICMP, RST, SYN, TCP, UDP, is_private, prefix24

WINDOW = 10.0


@dataclass(frozen=True)
class Feature:
    name: str
    label: str
    unit: str
    group: str
    log: bool = False  # log1p before modelling (heavy-tailed counts and bytes)
    explain: bool = True  # may be cited in an explanation


FEATURES: list[Feature] = [
    # volume (12)
    Feature("pkts_out", "Packets sent", "packets", "volume", log=True),
    Feature("pkts_in", "Packets received", "packets", "volume", log=True),
    Feature("bytes_out", "Bytes sent", "bytes", "volume", log=True),
    Feature("bytes_in", "Bytes received", "bytes", "volume", log=True),
    Feature("pkts_total", "Total packets", "packets", "volume", log=True),
    Feature("bytes_total", "Total bytes", "bytes", "volume", log=True),
    Feature("mean_size_out", "Average sent packet size", "bytes", "volume"),
    Feature("mean_size_in", "Average received packet size", "bytes", "volume"),
    Feature("std_size_out", "Sent packet size spread", "bytes", "volume"),
    Feature("std_size_in", "Received packet size spread", "bytes", "volume"),
    Feature("max_size", "Largest packet", "bytes", "volume"),
    Feature("large_pkt_frac", "Share of large packets (>1000 B)", "ratio", "volume"),
    # rates (6)
    Feature("out_in_pkt_ratio", "Sent/received packet ratio", "ratio", "rates", log=True),
    Feature("out_in_byte_ratio", "Sent/received byte ratio", "ratio", "rates", log=True),
    Feature("upload_frac", "Upload share of bytes", "ratio", "rates"),
    Feature("small_pkt_frac", "Share of tiny packets (<100 B)", "ratio", "rates"),
    Feature("peak_pps", "Peak packets in one second", "packets/s", "rates", log=True),
    Feature("active_seconds", "Seconds with traffic", "seconds", "rates"),
    # timing (6)
    Feature("iat_mean", "Average gap between packets", "seconds", "timing"),
    Feature("iat_std", "Gap variability", "seconds", "timing"),
    Feature("iat_min", "Shortest gap", "seconds", "timing"),
    Feature("iat_max", "Longest gap", "seconds", "timing"),
    Feature("iat_cv", "Gap irregularity (CV)", "ratio", "timing"),
    Feature("burstiness", "Burstiness (peak/average rate)", "ratio", "timing"),
    # protocol mix (8)
    Feature("frac_tcp", "TCP share", "ratio", "protocol"),
    Feature("frac_udp", "UDP share", "ratio", "protocol"),
    Feature("frac_icmp", "ICMP share", "ratio", "protocol"),
    Feature("frac_mqtt", "MQTT share", "ratio", "protocol"),
    Feature("frac_http", "HTTP share", "ratio", "protocol"),
    Feature("frac_https", "HTTPS/TLS share", "ratio", "protocol"),
    Feature("frac_dns", "DNS share", "ratio", "protocol"),
    Feature("frac_other_ports", "Unusual-port share", "ratio", "protocol"),
    # network identity (12)
    Feature("n_peers", "Distinct destinations", "hosts", "identity", log=True),
    Feature("n_ports", "Distinct ports", "ports", "identity", log=True),
    Feature("n_new_peers", "Never-seen destinations", "hosts", "identity", log=True),
    Feature("frac_new_peer_pkts", "Traffic to never-seen destinations", "ratio", "identity"),
    Feature("n_new_ports", "Never-seen ports", "ports", "identity", log=True),
    Feature("n_external_peers", "Internet destinations", "hosts", "identity", log=True),
    Feature("frac_external_pkts", "Internet share of traffic", "ratio", "identity"),
    Feature("n_new_external_nets", "Never-seen internet networks (/24)", "networks", "identity",
            log=True),
    Feature("peer_entropy", "Destination spread (entropy)", "bits", "identity"),
    Feature("port_entropy", "Port spread (entropy)", "bits", "identity"),
    Feature("n_lan_peers", "Local hosts contacted", "hosts", "identity", log=True),
    Feature("top_peer_frac", "Share of the busiest destination", "ratio", "identity"),
    # connections (10)
    Feature("n_syn", "Connection attempts (SYN)", "attempts", "connections", log=True),
    Feature("n_synack_in", "Accepted connections (SYN-ACK)", "replies", "connections", log=True),
    Feature("n_rst_in", "Refused connections (RST)", "replies", "connections", log=True),
    Feature("n_fin", "Connection closes (FIN)", "packets", "connections", log=True),
    Feature("syn_ratio", "SYN share of sent packets", "ratio", "connections"),
    Feature("n_conn_targets", "Distinct connection targets", "targets", "connections",
            log=True),
    Feature("failed_conn_ratio", "Unanswered connection share", "ratio", "connections"),
    Feature("n_dns_queries", "DNS lookups", "queries", "connections", log=True),
    Feature("dns_frac_out", "DNS share of sent packets", "ratio", "connections"),
    Feature("inbound_new_peer_pkts", "Packets from never-seen hosts", "packets", "connections",
            log=True),
    # time of day (6)
    Feature("hour_sin", "Time of day (sin)", "", "time", explain=False),
    Feature("hour_cos", "Time of day (cos)", "", "time", explain=False),
    Feature("hour_activity", "Usual activity at this hour", "ratio", "time", explain=False),
    Feature("off_hours_activity", "Activity at an unusual hour", "ratio", "time"),
    Feature("active_streak", "Consecutive active windows", "windows", "time", log=True),
    Feature("since_prev_active", "Seconds since previous activity", "seconds", "time",
            explain=False),
]

N_FEATURES = len(FEATURES)
NAMES = [f.name for f in FEATURES]
INDEX = {name: i for i, name in enumerate(NAMES)}
LOG_MASK = np.array([f.log for f in FEATURES])
EXPLAIN_MASK = np.array([f.explain for f in FEATURES])

assert N_FEATURES == 60, N_FEATURES

MQTT_PORTS = (1883, 8883)
HTTP_PORTS = (80, 8080)
HTTPS_PORTS = (443, 8443)
KNOWN_SERVICE_PORTS = (*MQTT_PORTS, *HTTP_PORTS, *HTTPS_PORTS, 53, 123, 8554)


@dataclass
class Context:
    """What a device normally does, learned during its baseline period."""

    known_peers: set[int] = field(default_factory=set)
    known_nets: set[int] = field(default_factory=set)
    known_ports: set[int] = field(default_factory=set)
    hour_activity: np.ndarray = field(default_factory=lambda: np.full(24, 0.5))
    # rolling state (not learned)
    streak: int = 0
    last_active: float = -1e9

    def learn(self, windows: list[tuple[float, np.ndarray]]) -> None:
        """Learn destinations, ports and hourly activity from baseline windows."""
        active = np.zeros(24)
        total = np.zeros(24)
        for t0, pkts in windows:
            h = int((t0 / 3600.0) % 24)
            total[h] += 1
            if len(pkts):
                active[h] += 1
                self.known_peers.update(np.unique(pkts["peer"]).tolist())
                self.known_ports.update(np.unique(pkts["port"]).tolist())
        self.known_nets = {int(p) & 0xFFFFFF00 for p in self.known_peers}
        with np.errstate(invalid="ignore", divide="ignore"):
            self.hour_activity = np.where(total > 0, active / np.maximum(total, 1), 0.5)
        self.reset_state()

    def reset_state(self) -> None:
        self.streak = 0
        self.last_active = -1e9


def _entropy(values: np.ndarray) -> float:
    if len(values) == 0:
        return 0.0
    _, counts = np.unique(values, return_counts=True)
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())


def _frac(mask: np.ndarray, n: int) -> float:
    return float(mask.sum()) / n if n else 0.0


def extract(pkts: np.ndarray, t0: float, ctx: Context, dt: float = WINDOW) -> np.ndarray:
    """Compute the 60-feature vector for one device and one window."""
    f = np.zeros(N_FEATURES, dtype=np.float64)
    n = len(pkts)
    hour = (t0 / 3600.0) % 24.0
    f[INDEX["hour_sin"]] = math.sin(2 * math.pi * hour / 24)
    f[INDEX["hour_cos"]] = math.cos(2 * math.pi * hour / 24)
    usual = float(ctx.hour_activity[int(hour)])
    f[INDEX["hour_activity"]] = usual

    if n == 0:
        ctx.streak = 0
        f[INDEX["since_prev_active"]] = min(t0 - ctx.last_active, 3600.0)
        return f

    out = pkts["out"]
    size = pkts["size"].astype(np.float64)
    proto = pkts["proto"]
    peer = pkts["peer"]
    port = pkts["port"]
    flags = pkts["flags"]
    so, si = size[out], size[~out]

    # volume
    f[0], f[1] = len(so), len(si)
    f[2], f[3] = so.sum(), si.sum()
    f[4], f[5] = n, size.sum()
    f[6] = so.mean() if len(so) else 0.0
    f[7] = si.mean() if len(si) else 0.0
    f[8] = so.std() if len(so) else 0.0
    f[9] = si.std() if len(si) else 0.0
    f[10] = size.max()
    f[11] = _frac(size > 1000, n)

    # rates
    f[12] = f[0] / (f[1] + 1)
    f[13] = f[2] / (f[3] + 1)
    f[14] = f[2] / f[5] if f[5] else 0.0
    f[15] = _frac(size < 100, n)
    bins = np.bincount(np.clip((pkts["t"] - t0).astype(np.int64), 0, int(dt) - 1),
                       minlength=int(dt))
    f[16] = bins.max()
    f[17] = (bins > 0).sum()

    # timing
    if n > 1:
        gaps = np.diff(np.sort(pkts["t"]))
        f[18], f[19], f[20], f[21] = gaps.mean(), gaps.std(), gaps.min(), gaps.max()
        f[22] = f[19] / f[18] if f[18] > 0 else 0.0
    f[23] = f[16] / (n / dt)

    # protocol mix
    f[24] = _frac(proto == TCP, n)
    f[25] = _frac(proto == UDP, n)
    f[26] = _frac(proto == ICMP, n)
    f[27] = _frac(np.isin(port, MQTT_PORTS), n)
    f[28] = _frac(np.isin(port, HTTP_PORTS), n)
    f[29] = _frac(np.isin(port, HTTPS_PORTS), n)
    f[30] = _frac(port == 53, n)
    f[31] = _frac(~np.isin(port, KNOWN_SERVICE_PORTS), n)

    # network identity
    peers = np.unique(peer)
    f[32] = len(peers)
    f[33] = len(np.unique(port))
    known = np.fromiter(ctx.known_peers, dtype=np.uint32, count=len(ctx.known_peers))
    new_peer_mask = ~np.isin(peer, known)
    new_peers = np.unique(peer[new_peer_mask])
    f[34] = len(new_peers)
    f[35] = _frac(new_peer_mask, n)
    known_ports = np.fromiter(ctx.known_ports, dtype=np.uint16, count=len(ctx.known_ports))
    f[36] = len(np.setdiff1d(np.unique(port), known_ports))
    private = is_private(peers)
    f[37] = int((~private).sum())
    f[38] = _frac(~is_private(peer), n)
    ext_new = new_peers[~is_private(new_peers)] if len(new_peers) else new_peers
    nets = {int(p) for p in np.unique(prefix24(ext_new))} if len(ext_new) else set()
    f[39] = len(nets - ctx.known_nets)
    f[40] = _entropy(peer)
    f[41] = _entropy(port)
    f[42] = int(private.sum())
    _, counts = np.unique(peer, return_counts=True)
    f[43] = counts.max() / n

    # connections
    tcp_out = out & (proto == TCP)
    syn = tcp_out & ((flags & SYN) > 0) & ((flags & ACK) == 0)
    f[44] = syn.sum()
    f[45] = ((~out) & ((flags & SYN) > 0) & ((flags & ACK) > 0)).sum()
    f[46] = ((~out) & ((flags & RST) > 0)).sum()
    f[47] = ((flags & FIN) > 0).sum()
    f[48] = f[44] / f[0] if f[0] else 0.0
    if f[44]:
        targets = np.unique(peer[syn].astype(np.uint64) << np.uint64(16) | port[syn])
        f[49] = len(targets)
        f[50] = max(0.0, (f[44] - f[45]) / f[44])
    dns = out & (proto == UDP) & (port == 53)
    f[51] = dns.sum()
    f[52] = f[51] / f[0] if f[0] else 0.0
    f[53] = ((~out) & new_peer_mask).sum()

    # time of day
    f[57] = 1.0 - usual
    ctx.streak += 1
    f[58] = ctx.streak
    f[59] = min(t0 - ctx.last_active, 3600.0)
    ctx.last_active = t0
    return f


def model_view(x: np.ndarray) -> np.ndarray:
    """Transform raw features for the models (log1p on heavy-tailed columns)."""
    x = np.array(x, dtype=np.float64, copy=True)
    x[..., LOG_MASK] = np.log1p(np.maximum(x[..., LOG_MASK], 0))
    return x
