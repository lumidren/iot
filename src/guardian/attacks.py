"""Attack traffic injected into a simulated device.

The six headline scenarios match the project plan (flooding, C&C beaconing,
scanning, exfiltration, cryptomining, and a multi-stage "zero-day" hybrid).
Three adversarial scenarios are kept separate on purpose: a bulk upload and a
low-and-slow exfiltration that both hide inside a destination the device
already trusts, and a very slow scan.
They exist to show where behavioral detection runs out, not to flatter it.

All addresses are documentation or arbitrary public ranges; nothing here sends
real packets.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .devices import GATEWAY, LAN, exchange
from .net import ACK, RST, SYN, TCP, UDP, ip, packets

ATTACKS = [
    "ddos_flood",
    "cc_beacon",
    "scan",
    "exfiltration",
    "cryptomining",
    "zero_day_hybrid",
]
ADVERSARIAL = ["trusted_upload", "mimicry_exfil", "low_rate_scan"]
ALL_ATTACKS = ATTACKS + ADVERSARIAL

LABELS = {
    "ddos_flood": "DDoS flooding",
    "cc_beacon": "C&C beaconing",
    "scan": "Network scanning",
    "exfiltration": "Data exfiltration",
    "cryptomining": "Cryptomining",
    "zero_day_hybrid": "Zero-day hybrid",
    "trusted_upload": "Bulk upload to a trusted destination (adversarial)",
    "mimicry_exfil": "Mimicry exfiltration (adversarial)",
    "low_rate_scan": "Low-rate scan (adversarial)",
}

FLOOD_VICTIM = ip("203.0.113.50")
C2_SERVER = ip("185.220.101.47")
EXFIL_DROP = ip("45.137.21.9")
MINING_POOL = ip("51.68.190.10")
EXPLOIT_SOURCE = ip("198.51.100.77")
HYBRID_C2 = [ip("193.142.146.20"), ip("193.142.146.21"), ip("194.26.29.15")]
SCAN_PORTS = [23, 2323, 22, 80, 8080, 7547]


@dataclass
class Attack:
    """One attack episode against one device."""

    kind: str
    device: str
    start: float
    duration: float
    intensity: float = 1.0  # scales packet rates (weaker hardware floods slower)
    cover_peer: int = 0  # destination a mimicry attack hides behind
    cover_port: int = 443
    _rng: np.random.Generator | None = field(default=None, repr=False)
    _next: float = field(default=-1.0, repr=False)

    @property
    def end(self) -> float:
        return self.start + self.duration

    def overlaps(self, t0: float, t1: float) -> bool:
        return self.start < t1 and self.end > t0

    def emit(self, t0: float, t1: float, rng: np.random.Generator) -> list[np.ndarray]:
        a, b = max(t0, self.start), min(t1, self.end)
        if b <= a:
            return []
        return getattr(self, "_" + self.kind)(a, b, rng)

    # -- periodic helper ---------------------------------------------------
    def _ticks(self, a: float, b: float, rng: np.random.Generator, lo: float, hi: float):
        if self._next < 0:
            self._next = self.start + float(rng.uniform(0, 2))
        while self._next < b:
            if self._next >= a:
                yield self._next
            self._next += float(rng.uniform(lo, hi))

    # -- scenarios ---------------------------------------------------------
    def _ddos_flood(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        rate = 400 * self.intensity
        n = int(rng.poisson(rate * (b - a)))
        times = np.sort(rng.uniform(a, b, size=n))
        syn = packets(times, out=True, size=60, proto=TCP, peer=FLOOD_VICTIM, port=80, flags=SYN)
        m = int(rng.poisson(rate * 0.5 * (b - a)))
        udp = packets(np.sort(rng.uniform(a, b, size=m)), out=True,
                      size=rng.integers(500, 1200, size=m), proto=UDP, peer=FLOOD_VICTIM,
                      port=53)
        return [syn, udp]

    def _cc_beacon(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        parts: list[np.ndarray] = []
        for t in self._ticks(a, b, rng, 20, 45):
            parts += exchange(min(t, b - 0.3), rng, peer=C2_SERVER, port=443, proto=TCP,
                              req=(180, 360), resp=(90, 260), new_connection=True, dns=True)
        return parts

    def _scan(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        n = int(rng.poisson(30 * self.intensity * (b - a)))
        parts: list[np.ndarray] = []
        for t in np.sort(rng.uniform(a, b, size=n)):
            host = ip(LAN + str(int(rng.integers(2, 255))))
            port = SCAN_PORTS[int(rng.integers(len(SCAN_PORTS)))]
            parts.append(packets([t], out=True, size=60, proto=TCP, peer=host, port=port,
                                 flags=SYN))
            roll = rng.random()
            if roll < 0.25:
                parts.append(packets([t + 0.003], out=False, size=54, proto=TCP, peer=host,
                                     port=port, flags=RST | ACK))
            elif roll < 0.28:
                parts.append(packets([t + 0.003], out=False, size=60, proto=TCP, peer=host,
                                     port=port, flags=SYN | ACK))
        return parts

    def _exfiltration(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        parts: list[np.ndarray] = []
        if a == self.start:
            parts += exchange(a, rng, peer=EXFIL_DROP, port=443, proto=TCP, req=(300, 500),
                              resp=(1200, 1460), new_connection=True, dns=True, resp_packets=3)
        n = int(rng.poisson(40 * self.intensity * (b - a)))
        times = np.sort(rng.uniform(a, b, size=n))
        parts.append(packets(times, out=True, size=rng.integers(1200, 1460, size=n), proto=TCP,
                             peer=EXFIL_DROP, port=443, flags=ACK))
        parts.append(packets(times[::2] + 0.08, out=False, size=54, proto=TCP, peer=EXFIL_DROP,
                             port=443, flags=ACK))
        return parts

    def _cryptomining(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        parts: list[np.ndarray] = []
        if a == self.start:
            parts += exchange(a, rng, peer=MINING_POOL, port=3333, proto=TCP, req=(200, 300),
                              resp=(300, 600), new_connection=True, dns=True)
        for t in self._ticks(a, b, rng, 4, 12):
            parts.append(packets([t], out=False, size=rng.integers(250, 420), proto=TCP,
                                 peer=MINING_POOL, port=3333, flags=ACK))
            if rng.random() < 0.4:
                parts += exchange(min(t + 0.5, b - 0.2), rng, peer=MINING_POOL, port=3333,
                                  proto=TCP, req=(150, 260), resp=(80, 120))
        return parts

    def _zero_day_hybrid(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        parts: list[np.ndarray] = []
        if a == self.start:  # exploit arrives from outside, payload pulled down
            src_port = int(rng.integers(40000, 60000))
            parts.append(packets(a + np.arange(6) * 0.01, out=False,
                                 size=rng.integers(400, 1400, size=6), proto=TCP,
                                 peer=EXPLOIT_SOURCE, port=src_port, flags=ACK))
            parts.append(packets(a + 0.07 + np.arange(4) * 0.01, out=True, size=60, proto=TCP,
                                 peer=EXPLOIT_SOURCE, port=src_port, flags=ACK))
        n_dns = int(rng.integers(3, 10))  # algorithmically generated domains
        for t in np.sort(rng.uniform(a, b, size=n_dns)):
            parts.append(packets([t], out=True, size=rng.integers(80, 110), proto=UDP,
                                 peer=GATEWAY, port=53))
            parts.append(packets([t + 0.02], out=False, size=rng.integers(90, 160), proto=UDP,
                                 peer=GATEWAY, port=53))
        for t in self._ticks(a, b, rng, 8, 20):
            peer = HYBRID_C2[int(rng.integers(len(HYBRID_C2)))]
            parts += exchange(min(t, b - 0.3), rng, peer=peer, port=8443, proto=TCP,
                              req=(150, 400), resp=(100, 900), new_connection=True)
        probes = int(rng.poisson(1.0 * (b - a)))
        for t in np.sort(rng.uniform(a, b, size=probes)):
            host = ip(LAN + str(int(rng.integers(2, 255))))
            parts.append(packets([t], out=True, size=60, proto=TCP, peer=host, port=23,
                                 flags=SYN))
        return parts

    def _mimicry_exfil(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        parts: list[np.ndarray] = []
        peer = self.cover_peer
        for t in self._ticks(a, b, rng, 25, 60):
            parts += exchange(min(t, b - 0.3), rng, peer=peer, port=self.cover_port, proto=TCP,
                              req=(300, 520), resp=(200, 420), new_connection=True, dns=True,
                              resp_packets=2)
        return parts

    def _trusted_upload(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        """Stolen data streamed to a destination the device already uses."""
        n = int(rng.poisson(25 * self.intensity * (b - a)))
        times = np.sort(rng.uniform(a, b, size=n))
        return [
            packets(times, out=True, size=rng.integers(1000, 1400, size=n), proto=TCP,
                    peer=self.cover_peer, port=self.cover_port, flags=ACK),
            packets(times[::2] + 0.05, out=False, size=54, proto=TCP, peer=self.cover_peer,
                    port=self.cover_port, flags=ACK),
        ]

    def _low_rate_scan(self, a: float, b: float, rng: np.random.Generator) -> list[np.ndarray]:
        parts: list[np.ndarray] = []
        for t in self._ticks(a, b, rng, 15, 40):
            host = ip(LAN + str(int(rng.integers(2, 255))))
            parts.append(packets([t], out=True, size=60, proto=TCP, peer=host, port=23,
                                 flags=SYN))
        return parts


INTENSITY_BY_KIND = {"sensor": 0.5, "actuator": 0.4, "compute": 1.0, "camera": 0.7}
