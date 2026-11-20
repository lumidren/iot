"""Simulated home IoT devices.

Each device is built from small behaviors (periodic publishes, event bursts,
streaming sessions, scheduled jobs) so that its traffic has the shape a real
gateway would see: MQTT to the local broker, TLS check-ins to a vendor cloud,
NTP, DNS, camera streams to a home server. The eight devices mirror the
hardware in the project plan: 3x ESP32 sensors, 2x ESP8266 actuators,
2x Raspberry Pi Zero, 1x ESP32-CAM.

Everything here is synthetic. It exists so the detector can be developed and
measured before the physical testbed is assembled; ``guardian.capture`` reads
real packet captures with the same packet format.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import numpy as np

from .net import ACK, FIN, SYN, TCP, UDP, concat, ip, packets

LAN = "192.168.50."
GATEWAY = ip(LAN + "1")  # MQTT broker, DNS forwarder, default route
HOME_SERVER = ip(LAN + "10")  # NAS / camera recorder
MQTT_PORT = 1883
DNS_PORT = 53
NTP_PORT = 123

# Public services the devices normally talk to. Several have more than one
# address (pools and CDNs rotate), as in real deployments.
NTP_POOL = [ip("162.159.200.1"), ip("162.159.200.123"), ip("162.159.200.5")]
PLUG_CLOUD = [ip("47.254.132.10"), ip("47.254.132.11")]
RELAY_CLOUD = [ip("47.254.132.10")]
CAM_CLOUD = [ip("18.194.35.20"), ip("18.194.35.21")]
HUB_SYNC = [ip("140.82.121.3"), ip("140.82.121.4")]
APT_MIRROR = [ip("91.189.91.81"), ip("91.189.91.82"), ip("91.189.91.83")]

HourCurve = Callable[[float], float]


def hour_of(t: float) -> float:
    """Hour of day (0-24) for a time in seconds since day 0 midnight."""
    return (t / 3600.0) % 24.0


def daytime(night: float, day: float, start: float = 7.0, end: float = 23.0) -> HourCurve:
    """A curve that is ``day`` between start and end hours and ``night`` otherwise."""

    def curve(t: float) -> float:
        h = hour_of(t)
        return day if start <= h < end else night

    return curve


def two_peaks(base: float, peak: float) -> HourCurve:
    """Morning (7-9) and evening (18-23) peaks, as people get up and come home."""

    def curve(t: float) -> float:
        h = hour_of(t)
        return peak if (7 <= h < 9 or 18 <= h < 23) else base

    return curve


def _rtt(rng: np.random.Generator, peer: int) -> float:
    lan = (peer & 0xFFFFFF00) == (GATEWAY & 0xFFFFFF00)
    return float(rng.uniform(0.002, 0.01) if lan else rng.uniform(0.03, 0.12))


def exchange(
    t: float,
    rng: np.random.Generator,
    *,
    peer: int,
    port: int,
    proto: int,
    req: tuple[int, int],
    resp: tuple[int, int] | None,
    new_connection: bool = False,
    dns: bool = False,
    resp_packets: int = 1,
) -> list[np.ndarray]:
    """One request/response, optionally with a DNS lookup and TCP handshake."""
    parts: list[np.ndarray] = []
    if dns:
        parts.append(packets([t], out=True, size=rng.integers(70, 90), proto=UDP,
                             peer=GATEWAY, port=DNS_PORT))
        parts.append(packets([t + 0.004], out=False, size=rng.integers(90, 140), proto=UDP,
                             peer=GATEWAY, port=DNS_PORT))
        t += 0.006
    rtt = _rtt(rng, peer)
    if proto == TCP and new_connection:
        parts.append(packets([t], out=True, size=60, proto=TCP, peer=peer, port=port, flags=SYN))
        parts.append(packets([t + rtt], out=False, size=60, proto=TCP, peer=peer, port=port,
                             flags=SYN | ACK))
        parts.append(packets([t + rtt + 0.0005], out=True, size=54, proto=TCP, peer=peer,
                             port=port, flags=ACK))
        t += rtt + 0.001
    tcp_flags = ACK if proto == TCP else 0
    parts.append(packets([t], out=True, size=rng.integers(*req), proto=proto, peer=peer,
                         port=port, flags=tcp_flags))
    if resp is not None:
        times = t + rtt + np.arange(resp_packets) * 0.0008
        parts.append(packets(times, out=False, size=rng.integers(*resp, size=resp_packets),
                             proto=proto, peer=peer, port=port, flags=tcp_flags))
    if proto == TCP and new_connection:
        end = t + rtt + resp_packets * 0.001 + 0.002
        parts.append(packets([end], out=True, size=54, proto=TCP, peer=peer, port=port,
                             flags=FIN | ACK))
        parts.append(packets([end + rtt], out=False, size=54, proto=TCP, peer=peer, port=port,
                             flags=FIN | ACK))
    return parts


class Behavior:
    """Something a device does that produces packets."""

    def emit(self, t0: float, t1: float, rng: np.random.Generator) -> list[np.ndarray]:
        raise NotImplementedError


@dataclass
class Periodic(Behavior):
    """A fixed-period message (sensor publish, keepalive, check-in)."""

    period: float
    peers: Sequence[int]
    port: int
    proto: int
    req: tuple[int, int]
    resp: tuple[int, int] | None
    jitter: float = 0.05
    new_connection: bool = False
    dns: bool = False
    resp_packets: int = 1
    phase: float | None = None

    def emit(self, t0: float, t1: float, rng: np.random.Generator) -> list[np.ndarray]:
        if self.phase is None:
            self.phase = float(rng.uniform(0, self.period))
        k0 = int(np.ceil((t0 - self.phase) / self.period))
        parts: list[np.ndarray] = []
        t = self.phase + k0 * self.period
        while t < t1:
            jit = float(rng.uniform(0, self.jitter * self.period))
            when = min(t + jit, t1 - 0.05)
            peer = self.peers[int(rng.integers(len(self.peers)))]
            parts += exchange(when, rng, peer=peer, port=self.port, proto=self.proto,
                              req=self.req, resp=self.resp, new_connection=self.new_connection,
                              dns=self.dns, resp_packets=self.resp_packets)
            t += self.period
        return parts


@dataclass
class Events(Behavior):
    """Random events (motion, a plug switched on) with an hour-dependent rate."""

    per_hour: HourCurve
    peers: Sequence[int]
    port: int
    proto: int
    req: tuple[int, int]
    resp: tuple[int, int] | None
    new_connection: bool = False
    dns: bool = False
    resp_packets: int = 1

    def emit(self, t0: float, t1: float, rng: np.random.Generator) -> list[np.ndarray]:
        lam = self.per_hour(t0) * (t1 - t0) / 3600.0
        n = int(rng.poisson(lam))
        parts: list[np.ndarray] = []
        for when in np.sort(rng.uniform(t0, t1 - 0.05, size=n)):
            peer = self.peers[int(rng.integers(len(self.peers)))]
            parts += exchange(float(when), rng, peer=peer, port=self.port, proto=self.proto,
                              req=self.req, resp=self.resp, new_connection=self.new_connection,
                              dns=self.dns, resp_packets=self.resp_packets)
        return parts


@dataclass
class Sessions(Behavior):
    """Streaming sessions (camera video, media download) that span many windows."""

    starts_per_hour: HourCurve
    duration: tuple[float, float]
    pps: tuple[float, float]
    size: tuple[int, int]
    peer: int
    port: int
    upload: bool = True
    ack_ratio: float = 0.5
    _until: float = field(default=-1.0, repr=False)
    _rate: float = field(default=0.0, repr=False)

    def emit(self, t0: float, t1: float, rng: np.random.Generator) -> list[np.ndarray]:
        start = t0
        if self._until <= t0:
            p = self.starts_per_hour(t0) * (t1 - t0) / 3600.0
            if rng.random() >= p:
                return []
            start = float(rng.uniform(t0, t1))
            self._until = start + float(rng.uniform(*self.duration))
            self._rate = float(rng.uniform(*self.pps))
            parts = exchange(start, rng, peer=self.peer, port=self.port, proto=TCP,
                             req=(120, 300), resp=(200, 400), new_connection=True)
            start += 0.2
        else:
            parts = []
        end = min(t1, self._until)
        if end <= start:
            return parts
        n = int(rng.poisson(self._rate * (end - start)))
        times = np.sort(rng.uniform(start, end, size=n))
        data = packets(times, out=self.upload, size=rng.integers(*self.size, size=n), proto=TCP,
                       peer=self.peer, port=self.port, flags=ACK)
        m = int(n * self.ack_ratio)
        acks = packets(np.sort(rng.uniform(start, end, size=m)), out=not self.upload, size=54,
                       proto=TCP, peer=self.peer, port=self.port, flags=ACK)
        return parts + [data, acks]


@dataclass
class Daily(Behavior):
    """A job that runs once a day around a fixed time (updates, backups)."""

    hour: float
    spread_minutes: float
    peers: Sequence[int]
    port: int
    transfers: tuple[int, int]
    _today: int = field(default=-1, repr=False)
    _when: float = field(default=0.0, repr=False)

    def emit(self, t0: float, t1: float, rng: np.random.Generator) -> list[np.ndarray]:
        day = int(t0 // 86400)
        if day != self._today:
            self._today = day
            offset = float(rng.uniform(-self.spread_minutes, self.spread_minutes)) * 60
            self._when = day * 86400 + self.hour * 3600 + offset
        if not (t0 <= self._when < t1):
            return []
        parts: list[np.ndarray] = []
        t = self._when
        for _ in range(int(rng.integers(*self.transfers))):
            peer = self.peers[int(rng.integers(len(self.peers)))]
            parts += exchange(t, rng, peer=peer, port=self.port, proto=TCP, req=(200, 400),
                              resp=(1200, 1460), new_connection=True, dns=True,
                              resp_packets=int(rng.integers(20, 60)))
            t = min(t + float(rng.uniform(0.1, 0.4)), t1 - 0.05)
        return parts


@dataclass
class DeviceSpec:
    """Static description of a protected device."""

    id: str
    name: str
    kind: str
    hardware: str
    address: int
    build: Callable[[], list[Behavior]]


class Device:
    """A running simulated device."""

    def __init__(self, spec: DeviceSpec, seed: int):
        self.spec = spec
        self.rng = np.random.default_rng(seed)
        self.behaviors = spec.build()

    def window(self, t0: float, t1: float) -> np.ndarray:
        parts: list[np.ndarray] = []
        for behavior in self.behaviors:
            parts += behavior.emit(t0, t1, self.rng)
        return concat(parts)


def _mqtt_keepalive() -> Periodic:
    return Periodic(60, [GATEWAY], MQTT_PORT, TCP, req=(54, 56), resp=(54, 56), jitter=0.02)


def _ntp(period: float = 3600) -> Periodic:
    return Periodic(period, NTP_POOL, NTP_PORT, UDP, req=(90, 91), resp=(90, 91), dns=True)


def _temp() -> list[Behavior]:
    return [
        Periodic(30, [GATEWAY], MQTT_PORT, TCP, req=(90, 121), resp=(58, 59)),
        _mqtt_keepalive(),
        _ntp(),
    ]


def _motion() -> list[Behavior]:
    return [
        Events(daytime(4, 40), [GATEWAY], MQTT_PORT, TCP, req=(70, 91), resp=(58, 59)),
        _mqtt_keepalive(),
        _ntp(),
    ]


def _environment() -> list[Behavior]:
    return [
        Periodic(60, [GATEWAY], MQTT_PORT, TCP, req=(180, 261), resp=(58, 59)),
        _mqtt_keepalive(),
        _ntp(),
    ]


def _plug() -> list[Behavior]:
    return [
        _mqtt_keepalive(),
        Events(two_peaks(1, 8), [GATEWAY], MQTT_PORT, TCP, req=(80, 101), resp=(58, 59)),
        Periodic(300, PLUG_CLOUD, 443, TCP, req=(300, 520), resp=(200, 420), new_connection=True,
                 dns=True, resp_packets=2),
    ]


def _relay() -> list[Behavior]:
    return [
        _mqtt_keepalive(),
        Events(daytime(0.2, 2), [GATEWAY], MQTT_PORT, TCP, req=(80, 101), resp=(58, 59)),
        Periodic(600, RELAY_CLOUD, 443, TCP, req=(300, 520), resp=(200, 420),
                 new_connection=True, dns=True, resp_packets=2),
    ]


def _hub() -> list[Behavior]:
    return [
        Periodic(10, [GATEWAY], MQTT_PORT, TCP, req=(200, 401), resp=(58, 59), jitter=0.1),
        Periodic(900, HUB_SYNC, 443, TCP, req=(400, 900), resp=(900, 1460), new_connection=True,
                 dns=True, resp_packets=6),
        _ntp(1024),
    ]


def _media() -> list[Behavior]:
    return [
        Sessions(daytime(0.1, 0.6, start=18, end=24), duration=(600, 2400), pps=(80, 160),
                 size=(1200, 1460), peer=HOME_SERVER, port=8080, upload=False),
        Periodic(120, [HOME_SERVER], 8080, TCP, req=(150, 250), resp=(150, 300)),
        Daily(3.0, 20, APT_MIRROR, 80, transfers=(3, 7)),
        _ntp(1024),
    ]


def _camera() -> list[Behavior]:
    return [
        Periodic(60, [HOME_SERVER], 8080, TCP, req=(1200, 1460), resp=(60, 120), jitter=0.05,
                 new_connection=True, resp_packets=1),
        Sessions(daytime(0.3, 4), duration=(20, 120), pps=(30, 80), size=(1000, 1460),
                 peer=HOME_SERVER, port=8554, upload=True),
        Periodic(120, CAM_CLOUD, 443, TCP, req=(200, 400), resp=(150, 300), new_connection=True,
                 dns=True),
        _ntp(),
    ]


DEVICES: list[DeviceSpec] = [
    DeviceSpec("temp-1", "Temperature sensor", "sensor", "ESP32", ip(LAN + "101"), _temp),
    DeviceSpec("motion-1", "Motion sensor", "sensor", "ESP32", ip(LAN + "102"), _motion),
    DeviceSpec("env-1", "Environment sensor", "sensor", "ESP32", ip(LAN + "103"), _environment),
    DeviceSpec("plug-1", "Smart plug", "actuator", "ESP8266", ip(LAN + "104"), _plug),
    DeviceSpec("relay-1", "Relay switch", "actuator", "ESP8266", ip(LAN + "105"), _relay),
    DeviceSpec("hub-1", "Sensor hub", "compute", "Raspberry Pi Zero", ip(LAN + "106"), _hub),
    DeviceSpec("media-1", "Media node", "compute", "Raspberry Pi Zero", ip(LAN + "107"), _media),
    DeviceSpec("cam-1", "Smart camera", "camera", "ESP32-CAM", ip(LAN + "108"), _camera),
]

DEVICE_INDEX = {spec.id: spec for spec in DEVICES}


class Home:
    """All simulated devices on one home network, stepped window by window."""

    def __init__(self, seed: int = 0, specs: Sequence[DeviceSpec] = DEVICES):
        self.devices = {
            spec.id: Device(spec, seed * 1000 + i) for i, spec in enumerate(specs)
        }

    def window(self, t0: float, t1: float) -> dict[str, np.ndarray]:
        return {dev_id: dev.window(t0, t1) for dev_id, dev in self.devices.items()}
