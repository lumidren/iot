"""Per-device detection: three independent signals combined into a 0-100 threat score.

1. Statistical layer: how far each feature is outside the device's learned
   normal range (0.1st-99.9th percentile of its baseline).
2. ML layer: an Isolation Forest plus a nearest-neighbour distance to the
   device's remembered normal traffic shapes, both trained only on that
   device's normal windows and calibrated on held-out normal windows so the
   score has a known false-alarm level. The forest finds unusual combinations
   inside the normal ranges; the distance also grows without limit for values
   the device has never produced (a forest cannot see past its training range).
3. Network identity: destinations, networks and local hosts the device has
   never contacted before. This is rule-based on purpose: "an ESP32 sensor
   opened a connection to a network it has never used" is evidence a person can
   check.

The signals are combined with a noisy-OR, so any one of them can raise the
threat on its own and agreement between them pushes it higher.
"""

from __future__ import annotations

import copy
import math
from collections import deque
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

from .fastforest import FastForest
from .features import FEATURES, INDEX, N_FEATURES, Context, extract, model_view
from .net import SYN, TCP, is_private, prefix24

# Novelty features are scored by the identity layer, not by the range check.
NOVELTY = {"n_new_peers", "frac_new_peer_pkts", "n_new_ports", "n_new_external_nets",
           "inbound_new_peer_pkts"}
STAT_MASK = np.array([f.explain and f.name not in NOVELTY for f in FEATURES])


def _scale_floor(feature) -> float:
    if feature.log:
        return 0.5  # about a 65% change on the original scale
    # Gaps inside a 10 s window are noisy for sparse devices: allow 2.5 s of slack.
    return {"ratio": 0.1, "bytes": 100.0, "seconds": 2.5, "bits": 0.5}.get(feature.unit, 1.0)


FLOORS = np.array([_scale_floor(f) for f in FEATURES])


@dataclass
class Baseline:
    """Learned normal range of every feature (in model space)."""

    lo: np.ndarray = field(default_factory=lambda: np.zeros(N_FEATURES))
    hi: np.ndarray = field(default_factory=lambda: np.zeros(N_FEATURES))
    med: np.ndarray = field(default_factory=lambda: np.zeros(N_FEATURES))
    raw_lo: np.ndarray = field(default_factory=lambda: np.zeros(N_FEATURES))
    raw_hi: np.ndarray = field(default_factory=lambda: np.zeros(N_FEATURES))
    raw_med: np.ndarray = field(default_factory=lambda: np.zeros(N_FEATURES))
    up: np.ndarray = field(default_factory=lambda: np.ones(N_FEATURES))
    down: np.ndarray = field(default_factory=lambda: np.ones(N_FEATURES))

    def fit(self, raw: np.ndarray) -> Baseline:
        view = model_view(raw)
        self.lo, self.med, self.hi = np.quantile(view, [0.001, 0.5, 0.999], axis=0)
        self.raw_lo, self.raw_med, self.raw_hi = np.quantile(raw, [0.001, 0.5, 0.999], axis=0)
        self.up = np.maximum(self.hi - self.med, FLOORS)
        self.down = np.maximum(self.med - self.lo, FLOORS)
        return self

    def deviations(self, raw: np.ndarray) -> np.ndarray:
        """How many 'normal spreads' each feature sits outside its range (0 = inside)."""
        v = model_view(raw)
        d = np.maximum(0.0, v - self.hi) / self.up + np.maximum(0.0, self.lo - v) / self.down
        return np.where(STAT_MASK, d, 0.0)


def stat_score(dev: np.ndarray) -> float:
    """Map the largest deviation to 0-100 (1 spread out -> 22, 3 -> 53, 6 -> 78)."""
    top = float(np.sort(dev)[-2:].mean()) if dev.any() else 0.0
    return 100.0 * (1.0 - math.exp(-top / 4.0))


@dataclass
class Identity:
    """Novel destinations seen in one window."""

    new_external: list[int] = field(default_factory=list)
    new_external_nets: list[int] = field(default_factory=list)
    new_lan: list[int] = field(default_factory=list)
    new_ports: list[int] = field(default_factory=list)
    unsolicited_inbound: list[int] = field(default_factory=list)

    @property
    def score(self) -> float:
        parts = []
        if self.new_external_nets:
            parts.append(1.0 - 0.4 ** len(self.new_external_nets))  # 1 net -> .60, 2 -> .84
        same_net = len(self.new_external) - len(self.new_external_nets)
        if same_net > 0:
            parts.append(min(0.3, 0.15 * same_net))  # CDN/pool rotation is common
        if len(self.new_lan) >= 3:
            parts.append(min(0.95, 0.5 + 0.05 * len(self.new_lan)))
        elif self.new_lan:
            parts.append(0.25)
        if self.unsolicited_inbound:
            parts.append(0.5)
        if self.new_ports and not parts:
            parts.append(0.2)
        keep = 1.0
        for p in parts:
            keep *= 1.0 - p
        return 100.0 * (1.0 - keep)


def identity(pkts: np.ndarray, ctx: Context) -> Identity:
    if len(pkts) == 0:
        return Identity()
    known = np.fromiter(ctx.known_peers, dtype=np.uint32, count=len(ctx.known_peers))
    peers = np.unique(pkts["peer"])
    new = peers[~np.isin(peers, known)]
    private = is_private(new) if len(new) else np.zeros(0, dtype=bool)
    ext = new[~private]
    nets = sorted({int(n) for n in prefix24(ext)} - ctx.known_nets) if len(ext) else []
    known_ports = np.fromiter(ctx.known_ports, dtype=np.uint16, count=len(ctx.known_ports))
    ports = np.setdiff1d(np.unique(pkts["port"]), known_ports)
    # inbound traffic from a never-seen host that the device did not contact first
    inbound = []
    for p in ext:
        mine = pkts[pkts["peer"] == p]
        if not mine[0]["out"]:
            inbound.append(int(p))
    return Identity(
        new_external=[int(p) for p in ext],
        new_external_nets=nets,
        new_lan=[int(p) for p in new[private]],
        new_ports=[int(p) for p in ports],
        unsolicited_inbound=inbound,
    )


@dataclass
class Score:
    """Everything the detector knows about one window."""

    t0: float
    threat: float
    ml: float
    stat: float
    ident: float
    features: np.ndarray
    deviations: np.ndarray
    identity: Identity
    mode: str = "protected"


def combine(*scores: float) -> float:
    keep = 1.0
    for s in scores:
        keep *= 1.0 - min(max(s, 0.0), 100.0) / 100.0
    return 100.0 * (1.0 - keep)


class DeviceDetector:
    """Learns one device's behavioral identity and scores new windows against it."""

    def __init__(self, device_id: str, seed: int = 0, trees: int = 150, memory: int = 3000):
        self.device_id = device_id
        self.seed = seed
        self.memory = memory
        self._ml_hist: deque = deque(maxlen=3)
        self._stat_hist: deque = deque(maxlen=3)
        self.ctx = Context()
        self.baseline = Baseline()
        self.forest = IsolationForest(n_estimators=trees, max_samples=512, random_state=seed,
                                      n_jobs=1)
        self.mean = np.zeros(N_FEATURES)
        self.std = np.ones(N_FEATURES)
        self.p99 = 0.0
        self.tau = 1.0
        self.fitted = False

    # -- training ----------------------------------------------------------
    def featurize(self, windows: list[tuple[float, np.ndarray]]) -> np.ndarray:
        self.ctx.reset_state()
        rows = np.array([extract(p, t0, self.ctx) for t0, p in windows])
        self.ctx.reset_state()
        return rows

    def fit(self, train: list[tuple[float, np.ndarray]],
            val: list[tuple[float, np.ndarray]]) -> DeviceDetector:
        self.ctx.learn(train)
        x_train = self.featurize(train)
        x_val = self.featurize(val)
        self.baseline.fit(x_train)
        # The forest learns the shape of *traffic*: silent windows (most of a sensor's
        # day) would otherwise make every ordinary check-in look rare.
        active = x_train[x_train[:, INDEX["pkts_total"]] > 0]
        if len(active) < 100:
            active = x_train
        view = model_view(active)
        self.mean = np.median(view, axis=0)
        self.std = np.maximum(view.std(axis=0), FLOORS)
        self.forest.set_params(max_samples=min(512, len(view)))
        self.forest.fit((view - self.mean) / self.std)
        self.fast = FastForest(self.forest)
        # Nearest-neighbour memory of normal traffic shapes (deduplicated, capped).
        z = np.unique(((view - self.mean) / self.std).round(3), axis=0)
        if len(z) > self.memory:
            z = z[np.random.default_rng(self.seed).choice(len(z), self.memory, replace=False)]
        self.memory_z = z.astype(np.float32)
        self.memory_sq = (self.memory_z.astype(np.float64) ** 2).sum(axis=1)
        val_active = x_val[x_val[:, INDEX["pkts_total"]] > 0]
        val_rows = val_active if len(val_active) >= 50 else x_val
        # held-out normal: p99 -> 0, p99.9 -> 30, rising above (both models)
        self.p99, p999 = np.quantile(self._raw_ml(val_rows), [0.99, 0.999])
        self.tau = max(float(p999 - self.p99), 1e-3) / -math.log(0.7)
        # The distance tail is estimated from held-out windows plus every training
        # window (ignoring its own copy in memory): half a day alone is too few.
        knn_cal = np.concatenate([self._raw_knn(val_rows),
                                  self._raw_knn(active, skip_self=True)])
        self.k99, k999 = np.quantile(knn_cal, [0.99, 0.999])
        self.ktau = max(float(k999 - self.k99), 1e-3) / -math.log(0.7)
        # Absorb destinations first seen in the validation period (pool rotation).
        self.ctx.learn(train + val)
        self.reset_state()
        self.fitted = True
        return self

    def _raw_ml(self, raw: np.ndarray) -> np.ndarray:
        z = (model_view(raw) - self.mean) / self.std
        return -self.fast.score_samples(z)

    def _raw_knn(self, raw: np.ndarray, skip_self: bool = False) -> np.ndarray:
        rows = np.atleast_2d(raw)
        out = np.empty(len(rows))
        for start in range(0, len(rows), 2048):  # bounded memory for calibration
            z = (model_view(rows[start:start + 2048]) - self.mean) / self.std
            d2 = ((z ** 2).sum(axis=1)[:, None] + self.memory_sq[None, :]
                  - 2.0 * z @ self.memory_z.T)
            k = min(5 + int(skip_self), d2.shape[1])
            nearest = np.sort(np.partition(np.maximum(d2, 0.0), k - 1, axis=1)[:, :k], axis=1)
            if skip_self:
                nearest = nearest[:, 1:]
            out[start:start + 2048] = np.sqrt(nearest).mean(axis=1)
        return out

    def ml_score(self, raw: np.ndarray) -> float:
        """Isolation Forest and nearest-neighbour distance; the more alarmed one wins."""
        if raw[INDEX["pkts_total"]] == 0:
            return 0.0
        r = float(self._raw_ml(raw)[0])
        s_if = 100.0 * (1.0 - math.exp(-max(0.0, r - self.p99) / self.tau))
        k = float(self._raw_knn(raw)[0])
        s_knn = 100.0 * (1.0 - math.exp(-max(0.0, k - self.k99) / self.ktau))
        return max(s_if, s_knn)

    # -- scoring -----------------------------------------------------------
    def score(self, pkts: np.ndarray, t0: float) -> Score:
        x = extract(pkts, t0, self.ctx)
        dev = self.baseline.deviations(x)
        s_stat = corroborate(self._stat_hist, stat_score(dev), strong=75.0)
        s_ml = corroborate(self._ml_hist, self.ml_score(x), strong=90.0)
        ident = identity(pkts, self.ctx)
        s_id = ident.score
        return Score(t0, combine(s_ml, s_stat, s_id), s_ml, s_stat, s_id, x, dev, ident)

    def clone(self) -> DeviceDetector:
        """A copy sharing the trained models but with its own rolling state."""
        other = copy.copy(self)
        other.ctx = copy.copy(self.ctx)
        other._ml_hist = deque(maxlen=3)
        other._stat_hist = deque(maxlen=3)
        other.reset_state()
        return other

    def reset_state(self) -> None:
        self.ctx.reset_state()
        self._ml_hist.clear()
        self._stat_hist.clear()


def corroborate(history: deque, value: float, strong: float) -> float:
    """Require moderate evidence to persist: 2 of the last 3 windows.

    Normal traffic produces the odd one-window spike; attacks last longer. Values
    at or above ``strong`` count immediately.
    """
    history.append(value)
    if value >= strong:
        return value
    if len(history) < 2:
        return 0.0
    return min(value, sorted(history)[-2])


@dataclass
class StartupGuard:
    """Protection while a device's baseline is still being learned.

    Hours 0-24: fixed safety rules (flood rate, scanning, known-bad ports).
    Hours 24-48: the statistical layer on whatever has been learned so far.
    After 48 h the full detector takes over (see ``Guardian``).
    """

    flood_pps: float = 100.0
    scan_hosts: int = 20
    bad_ports: tuple[int, ...] = (23, 2323, 3333, 4444, 5555, 6667, 7547)

    def score(self, pkts: np.ndarray, t0: float, ctx: Context) -> Score:
        x = extract(pkts, t0, ctx)
        s = 0.0
        if len(pkts):
            out = pkts[pkts["out"]]
            if len(out) / 10.0 > self.flood_pps:
                s = max(s, 90.0)
            syn = out[(out["proto"] == TCP) & ((out["flags"] & SYN) > 0)]
            if len(np.unique(syn["peer"])) >= self.scan_hosts:
                s = max(s, 80.0)
            if np.isin(syn["port"], self.bad_ports).any():
                s = max(s, 70.0)
        return Score(t0, s, 0.0, s, 0.0, x, np.zeros(N_FEATURES), Identity(), mode="startup")


def feature_index(name: str) -> int:
    return INDEX[name]
