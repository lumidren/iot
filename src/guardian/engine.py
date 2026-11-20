"""The gateway engine: one place that turns traffic windows into decisions.

For every device and every 10-second window GUARDIAN:
  1. scores the window (startup rules while learning, full detector after),
  2. picks a response tier and, when it changes, enforces it,
  3. explains anything above "monitor" in plain language,
  4. logs the decision.

A device moves through three phases (the hybrid startup from the design):
  learning-rules   0 to ``stats_after``: fixed safety rules only
  learning-ranges  ``stats_after`` to ``learn_after``: rules + learned normal ranges
  protected        after ``learn_after``: full per-device detector
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .detector import Baseline, DeviceDetector, Score, StartupGuard, combine, stat_score
from .devices import GATEWAY, DeviceSpec
from .explain import Explanation, explain
from .features import INDEX, Context, extract
from .net import ip_str, is_private, prefix24
from .response import TIER_EFFECT, Action, DryRunEnforcer, ResponsePolicy, Tier, nft_rules

HOUR = 3600.0


@dataclass
class Event:
    t: float
    device: str
    threat: float
    tier: Tier
    mode: str
    ml: float
    stat: float
    ident: float
    explanation: Explanation | None = None
    action: Action | None = None

    def to_dict(self) -> dict:
        return {
            "t": self.t, "device": self.device, "threat": round(self.threat, 1),
            "tier": self.tier.name, "mode": self.mode,
            "components": {"ml": round(self.ml, 1), "stat": round(self.stat, 1),
                           "identity": round(self.ident, 1)},
            "explanation": self.explanation.to_dict() if self.explanation else None,
            "action": self.action.to_dict() if self.action else None,
        }


@dataclass
class DeviceRuntime:
    spec: DeviceSpec
    first_seen: float | None = None
    windows: list[tuple[float, np.ndarray]] = field(default_factory=list)
    detector: DeviceDetector | None = None
    ranges: Baseline | None = None
    ranges_ctx: Context | None = None
    last_score: Score | None = None
    last_alert: Score | None = None

    def phase(self, t: float, stats_after: float, learn_after: float) -> str:
        if self.detector is not None:
            return "protected"
        age = 0.0 if self.first_seen is None else t - self.first_seen
        if age >= stats_after:
            return "learning-ranges"
        return "learning-rules"


class Guardian:
    def __init__(self, specs: list[DeviceSpec], *, stats_after: float = 24 * HOUR,
                 learn_after: float = 48 * HOUR, enforcer: DryRunEnforcer | None = None,
                 policy: ResponsePolicy | None = None, gateway: int = GATEWAY, seed: int = 0):
        self.devices = {s.id: DeviceRuntime(s) for s in specs}
        self.stats_after = stats_after
        self.learn_after = learn_after
        self.enforcer = enforcer or DryRunEnforcer()
        self.policy = policy or ResponsePolicy()
        self.gateway = gateway
        self.guard = StartupGuard()
        self.seed = seed
        self.log: list[Event] = []

    # -- learning ----------------------------------------------------------
    def bootstrap(self, history: dict[str, list[tuple[float, np.ndarray]]],
                  val_fraction: float = 0.25) -> None:
        """Train every device at once from recorded history (skips the learning phases)."""
        for dev_id, windows in history.items():
            rt = self.devices[dev_id]
            cut = int(len(windows) * (1 - val_fraction))
            rt.detector = DeviceDetector(dev_id, seed=self.seed).fit(windows[:cut],
                                                                    windows[cut:])
            rt.first_seen = windows[0][0] if windows else 0.0
            rt.windows = []

    def _advance_learning(self, rt: DeviceRuntime, t0: float) -> None:
        phase = rt.phase(t0, self.stats_after, self.learn_after)
        age = 0.0 if rt.first_seen is None else t0 - rt.first_seen
        if phase == "learning-ranges" and rt.ranges is None and rt.windows:
            ctx = Context()
            ctx.learn(rt.windows)
            rows = np.array([extract(p, t, ctx) for t, p in rt.windows])
            ctx.reset_state()
            rt.ranges, rt.ranges_ctx = Baseline().fit(rows), ctx
        if age >= self.learn_after and rt.detector is None and len(rt.windows) >= 40:
            cut = int(len(rt.windows) * 0.75)
            rt.detector = DeviceDetector(rt.spec.id, seed=self.seed).fit(rt.windows[:cut],
                                                                        rt.windows[cut:])
            rt.windows, rt.ranges, rt.ranges_ctx = [], None, None

    # -- scoring -----------------------------------------------------------
    def _score(self, rt: DeviceRuntime, pkts: np.ndarray, t0: float) -> Score:
        if rt.detector is not None:
            return rt.detector.score(pkts, t0)
        rt.windows.append((t0, pkts))
        ctx = rt.ranges_ctx or Context()
        s = self.guard.score(pkts, t0, ctx)
        if rt.ranges is not None:
            dev = rt.ranges.deviations(s.features)
            ranges = stat_score(dev)
            s = Score(t0, combine(s.threat, ranges), 0.0, ranges, 0.0, s.features, dev,
                      s.identity, mode="learning-ranges")
        else:
            s.mode = "learning-rules"
        return s

    def observe(self, t0: float, windows: dict[str, np.ndarray]) -> list[Event]:
        """Process one 10-second window for every device. Returns events worth showing."""
        out: list[Event] = []
        for dev_id, pkts in windows.items():
            rt = self.devices.get(dev_id)
            if rt is None:
                continue
            if rt.first_seen is None:
                rt.first_seen = t0
            self._advance_learning(rt, t0)
            s = self._score(rt, pkts, t0)
            rt.last_score = s
            change = None if self.policy.observe_only else self.policy.decide(dev_id, t0,
                                                                              s.threat)
            tier = self.policy.state(dev_id).tier
            exp = None
            if s.threat >= 31:
                exp = explain(s, rt.detector, rt.spec.name)
                rt.last_alert = s
            action = self._enforce(rt, t0, change, exp) if change else None
            event = Event(t0, dev_id, s.threat, tier, s.mode, s.ml, s.stat, s.ident, exp, action)
            if exp is not None or action is not None:
                self.log.append(event)
                out.append(event)
        return out

    # -- response ----------------------------------------------------------
    def _allowed(self, rt: DeviceRuntime) -> list[int]:
        ctx = rt.detector.ctx if rt.detector else (rt.ranges_ctx or Context())
        peers = [p for p in sorted(ctx.known_peers) if not is_private(p)]
        return peers[:32]

    def _rate(self, rt: DeviceRuntime) -> int:
        if rt.detector is None:
            return 50_000
        peak = rt.detector.baseline.raw_hi[INDEX["bytes_total"]] / 10.0
        return int(max(peak * 0.5, 2_000))

    def _enforce(self, rt: DeviceRuntime, t0: float, change: tuple[Tier, Tier],
                 exp: Explanation | None) -> Action:
        before, after = change
        if after < before:
            minutes = self.policy.cooldown_windows * 10 / 60
            reason = f"Nothing suspicious for {minutes:.0f} minutes: stepping down to " \
                     f"{after.label}"
        else:
            reason = exp.summary if exp is not None else TIER_EFFECT[after]
        cmds = nft_rules(rt.spec.address, after, gateway=self.gateway,
                         allowed=self._allowed(rt), rate_bytes=self._rate(rt))
        action = Action(t0, rt.spec.id, before, after, reason, cmds)
        self.enforcer.apply(action)
        return action

    def release(self, dev_id: str, t0: float, trust: bool = True) -> Event | None:
        """User override: lift the device's restrictions and, if trusted, learn from it."""
        rt = self.devices[dev_id]
        change = self.policy.release(dev_id, t0)
        if trust and rt.last_alert is not None and rt.detector is not None:
            ctx = rt.detector.ctx
            ident = rt.last_alert.identity
            for p in ident.new_external + ident.new_lan:
                ctx.known_peers.add(int(p))
                if not is_private(p):
                    ctx.known_nets.add(int(prefix24(p)))
            ctx.known_ports.update(ident.new_ports)
        rt.last_alert = None
        if change is None:
            return None
        action = Action(t0, dev_id, change[0], change[1],
                        "Released by user" + (" and marked as normal" if trust else ""),
                        nft_rules(rt.spec.address, Tier.MONITOR, gateway=self.gateway,
                                  allowed=[], rate_bytes=0))
        self.enforcer.apply(action)
        event = Event(t0, dev_id, 0.0, Tier.MONITOR, "protected", 0, 0, 0, None, action)
        self.log.append(event)
        return event

    def status(self, t0: float) -> list[dict]:
        rows = []
        for dev_id, rt in self.devices.items():
            st = self.policy.state(dev_id)
            s = rt.last_score
            rows.append({
                "id": dev_id, "name": rt.spec.name, "kind": rt.spec.kind,
                "hardware": rt.spec.hardware, "address": ip_str(rt.spec.address),
                "phase": rt.phase(t0, self.stats_after, self.learn_after),
                "tier": st.tier.name, "tier_since": st.since,
                "effect": TIER_EFFECT[st.tier],
                "threat": round(s.threat, 1) if s else 0.0,
                "components": {"ml": round(s.ml, 1), "stat": round(s.stat, 1),
                               "identity": round(s.ident, 1)} if s else None,
                "packets": int(s.features[INDEX["pkts_total"]]) if s else 0,
                "bytes": int(s.features[INDEX["bytes_total"]]) if s else 0,
            })
        return rows
