"""Plain-language explanations for every decision.

An alert says which behavior changed, what is normal for this device, what was
seen instead, how severe each finding is, what the attack most likely is, and
what to do about it. Every number in an explanation comes from the window that
was scored and the device's own baseline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np

from .detector import DeviceDetector, Score
from .features import FEATURES, INDEX
from .net import ip_str

MINING_PORTS = {3333, 4444, 5555, 7777, 14444, 45700}


@dataclass
class Reason:
    title: str
    detail: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    normal: str = ""
    observed: str = ""


@dataclass
class Explanation:
    device: str
    threat: float
    likely_attack: str
    reasons: list[Reason] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.reasons:
            return "Behaving like itself."
        top = "; ".join(r.title.lower() for r in self.reasons[:3])
        return f"{self.likely_attack}: {top}."

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary
        return d

    def render(self) -> str:
        lines = [f"{self.device.upper()} - threat {self.threat:.0f}/100",
                 f"Likely: {self.likely_attack}", "", "Why:"]
        for i, r in enumerate(self.reasons, 1):
            lines.append(f"  {i}. {r.title} [{r.severity}]")
            if r.normal:
                lines.append(f"     Normal:   {r.normal}")
            if r.observed:
                lines.append(f"     Detected: {r.observed}")
            if r.detail:
                lines.append(f"     {r.detail}")
        if self.actions:
            lines += ["", "Recommended:"] + [f"  - {a}" for a in self.actions]
        return "\n".join(lines)


def _fmt(value: float, unit: str) -> str:
    if unit == "bytes":
        for scale, suffix in ((1e6, "MB"), (1e3, "KB")):
            if value >= scale:
                return f"{value / scale:.1f} {suffix}"
        return f"{value:.0f} B"
    if unit == "ratio":
        return f"{value * 100:.0f}%"
    if unit == "seconds":
        return f"{value:.1f} s"
    if unit in ("bits",):
        return f"{value:.2f} bits"
    return f"{value:,.0f} {unit}".strip()


def _severity(dev: float) -> str:
    if dev >= 6:
        return "CRITICAL"
    if dev >= 3:
        return "HIGH"
    if dev >= 1:
        return "MEDIUM"
    return "LOW"


def classify(score: Score) -> str:
    """Name the most likely attack from the shape of the evidence."""
    x = score.features
    ident = score.identity
    f = {name: x[INDEX[name]] for name in INDEX}
    ports = set(ident.new_ports)
    if f["pkts_out"] >= 1000 and f["n_peers"] <= 5 and (f["syn_ratio"] > 0.3 or
                                                        f["frac_udp"] > 0.3):
        return "Flooding (device used in a DDoS)"
    if len(ident.new_lan) >= 8 or (f["n_conn_targets"] >= 10 and f["failed_conn_ratio"] > 0.5):
        return "Network scanning (worm-style propagation)"
    if ports & MINING_PORTS:
        return "Cryptomining pool connection"
    if ident.unsolicited_inbound and (ident.new_external_nets or f["n_dns_queries"] >= 3):
        return "Exploitation followed by command-and-control"
    if f["bytes_out"] >= 100_000 and f["upload_frac"] > 0.8 and ident.new_external:
        return "Data exfiltration"
    if ident.new_external_nets:
        return "Command-and-control communication"
    if len(ident.new_lan) >= 3:
        return "Lateral movement on the home network"
    if f["bytes_out"] >= 100_000 and f["upload_frac"] > 0.8:
        return "Unusual upload (possible exfiltration)"
    return "Unusual behavior"


def explain(score: Score, detector: DeviceDetector | None = None,
            device_name: str = "device") -> Explanation:
    reasons: list[Reason] = []
    ident = score.identity

    if ident.new_external_nets:
        hosts = ", ".join(ip_str(p) for p in ident.new_external[:3])
        nets = ", ".join(ip_str(n) + "/24" for n in ident.new_external_nets[:3])
        reasons.append(Reason(
            "Unknown destination", f"Network {nets} was never used in the learning period.",
            "CRITICAL" if len(ident.new_external_nets) > 1 or score.threat >= 86 else "HIGH",
            normal="Only its usual cloud and local services",
            observed=f"{hosts}"))
    if ident.unsolicited_inbound:
        hosts = ", ".join(ip_str(p) for p in ident.unsolicited_inbound[:3])
        reasons.append(Reason("Unsolicited inbound connection",
                              "A never-seen internet host started talking to the device first.",
                              "HIGH", observed=hosts))
    if len(ident.new_lan) >= 3:
        reasons.append(Reason(
            "Contacting other home devices",
            "Probing many local addresses is how IoT worms spread.",
            "CRITICAL" if len(ident.new_lan) >= 10 else "HIGH",
            normal="Talks only to the gateway and home server",
            observed=f"{len(ident.new_lan)} local hosts it never contacted before"))

    dev = score.deviations
    # Volume, destination and connection findings read better than packet-gap
    # statistics, so timing features are only cited when nothing else stands out.
    timing = np.array([f.group == "timing" for f in FEATURES])
    rank = np.where(timing, dev * 0.25, dev)
    for i in np.argsort(rank)[::-1][:3]:
        if dev[i] < 1.0 or (timing[i] and len(reasons) >= 2):
            continue
        feat = FEATURES[i]
        value = score.features[i]
        if detector is not None:
            hi = detector.baseline.raw_hi[i]
            lo = detector.baseline.raw_lo[i]
            above = value > hi
            normal = (f"up to {_fmt(hi, feat.unit)} per 10 s" if above
                      else f"at least {_fmt(lo, feat.unit)} per 10 s")
            if feat.unit in ("ratio", "bits", "seconds"):
                normal = f"between {_fmt(lo, feat.unit)} and {_fmt(hi, feat.unit)}"
            ratio = ""
            if above and hi > 0 and feat.unit not in ("ratio", "bits", "seconds"):
                ratio = f" ({value / hi:.0f}x the usual maximum)" if value / hi >= 2 else ""
        else:
            normal, ratio, above = "", "", True
        title = feat.label + (" spike" if above else " drop")
        reasons.append(Reason(title, "", _severity(dev[i]), normal=normal,
                              observed=_fmt(value, feat.unit) + ratio))

    usual = score.features[INDEX["hour_activity"]]
    active = score.features[INDEX["pkts_total"]] > 0
    if active and usual < 0.1 and score.threat >= 31:
        hour = (score.t0 / 3600.0) % 24
        reasons.append(Reason(
            "Unusual activity time", "", "HIGH" if usual < 0.02 else "MEDIUM",
            normal=f"active in {usual * 100:.0f}% of windows at this hour",
            observed=f"traffic at {int(hour):02d}:{int((hour % 1) * 60):02d}"))

    if score.ml >= 50 and len(reasons) < 2:
        reasons.append(Reason(
            "Overall pattern unlike its baseline",
            "The combination of features is unlike any window seen while learning, "
            "even though no single number is extreme.", _severity(score.ml / 15)))

    likely = classify(score) if reasons else "Normal"
    return Explanation(device_name, round(score.threat, 1), likely, reasons,
                       recommend(likely, score.threat))


def recommend(likely: str, threat: float) -> list[str]:
    if threat < 31:
        return []
    actions = []
    if threat >= 61:
        actions.append("Keep the device isolated until it is checked")
    if "scanning" in likely or "Lateral" in likely:
        actions.append("Check the other devices on the network for the same behavior")
    if threat >= 61:
        actions += ["Factory reset the device", "Install the latest firmware before reconnecting",
                    "Change its default or shared passwords"]
    else:
        actions.append("Watch the device; GUARDIAN will escalate if this continues")
    return actions
