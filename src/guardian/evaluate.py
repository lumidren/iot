"""Reproducible evaluation: GUARDIAN against a signature IDS and a generic model.

For each seed the simulated home runs for a learning period (train + held-out
validation) and then a 24-hour test day. Every device suffers each of the
eight attack scenarios once, at a random time of day, for five minutes. The
rest of the test day is normal traffic and measures false alarms.

Compared detectors (all see exactly the same windows):
  guardian      full system (ML + statistical ranges + network identity)
  ml_only       per-device Isolation Forest alone
  stat_only     per-device normal ranges alone
  identity_only never-seen destinations alone
  generic       one Isolation Forest for all devices (no per-device identity)
  signature     Snort-style rules: bad ports, flood rates (no blocklist hit,
                because the infrastructure is new: that is what zero-day means)

An alert is a window scoring 61+ (quarantine or block). Detection of an
episode = at least one alert while it runs.

Caveat that applies to every number: the traffic and the attacks are
synthetic and written by the same author as the detector. The results show
that the pipeline works and how its parts compare; they are not evidence of
real-world detection rates. The hardware testbed is the next step.
"""

from __future__ import annotations

import json
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .attacks import ADVERSARIAL, ALL_ATTACKS, ATTACKS, INTENSITY_BY_KIND, LABELS, Attack
from .detector import DeviceDetector, combine
from .devices import CAM_CLOUD, DEVICES, GATEWAY, HOME_SERVER, HUB_SYNC, PLUG_CLOUD, Home
from .net import SYN, TCP, UDP, concat

W = 10.0
DAY = 8640  # windows per day
ALERT = 61.0
RESTRICT = 31.0
DETECTORS = ["guardian", "ml_only", "stat_only", "identity_only", "generic", "signature"]

# Where an attacker would hide on each device: a destination and port it already uses.
COVER = {"plug-1": (PLUG_CLOUD[0], 443), "relay-1": (PLUG_CLOUD[0], 443),
         "hub-1": (HUB_SYNC[0], 443), "cam-1": (CAM_CLOUD[0], 443)}


def signature_score(pkts: np.ndarray) -> float:
    """A rule-based IDS of the kind shipped with Snort/Suricata community rules."""
    if len(pkts) == 0:
        return 0.0
    out = pkts[pkts["out"]]
    syn = out[(out["proto"] == TCP) & ((out["flags"] & SYN) > 0)]
    if np.isin(syn["port"], [23, 2323, 7547, 5555]).any():
        return 100.0  # telnet / TR-069 / ADB exploitation and scanning
    if np.isin(out["port"], [3333, 4444, 14444]).any():
        return 100.0  # stratum mining pools
    for proto, limit in ((TCP, 1000), (UDP, 500)):
        sel = out[out["proto"] == proto]
        if len(sel):
            _, counts = np.unique(sel["peer"], return_counts=True)
            if counts.max() >= limit:
                return 100.0  # flood towards one target
    return 0.0


@dataclass
class Record:
    device: str
    t0: float
    attack: str | None
    episode: int | None
    scores: dict[str, float]


@dataclass
class SeedResult:
    seed: int
    records: list[Record] = field(default_factory=list)
    episodes: dict[int, Attack] = field(default_factory=dict)
    latency_ms: list[float] = field(default_factory=list)
    fit_seconds: float = 0.0


def schedule(rng: np.random.Generator, start: float, hours: float) -> list[Attack]:
    """One episode of every scenario per device, at random times, never overlapping."""
    attacks = []
    slots = int(hours * 3600 // 1800)  # 30-minute slots
    for spec in DEVICES:
        chosen = rng.choice(np.arange(1, slots - 1), size=len(ALL_ATTACKS), replace=False)
        for kind, slot in zip(ALL_ATTACKS, chosen, strict=True):
            t = start + slot * 1800 + float(rng.uniform(0, 1200))
            peer, port = COVER.get(spec.id, (HOME_SERVER, 8080))
            if spec.kind == "sensor":
                peer, port = GATEWAY, 1883
            attacks.append(Attack(kind, spec.id, t, 300.0, INTENSITY_BY_KIND[spec.kind],
                                  cover_peer=peer, cover_port=port))
    return attacks


def run_seed(seed: int, train_days: float = 1.5, val_days: float = 0.5,
             test_hours: float = 24.0, log=print) -> SeedResult:
    home = Home(seed=seed)
    n_train, n_val = int(train_days * DAY), int(val_days * DAY)
    windows: dict[str, list[tuple[float, np.ndarray]]] = {d.id: [] for d in DEVICES}
    t_start = time.perf_counter()
    for w in range(n_train + n_val):
        for dev, pkts in home.window(w * W, (w + 1) * W).items():
            windows[dev].append((w * W, pkts))
    log(f"  seed {seed}: simulated {train_days + val_days:.1f} learning days "
        f"in {time.perf_counter() - t_start:.0f}s")

    t_fit = time.perf_counter()
    detectors = {}
    for spec in DEVICES:
        ws = windows[spec.id]
        detectors[spec.id] = DeviceDetector(spec.id, seed=seed).fit(ws[:n_train], ws[n_train:])
    pooled_train = [w for spec in DEVICES for w in windows[spec.id][:n_train]]
    pooled_val = [w for spec in DEVICES for w in windows[spec.id][n_train:]]
    generic_model = DeviceDetector("generic", seed=seed).fit(pooled_train, pooled_val)
    generic = {spec.id: generic_model.clone() for spec in DEVICES}
    del windows, pooled_train, pooled_val
    result = SeedResult(seed, fit_seconds=time.perf_counter() - t_fit)
    log(f"  seed {seed}: trained 8 device models + generic in {result.fit_seconds:.0f}s")

    rng = np.random.default_rng(seed + 100)
    start = (n_train + n_val) * W
    attacks = schedule(rng, start, test_hours)
    result.episodes = dict(enumerate(attacks))
    by_device: dict[str, list[tuple[int, Attack]]] = {}
    for i, a in result.episodes.items():
        by_device.setdefault(a.device, []).append((i, a))

    t_test = time.perf_counter()
    n_test = int(test_hours * 3600 / W)
    for w in range(n_test):
        t0 = start + w * W
        base = home.window(t0, t0 + W)
        for spec in DEVICES:
            active = [(i, a) for i, a in by_device[spec.id] if a.overlaps(t0, t0 + W)]
            parts = [base[spec.id]]
            for _, a in active:
                parts += a.emit(t0, t0 + W, rng)
            pkts = concat(parts)
            tic = time.perf_counter()
            s = detectors[spec.id].score(pkts, t0)
            result.latency_ms.append((time.perf_counter() - tic) * 1e3)
            g = generic[spec.id].score(pkts, t0)
            scores = {
                "guardian": s.threat, "ml_only": s.ml, "stat_only": s.stat,
                "identity_only": s.ident, "generic": combine(g.ml, g.stat),
                "signature": signature_score(pkts),
            }
            kind, ep = (active[0][1].kind, active[0][0]) if active else (None, None)
            result.records.append(Record(spec.id, t0, kind, ep, scores))
    log(f"  seed {seed}: scored {n_test * len(DEVICES):,} test windows "
        f"in {time.perf_counter() - t_test:.0f}s")
    return result


def summarize(results: list[SeedResult]) -> dict:
    summary: dict = {"detectors": {}, "per_attack": {}, "per_device_fp": {}}
    # index records once: normal sequences per (seed, device) and rows per episode
    normal_seq: dict[tuple[int, str], list[Record]] = {}
    episode_rows: dict[tuple[int, int], list[Record]] = {}
    for res in results:
        for r in res.records:
            if r.attack is None:
                normal_seq.setdefault((res.seed, r.device), []).append(r)
            else:
                episode_rows.setdefault((res.seed, r.episode), []).append(r)

    for det in DETECTORS:
        normal = np.array([r.scores[det] for seq in normal_seq.values() for r in seq])
        alerts_per_day = []
        for seq in normal_seq.values():
            flags = [r.scores[det] >= ALERT for r in seq]
            bursts = sum(1 for i, a in enumerate(flags) if a and (i == 0 or not flags[i - 1]))
            alerts_per_day.append(bursts / (len(flags) / DAY))
        summary["detectors"][det] = {
            "false_alert_rate": float(np.mean(normal >= ALERT)),
            "restrict_rate": float(np.mean(normal >= RESTRICT)),
            "false_alerts_per_device_day": float(np.mean(alerts_per_day)),
            "normal_windows": int(len(normal)),
        }
        for kind in ALL_ATTACKS:
            detected, recall, ttd = [], [], []
            for res in results:
                for ep, attack in res.episodes.items():
                    if attack.kind != kind:
                        continue
                    rows = episode_rows.get((res.seed, ep), [])
                    hits = [r for r in rows if r.scores[det] >= ALERT]
                    detected.append(bool(hits))
                    recall.append(len(hits) / max(len(rows), 1))
                    if hits:
                        ttd.append(max(0.0, hits[0].t0 + W - attack.start))
            summary["per_attack"].setdefault(kind, {})[det] = {
                "episodes": len(detected),
                "detected": int(sum(detected)),
                "detection_rate": float(np.mean(detected)),
                "window_recall": float(np.mean(recall)),
                "median_seconds_to_detect": float(np.median(ttd)) if ttd else None,
            }
    for det in DETECTORS:
        agg = summary["detectors"][det]
        agg["detection_rate_headline"] = float(np.mean(
            [summary["per_attack"][k][det]["detection_rate"] for k in ATTACKS]))
        agg["detection_rate_adversarial"] = float(np.mean(
            [summary["per_attack"][k][det]["detection_rate"] for k in ADVERSARIAL]))
    for spec in DEVICES:
        normal = np.array([r.scores["guardian"] for (_, dev), seq in normal_seq.items()
                           if dev == spec.id for r in seq])
        summary["per_device_fp"][spec.id] = {
            "false_alert_rate": float(np.mean(normal >= ALERT)),
            "restrict_rate": float(np.mean(normal >= RESTRICT)),
        }
    lat = np.concatenate([np.array(res.latency_ms) for res in results])
    summary["latency_ms"] = {"p50": float(np.percentile(lat, 50)),
                             "p99": float(np.percentile(lat, 99)),
                             "max": float(lat.max())}
    summary["fit_seconds_per_seed"] = float(np.mean([r.fit_seconds for r in results]))
    return summary


def to_markdown(summary: dict, config: dict) -> str:
    pct = lambda v: f"{v * 100:.1f}%"  # noqa: E731
    fine = lambda v: f"{v * 100:.3f}%"  # noqa: E731  (false-alarm rates are tiny)
    names = {"guardian": "GUARDIAN", "ml_only": "ML only", "stat_only": "Ranges only",
             "identity_only": "Identity only", "generic": "Generic model",
             "signature": "Signature rules"}
    lines = [
        "# Evaluation results",
        "",
        f"Generated by `guardian eval` on {config['date']} ({config['machine']}).",
        f"Seeds: {config['seeds']}. Per seed: {config['learning_days']} days of learning "
        f"({config['val_days']} held out for calibration), then a {config['test_hours']:.0f}-hour "
        "test day. Each of the 8 devices suffers each of the 8 scenarios once "
        "(5 minutes, random time of day). Alert threshold: threat >= 61 (quarantine).",
        "",
        "> All traffic and attacks are simulated, and the simulator and the detector were "
        "written by the same person. These numbers show the pipeline works and how its parts "
        "compare. They are not real-world detection rates.",
        "",
        "## Detection rate per scenario (episodes with at least one alert)",
        "",
        "| Scenario | " + " | ".join(names[d] for d in DETECTORS) + " |",
        "|---|" + "---:|" * len(DETECTORS),
    ]
    for kind in ALL_ATTACKS:
        row = summary["per_attack"][kind]
        lines.append(f"| {LABELS[kind]} | "
                     + " | ".join(pct(row[d]["detection_rate"]) for d in DETECTORS) + " |")
    lines.append("| **Average, 6 headline scenarios** | " + " | ".join(
        f"**{pct(summary['detectors'][d]['detection_rate_headline'])}**" for d in DETECTORS)
        + " |")
    lines += [
        "",
        "## False alarms on normal traffic",
        "",
        "| Detector | Windows alerting (61+) | Windows restricted (31+) "
        "| False alerts per device per day |",
        "|---|---:|---:|---:|",
    ]
    for d in DETECTORS:
        s = summary["detectors"][d]
        lines.append(f"| {names[d]} | {fine(s['false_alert_rate'])} | {fine(s['restrict_rate'])} "
                     f"| {s['false_alerts_per_device_day']:.2f} |")
    lines += [
        "",
        "## GUARDIAN: speed and depth per scenario",
        "",
        "| Scenario | Detected | Windows flagged during attack | Median time to first alert |",
        "|---|---:|---:|---:|",
    ]
    for kind in ALL_ATTACKS:
        g = summary["per_attack"][kind]["guardian"]
        ttd = g["median_seconds_to_detect"]
        lines.append(f"| {LABELS[kind]} | {g['detected']}/{g['episodes']} "
                     f"| {pct(g['window_recall'])} | {'-' if ttd is None else f'{ttd:.0f} s'} |")
    lines += [
        "",
        "## GUARDIAN false alarms per device",
        "",
        "| Device | Windows alerting (61+) | Windows restricted (31+) |",
        "|---|---:|---:|",
    ]
    for dev, s in summary["per_device_fp"].items():
        lines.append(f"| {dev} | {fine(s['false_alert_rate'])} | {fine(s['restrict_rate'])} |")
    lat = summary["latency_ms"]
    lines += [
        "",
        "## Cost",
        "",
        f"- Scoring one device-window (features + all three layers; silent windows are "
        f"cheap): p50 {lat['p50']:.2f} ms, "
        f"p99 {lat['p99']:.2f} ms, max {lat['max']:.1f} ms on this machine.",
        f"- Training all eight device models plus the generic model: "
        f"{summary['fit_seconds_per_seed']:.0f} s per seed.",
        "",
    ]
    return "\n".join(lines)


def main(seeds: list[int], out_dir: Path, test_hours: float = 24.0, log=print) -> dict:
    results = []
    for seed in seeds:
        results.append(run_seed(seed, test_hours=test_hours, log=log))
    summary = summarize(results)
    config = {"seeds": seeds, "learning_days": 2.0, "val_days": 0.5, "test_hours": test_hours,
              "date": time.strftime("%Y-%m-%d"),
              "machine": f"{platform.system()} {platform.machine()}, Python "
                         f"{platform.python_version()}"}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps({"config": config, "summary": summary},
                                                     indent=2))
    (out_dir / "results.md").write_text(to_markdown(summary, config))
    return summary
