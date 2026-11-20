# Architecture

How a packet becomes a decision, module by module, and why each design choice
was made. Read this before changing the detector or before defending the
project in front of a jury.

## Data flow

```
packets ──► 10 s window per device ──► 60 features ──┬─► normal ranges ──┐
 (gateway      (capture.py or            (features.py)│                   │
  or simulator) devices.py)                           ├─► ML layer ───────┼─► threat 0-100 ─► tier ─► nftables
                                                      │                   │   (detector.py)   (response.py)
                                     packets ─────────┴─► network identity┘         │
                                                                                    ▼
                                                                    explanation (explain.py)
```

`engine.py` runs this loop for every device and window, owns the learning
phases, the response policy, drift reviews and the owner's "release" button.

## Modules

| Module | Responsibility | Key idea |
|---|---|---|
| `net.py` | Packet record (`PACKET` dtype) and address helpers | Only metadata a gateway sees: time, direction, size, protocol, peer, port, TCP flags |
| `devices.py` | Eight simulated devices built from small behaviors | Periodic publishes, random events, streaming sessions, nightly jobs; rotating cloud addresses like real CDNs |
| `attacks.py` | Six attack scenarios and three adversarial ones | Adversarial ones are designed to look normal and are reported separately |
| `features.py` | 60 features per window plus each device's `Context` | Network-identity features compare against what the device is known to talk to |
| `detector.py` | Three layers combined into one score | See "Detection" below |
| `fastforest.py` | Flattened Isolation Forest | Same scores as scikit-learn, about 300x faster, so a Pi can score every device every 10 s |
| `explain.py` | Reasons, attack name, recommended actions | Every number cited comes from the scored window and the device's own baseline |
| `response.py` | Tiers, cool-down, nftables rules, enforcers | Dry run by default; real enforcement needs Linux, `nft` and `GUARDIAN_ENFORCE=1` |
| `drift.py` | Daily drift review | Small drift absorbed; bigger drift asks the owner; nothing is relearned without a yes |
| `store.py` | Save and load trained models | Plain arrays, `allow_pickle=False`, feature-version check |
| `capture.py` | pcap reader and writer | No dependencies; Ethernet, raw IP, VLAN, both byte orders, ns timestamps |
| `evaluate.py` | Reproducible comparison | GUARDIAN vs each layer alone, a generic model and signature rules |
| `server.py`, `web/` | Live simulated home and dashboard | FastAPI + server-sent events; vanilla JS, no build step, no CDN |

## Detection

Three layers, each answering a different question:

1. **Normal ranges** (`Baseline`): is any single number outside what this
   device has ever done? Range = 0.1st-99.9th percentile of the learning period,
   measured in "spreads" beyond the range. Novelty features are left to layer 3
   so the same evidence is not counted twice.
2. **ML layer**: is the *combination* of numbers unlike anything learned?
   - Isolation Forest, trained only on windows with traffic. On sparse sensors
     most windows are empty; training on them made ordinary check-ins look rare
     and attacks score *below* the normal tail (separation AUC 0.82-0.93 before,
     0.97-0.99 after).
   - Nearest-neighbour distance to remembered normal windows. A forest cannot
     see values beyond its training range; a distance keeps growing.
   - Calibrated on held-out windows: their 99th percentile scores 0, the 99.9th
     scores 30.
3. **Network identity**: never-seen internet networks (/24), never-seen local
   hosts, unsolicited inbound contacts, new ports. Rule-based on purpose: "this
   plug contacted a network it has never used" is evidence a person can check.
   New addresses inside known networks score low, because CDNs and NTP pools rotate.

The layers are combined with a noisy-OR. Moderate ML and range evidence has to
appear in 2 of the last 3 windows (corroboration), and the ML layer never acts
on one window alone; strong range violations and identity evidence count
immediately.

## Response

| Threat | Tier | Effect | Lifts |
|---|---|---|---|
| 0-30 | Monitor | Logging only | - |
| 31-60 | Restrict | Half bandwidth, new internet destinations dropped | After 5 quiet minutes |
| 61-85 | Quarantine | Only the local broker and DNS | After 5 quiet minutes, one step at a time |
| 86-100 | Block | Everything dropped | Only when the owner releases it |

"That was me" releases the device and adds the destinations from its last
alert to its known set. "Release, keep watching" releases without learning.

## Learning phases

| Age of device | Protection |
|---|---|
| 0-24 h | Fixed rules: flood rate, scanning, known-bad ports |
| 24-48 h | Rules plus learned normal ranges |
| 48 h+ | Full detector (75% of the period trains, 25% calibrates) |

Saved models skip all of this after a restart.

## Decisions worth knowing

- **Per-device models, not one model.** A camera uploading megabytes is normal;
  a plug doing it is not. The generic baseline in the evaluation shows the cost
  of ignoring this (it misses every beacon).
- **Metadata only.** It works on encrypted traffic, and it is also the limit:
  attacks that keep to a device's usual destinations and volumes can pass.
- **Bounded features.** Any feature whose value depends on when monitoring
  started (an ever-growing counter) makes restarts look like anomalies. The
  activity streak is capped at one hour for that reason.
- **No silent adaptation.** An attacker who persists also looks like "drift",
  so only the owner can approve a relearn.
