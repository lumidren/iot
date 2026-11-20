"""Concept drift: noticing that a device has legitimately changed.

Devices change: a firmware update adds a cloud endpoint, the owner moves a
camera, a hub gets a new sensor. A detector that never adapts keeps raising
alerts; one that adapts silently would also learn an attacker's behavior. The
rule from the design is in between, reviewed once per period:

  drift < 10%    small:    absorb rotated addresses inside known networks
  10% - 30%      moderate: ask the owner "did you change something?"
  > 30%          large:    ask "was this a firmware update?"

Drift is the share of a device's active windows in the period that sat outside
its normal behavior (any layer above zero). Nothing is relearned without the
owner's yes: an attacker who persists also looks like drift, which is exactly
why the owner is asked instead of the model adapting by itself.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

import numpy as np

from .detector import Score
from .features import INDEX
from .net import is_private, prefix24

SMALL = 0.10
LARGE = 0.30


@dataclass
class Notice:
    device: str
    t: float
    level: str  # "moderate" or "large"
    drift: float
    question: str
    new_destinations: int

    def to_dict(self) -> dict:
        return {"device": self.device, "t": self.t, "level": self.level,
                "drift": round(self.drift, 3), "question": self.question,
                "new_destinations": self.new_destinations}


@dataclass
class DriftMonitor:
    """Per-device drift bookkeeping for one review period."""

    review_windows: int = 8640  # one day of 10-second windows
    buffer_windows: int = 4320  # recent traffic kept for an approved relearn (12 h)
    active: int = 0
    unusual: int = 0
    seen: int = 0
    rotated: Counter = field(default_factory=Counter)
    new_peers: Counter = field(default_factory=Counter)
    buffer: deque = field(default_factory=deque)

    def __post_init__(self) -> None:
        self.buffer = deque(maxlen=self.buffer_windows)

    def record(self, t0: float, pkts: np.ndarray, score: Score) -> None:
        self.seen += 1
        self.buffer.append((t0, pkts))
        if score.features[INDEX["pkts_total"]] == 0:
            return
        self.active += 1
        if score.ml > 0 or score.stat > 0 or score.ident > 0:
            self.unusual += 1
        if score.threat < 31:  # only benign-looking windows may teach anything
            new_nets = set(score.identity.new_external_nets)
            for p in score.identity.new_external:
                if int(prefix24(p)) not in new_nets and not is_private(p):
                    self.rotated[int(p)] += 1
        for p in score.identity.new_external:
            self.new_peers[int(p)] += 1

    @property
    def drift(self) -> float:
        return self.unusual / self.active if self.active else 0.0

    def due(self) -> bool:
        return self.seen >= self.review_windows

    def review(self, device: str, t: float, known_peers: set[int]) -> Notice | None:
        """Close the period. Small drift is absorbed; bigger drift becomes a question."""
        drift = self.drift
        notice = None
        if drift < SMALL:
            for peer, count in self.rotated.items():
                if count >= 3:
                    known_peers.add(peer)
        elif drift < LARGE:
            notice = Notice(device, t, "moderate", drift,
                            "This device has been behaving differently for a while. "
                            "Did you change its settings or how you use it?",
                            len(self.new_peers))
        else:
            notice = Notice(device, t, "large", drift,
                            "This device's behavior changed a lot. Was it a firmware "
                            "update or a new setup? If yes, GUARDIAN will relearn it.",
                            len(self.new_peers))
        self.active = self.unusual = self.seen = 0
        self.rotated.clear()
        self.new_peers.clear()
        return notice
