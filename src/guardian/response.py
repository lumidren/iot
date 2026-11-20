"""Graduated response: monitor, restrict, quarantine, block.

Low-confidence detections cost the user little (extra logging, a bandwidth
cap); only high-confidence ones cut a device off. Quarantine and restriction
lift on their own after a quiet period; a full block waits for the user.
Every enforcement step is expressed as nftables rules for the Linux gateway.
By default the rules are only recorded (dry run); they are applied only when
explicitly enabled on a Linux host.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import IntEnum

from .net import ip_str


class Tier(IntEnum):
    MONITOR = 0
    RESTRICT = 1
    QUARANTINE = 2
    BLOCK = 3

    @property
    def label(self) -> str:
        return self.name.title()


TIER_FLOORS = {Tier.MONITOR: 0.0, Tier.RESTRICT: 31.0, Tier.QUARANTINE: 61.0, Tier.BLOCK: 86.0}

TIER_EFFECT = {
    Tier.MONITOR: "Enhanced logging only",
    Tier.RESTRICT: "Bandwidth limited to half its normal peak, new internet destinations blocked",
    Tier.QUARANTINE: "Isolated: may only reach the local broker and DNS",
    Tier.BLOCK: "Completely cut off until you release it",
}


def tier_for(threat: float) -> Tier:
    for tier in (Tier.BLOCK, Tier.QUARANTINE, Tier.RESTRICT):
        if threat >= TIER_FLOORS[tier]:
            return tier
    return Tier.MONITOR


def nft_rules(device_ip: int, tier: Tier, *, gateway: int, allowed: list[int],
              rate_bytes: int) -> list[str]:
    """nftables commands that put one device into one tier."""
    dev = ip_str(device_ip)
    gw = ip_str(gateway)
    chain = f"dev_{dev.replace('.', '_')}"
    base = [
        "add table inet guardian",
        "add chain inet guardian forward { type filter hook forward priority -10; }",
        "add chain inet guardian input { type filter hook input priority -10; }",
        f"add chain inet guardian {chain}",
        f"flush chain inet guardian {chain}",
    ]
    jump = [f"add rule inet guardian forward ip saddr {dev} jump {chain}",
            f"add rule inet guardian input ip saddr {dev} jump {chain}"]
    if tier == Tier.MONITOR:
        return base + [f"add rule inet guardian {chain} counter accept"]
    if tier == Tier.RESTRICT:
        allow = ", ".join(ip_str(a) for a in allowed) or gw
        return base + [
            f"add rule inet guardian {chain} ip daddr 192.168.0.0/16 accept",
            f"add rule inet guardian {chain} ip daddr {{ {allow} }} "
            f"limit rate over {max(rate_bytes, 1000)} bytes/second drop",
            f"add rule inet guardian {chain} ip daddr {{ {allow} }} accept",
            f"add rule inet guardian {chain} log prefix \"guardian-restrict \" drop",
        ] + jump
    if tier == Tier.QUARANTINE:
        return base + [
            f"add rule inet guardian {chain} ip daddr {gw} tcp dport 1883 accept",
            f"add rule inet guardian {chain} ip daddr {gw} udp dport 53 accept",
            f"add rule inet guardian {chain} log prefix \"guardian-quarantine \" drop",
        ] + jump
    return base + [f"add rule inet guardian {chain} log prefix \"guardian-block \" drop"] + jump


@dataclass
class Action:
    t: float
    device: str
    before: Tier
    after: Tier
    reason: str
    commands: list[str]

    def to_dict(self) -> dict:
        return {"t": self.t, "device": self.device, "before": self.before.name,
                "after": self.after.name, "reason": self.reason, "commands": self.commands}


class DryRunEnforcer:
    """Records the rules it would apply."""

    def __init__(self) -> None:
        self.applied: list[Action] = []

    def apply(self, action: Action) -> None:
        self.applied.append(action)


class NftablesEnforcer(DryRunEnforcer):
    """Applies rules with ``nft`` on a Linux gateway (needs root and opt-in)."""

    def __init__(self) -> None:
        super().__init__()
        if not sys.platform.startswith("linux") or shutil.which("nft") is None:
            raise RuntimeError("nftables enforcement needs a Linux gateway with nft installed")
        if os.environ.get("GUARDIAN_ENFORCE") != "1":
            raise RuntimeError("set GUARDIAN_ENFORCE=1 to apply firewall rules")

    def apply(self, action: Action) -> None:
        super().apply(action)
        script = "\n".join(action.commands) + "\n"
        subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True)


@dataclass
class DeviceState:
    tier: Tier = Tier.MONITOR
    quiet: int = 0  # consecutive windows below the current tier
    since: float = 0.0


@dataclass
class ResponsePolicy:
    """Decides tier changes from threat scores, with cool-down and user override."""

    cooldown_windows: int = 30  # 5 minutes of quiet before stepping down
    observe_only: bool = False
    states: dict[str, DeviceState] = field(default_factory=dict)

    def state(self, device: str) -> DeviceState:
        return self.states.setdefault(device, DeviceState())

    def decide(self, device: str, t: float, threat: float) -> tuple[Tier, Tier] | None:
        """Return (before, after) when the device should change tier, else None."""
        st = self.state(device)
        wanted = tier_for(threat)
        if wanted > st.tier:
            before = st.tier
            st.tier, st.quiet, st.since = wanted, 0, t
            return before, wanted
        if st.tier in (Tier.RESTRICT, Tier.QUARANTINE) and threat < TIER_FLOORS[st.tier]:
            st.quiet += 1
            if st.quiet >= self.cooldown_windows:
                before = st.tier
                st.tier, st.quiet, st.since = Tier(st.tier - 1), 0, t
                return before, st.tier
        elif threat >= TIER_FLOORS[st.tier]:
            st.quiet = 0
        return None

    def release(self, device: str, t: float) -> tuple[Tier, Tier] | None:
        st = self.state(device)
        if st.tier == Tier.MONITOR:
            return None
        before = st.tier
        st.tier, st.quiet, st.since = Tier.MONITOR, 0, t
        return before, Tier.MONITOR
