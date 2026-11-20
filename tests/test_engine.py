import numpy as np
import pytest

from guardian.attacks import C2_SERVER, Attack
from guardian.devices import DEVICE_INDEX, Home
from guardian.engine import Guardian
from guardian.net import concat, ip_str
from guardian.response import ResponsePolicy, Tier, nft_rules, tier_for

GW = DEVICE_INDEX["plug-1"].address & 0xFFFFFF00 | 1


def test_tiers_follow_the_design_thresholds():
    assert tier_for(0) == Tier.MONITOR
    assert tier_for(30.9) == Tier.MONITOR
    assert tier_for(31) == Tier.RESTRICT
    assert tier_for(61) == Tier.QUARANTINE
    assert tier_for(86) == Tier.BLOCK


def test_policy_escalates_cools_down_and_never_auto_releases_a_block():
    p = ResponsePolicy(cooldown_windows=3)
    assert p.decide("d", 0, 70) == (Tier.MONITOR, Tier.QUARANTINE)
    assert p.decide("d", 10, 65) is None
    assert [p.decide("d", t, 5) for t in (20, 30)] == [None, None]
    assert p.decide("d", 40, 5) == (Tier.QUARANTINE, Tier.RESTRICT)
    assert p.decide("d", 50, 95) == (Tier.RESTRICT, Tier.BLOCK)
    assert all(p.decide("d", 60 + i, 0) is None for i in range(10))
    assert p.release("d", 200) == (Tier.BLOCK, Tier.MONITOR)


def test_firewall_rules_per_tier():
    dev = DEVICE_INDEX["plug-1"].address
    block = "\n".join(nft_rules(dev, Tier.BLOCK, gateway=GW, allowed=[], rate_bytes=0))
    assert "drop" in block and ip_str(dev) in block
    quarantine = "\n".join(nft_rules(dev, Tier.QUARANTINE, gateway=GW, allowed=[],
                                     rate_bytes=0))
    assert "dport 1883 accept" in quarantine and "udp dport 53 accept" in quarantine
    restrict = "\n".join(nft_rules(dev, Tier.RESTRICT, gateway=GW, allowed=[C2_SERVER],
                                   rate_bytes=4000))
    assert "4000 bytes/second" in restrict and ip_str(C2_SERVER) in restrict


@pytest.fixture(scope="module")
def guarded():
    home = Home(seed=9)
    specs = [DEVICE_INDEX["plug-1"], DEVICE_INDEX["temp-1"]]
    history = {s.id: [] for s in specs}
    for w in range(4320):
        win = home.window(w * 10.0, w * 10.0 + 10)
        for s in specs:
            history[s.id].append((w * 10.0, win[s.id]))
    g = Guardian(specs)
    g.bootstrap(history)
    return home, g


def test_attack_is_contained_and_explained(guarded):
    home, g = guarded
    attack = Attack("cc_beacon", "plug-1", 4400 * 10.0 + 1, 300, intensity=0.4)
    rng = np.random.default_rng(1)
    events = []
    for w in range(4400, 4430):
        t = w * 10.0
        win = home.window(t, t + 10)
        win = {k: v for k, v in win.items() if k in g.devices}
        win["plug-1"] = concat([win["plug-1"]] + attack.emit(t, t + 10, rng))
        events += g.observe(t, win)
    plug = [e for e in events if e.device == "plug-1"]
    assert plug, "beacon not reported"
    worst = max(plug, key=lambda e: e.threat)
    assert worst.threat >= 61
    assert worst.explanation is not None
    titles = [r.title for r in worst.explanation.reasons]
    assert "Unknown destination" in titles
    assert ip_str(C2_SERVER) in worst.explanation.render()
    assert g.policy.state("plug-1").tier >= Tier.QUARANTINE
    assert any(a.after >= Tier.QUARANTINE for a in g.enforcer.applied)
    assert g.policy.state("temp-1").tier == Tier.MONITOR

    # the user says "that was me": release and learn the destination
    released = g.release("plug-1", 4430 * 10.0, trust=True)
    assert released is not None and released.action.after == Tier.MONITOR
    assert C2_SERVER in g.devices["plug-1"].detector.ctx.known_peers


def test_new_device_goes_through_the_learning_phases():
    home = Home(seed=4)
    spec = DEVICE_INDEX["hub-1"]
    g = Guardian([spec], stats_after=600, learn_after=1200)
    phases = []
    for w in range(200):
        t = w * 10.0
        g.observe(t, {spec.id: home.window(t, t + 10)[spec.id]})
        phases.append(g.status(t)[0]["phase"])
    assert phases[0] == "learning-rules"
    assert "learning-ranges" in phases
    assert phases[-1] == "protected"


def test_startup_rules_protect_before_any_baseline():
    home = Home(seed=4)
    spec = DEVICE_INDEX["hub-1"]
    g = Guardian([spec])
    attack = Attack("scan", "hub-1", 1.0, 60)
    rng = np.random.default_rng(0)
    worst = 0.0
    for w in range(6):
        t = w * 10.0
        pkts = concat([home.window(t, t + 10)[spec.id]] + attack.emit(t, t + 10, rng))
        for e in g.observe(t, {spec.id: pkts}):
            worst = max(worst, e.threat)
    assert worst >= 61
    assert g.status(60.0)[0]["phase"] == "learning-rules"
