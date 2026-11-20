from collections import deque

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from guardian.attacks import Attack
from guardian.detector import (
    Baseline,
    DeviceDetector,
    Identity,
    StartupGuard,
    combine,
    corroborate,
    identity,
    stat_score,
)
from guardian.devices import Home
from guardian.fastforest import FastForest
from guardian.features import INDEX, N_FEATURES, Context
from guardian.net import SYN, TCP, concat, ip, packets


@pytest.fixture(scope="module")
def trained():
    home = Home(seed=7)
    windows = [(w * 10.0, home.window(w * 10.0, w * 10.0 + 10)["plug-1"]) for w in range(4320)]
    det = DeviceDetector("plug-1", seed=0, trees=60, memory=800).fit(windows[:3240],
                                                                     windows[3240:])
    return home, det


def test_fast_forest_matches_scikit_learn_exactly():
    rng = np.random.default_rng(0)
    x = rng.normal(size=(1500, 12))
    forest = IsolationForest(n_estimators=40, max_samples=256, random_state=3).fit(x)
    probe = np.vstack([rng.normal(size=(200, 12)), rng.normal(size=(20, 12)) * 6])
    assert np.allclose(FastForest(forest).score_samples(probe), forest.score_samples(probe),
                       atol=1e-12)


def test_baseline_range_is_zero_inside_and_grows_outside():
    rng = np.random.default_rng(1)
    raw = np.abs(rng.normal(10, 2, size=(2000, N_FEATURES)))
    b = Baseline().fit(raw)
    assert b.deviations(np.median(raw, axis=0)).max() == 0
    spike = np.median(raw, axis=0)
    spike[INDEX["pkts_out"]] = 5000
    d = b.deviations(spike)
    assert d[INDEX["pkts_out"]] > 3
    assert stat_score(d) > stat_score(d / 4)


def test_noisy_or_combination():
    assert combine(0, 0, 0) == 0
    assert combine(50, 50) == pytest.approx(75)
    assert combine(100, 0) == 100


def test_one_window_spikes_need_corroboration():
    hist = deque(maxlen=3)
    assert corroborate(hist, 70, strong=90) == 0.0  # nothing to compare with yet
    assert corroborate(hist, 5, strong=90) == 5
    assert corroborate(hist, 70, strong=90) == 70  # earlier 70 corroborates
    hist.clear()
    corroborate(hist, 5, strong=90)
    corroborate(hist, 5, strong=90)
    assert corroborate(hist, 70, strong=90) == 5
    assert corroborate(hist, 95, strong=90) == 95  # strong evidence passes at once


def test_identity_flags_new_networks_but_tolerates_pool_rotation():
    ctx = Context(known_peers={ip("162.159.200.1"), ip("192.168.50.1")})
    ctx.known_nets = {ip("162.159.200.0")}
    ctx.known_ports = {123, 1883}
    rotated = packets([1.0], out=True, size=90, proto=17, peer=ip("162.159.200.9"), port=123)
    assert identity(rotated, ctx).score == pytest.approx(15)
    c2 = packets([1.0], out=True, size=200, proto=TCP, peer=ip("185.220.101.47"), port=443)
    found = identity(c2, ctx)
    assert found.new_external_nets == [ip("185.220.101.0")]
    assert found.score == pytest.approx(60)
    assert Identity().score == 0


def test_normal_traffic_stays_quiet(trained):
    home, det = trained
    det.reset_state()
    threats = [det.score(home.window(t, t + 10)["plug-1"], t).threat
               for t in np.arange(4320, 4320 + 720) * 10.0]
    assert max(threats) < 61


@pytest.mark.parametrize("kind", ["ddos_flood", "scan", "exfiltration", "cc_beacon"])
def test_attacks_raise_the_threat(trained, kind):
    home, det = trained
    det.reset_state()
    start = 5100 * 10.0
    attack = Attack(kind, "plug-1", start + 1, 120, intensity=0.4)
    rng = np.random.default_rng(0)
    peak = 0.0
    for t in np.arange(5100, 5114) * 10.0:
        pkts = concat([home.window(t, t + 10)["plug-1"]] + attack.emit(t, t + 10, rng))
        peak = max(peak, det.score(pkts, t).threat)
    assert peak >= 61


def test_startup_guard_catches_obvious_abuse_without_a_baseline():
    guard = StartupGuard()
    probes = packets(np.linspace(0, 9, 30), out=True, size=60, proto=TCP,
                     peer=ip("192.168.50.77"), port=23, flags=SYN)
    assert guard.score(probes, 0.0, Context()).threat >= 61
    flood = packets(np.linspace(0, 9.9, 2000), out=True, size=60, proto=TCP,
                    peer=ip("203.0.113.50"), port=80, flags=SYN)
    assert guard.score(flood, 0.0, Context()).threat >= 86
    quiet = packets([1.0], out=True, size=100, proto=TCP, peer=ip("192.168.50.1"), port=1883)
    assert guard.score(quiet, 0.0, Context()).threat == 0
