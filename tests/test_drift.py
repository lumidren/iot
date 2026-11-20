import numpy as np

from guardian.detector import Identity, Score
from guardian.devices import DEVICE_INDEX, Home, Periodic
from guardian.drift import DriftMonitor
from guardian.engine import Guardian
from guardian.features import INDEX, N_FEATURES
from guardian.net import TCP, ip


def window_score(unusual: bool, new_external=()) -> Score:
    x = np.zeros(N_FEATURES)
    x[INDEX["pkts_total"]] = 4
    return Score(0.0, 10.0, 5.0 if unusual else 0.0, 0.0, 0.0, x, np.zeros(N_FEATURES),
                 Identity(new_external=list(new_external)))


def run_period(monitor: DriftMonitor, share: float, new_external=()):
    empty = np.zeros(0)
    n = monitor.review_windows
    for i in range(n):
        monitor.record(i * 10.0, empty, window_score(i < share * n, new_external))
    return monitor


def test_small_drift_absorbs_rotated_addresses_silently():
    rotated = ip("47.254.132.77")  # same /24 as a known cloud, new address
    m = run_period(DriftMonitor(review_windows=100), 0.05, new_external=[rotated])
    assert m.due()
    known: set[int] = set()
    assert m.review("plug-1", 1000.0, known) is None
    assert rotated in known
    assert not m.due() and m.active == 0


def test_moderate_and_large_drift_ask_the_owner():
    m = run_period(DriftMonitor(review_windows=100), 0.2)
    notice = m.review("plug-1", 1000.0, set())
    assert notice.level == "moderate" and "change" in notice.question
    m = run_period(DriftMonitor(review_windows=100), 0.6)
    notice = m.review("plug-1", 2000.0, set())
    assert notice.level == "large" and "firmware" in notice.question


def _firmware_update_scenario(accept: bool):
    spec = DEVICE_INDEX["plug-1"]
    home = Home(seed=21, specs=[spec])
    history = {spec.id: [(w * 10.0, home.window(w * 10.0, w * 10.0 + 10)[spec.id])
                         for w in range(3000)]}
    g = Guardian([spec], drift_review_windows=360)
    g.bootstrap(history)
    # the "update": the plug now also checks in with a new cloud every minute
    new_cloud = ip("52.29.40.10")
    home.devices[spec.id].behaviors.append(
        Periodic(60, [new_cloud], 443, TCP, req=(300, 520), resp=(200, 420),
                 new_connection=True))
    w = 3000
    while spec.id not in g.notices and w < 3000 + 2 * 360:
        t = w * 10.0
        g.observe(t, {spec.id: home.window(t, t + 10)[spec.id]})
        w += 1
    assert spec.id in g.notices, "the change was never noticed"
    relearned = g.resolve_drift(spec.id, accept)
    g.release(spec.id, w * 10.0, trust=False)
    threats = []
    for v in range(w, w + 120):
        t = v * 10.0
        g.observe(t, {spec.id: home.window(t, t + 10)[spec.id]})
        threats.append(g.devices[spec.id].last_score.threat)
    return relearned, max(threats), g


def test_owner_approved_relearn_makes_the_new_behavior_normal():
    relearned, worst, g = _firmware_update_scenario(accept=True)
    assert relearned
    assert worst < 61
    assert "plug-1" not in g.notices


def test_declined_change_keeps_alerting():
    relearned, worst, _ = _firmware_update_scenario(accept=False)
    assert not relearned
    assert worst >= 31
