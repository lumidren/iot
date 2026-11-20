import numpy as np

from guardian.attacks import ALL_ATTACKS, Attack
from guardian.devices import DEVICES, Home
from guardian.net import PACKET, concat, ip, ip_str, is_private


def test_address_helpers():
    assert ip_str(ip("192.168.50.7")) == "192.168.50.7"
    assert is_private(ip("192.168.50.7"))
    assert is_private(ip("10.1.2.3"))
    assert not is_private(ip("185.220.101.47"))
    flags = is_private(np.array([ip("172.16.0.1"), ip("8.8.8.8")], dtype=np.uint32))
    assert flags.tolist() == [True, False]


def test_home_has_the_eight_planned_devices():
    assert len(DEVICES) == 8
    kinds = [d.hardware for d in DEVICES]
    assert kinds.count("ESP32") == 3
    assert kinds.count("ESP8266") == 2
    assert kinds.count("Raspberry Pi Zero") == 2
    assert kinds.count("ESP32-CAM") == 1


def test_simulation_is_deterministic_per_seed():
    a, b = Home(seed=5), Home(seed=5)
    for w in range(60):
        wa, wb = a.window(w * 10.0, w * 10.0 + 10), b.window(w * 10.0, w * 10.0 + 10)
        for dev in wa:
            assert np.array_equal(wa[dev], wb[dev])


def test_windows_contain_sorted_packets_inside_the_window():
    home = Home(seed=3)
    for w in range(360):
        t0 = 6 * 3600 + w * 10.0
        for pkts in home.window(t0, t0 + 10).values():
            assert pkts.dtype == PACKET
            if len(pkts):
                assert np.all(np.diff(pkts["t"]) >= 0)
                assert pkts["t"].min() >= t0
                assert pkts["t"].max() < t0 + 10.5


def test_every_attack_produces_traffic():
    rng = np.random.default_rng(0)
    for kind in ALL_ATTACKS:
        attack = Attack(kind, "hub-1", start=100.0, duration=120.0, cover_peer=ip("1.2.3.4"))
        parts = []
        for w in range(10, 22):
            parts += attack.emit(w * 10.0, w * 10.0 + 10, rng)
        pkts = concat(parts)
        assert len(pkts) > 0, kind
        assert pkts["t"].min() >= 100.0
        assert pkts["t"].max() <= 220.5


def test_attack_is_silent_outside_its_episode():
    attack = Attack("ddos_flood", "hub-1", start=100.0, duration=30.0)
    rng = np.random.default_rng(0)
    assert attack.emit(0, 90, rng) == []
    assert attack.emit(130, 200, rng) == []
