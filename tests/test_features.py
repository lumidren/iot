import numpy as np

from guardian.features import (
    EXPLAIN_MASK,
    FEATURES,
    INDEX,
    N_FEATURES,
    NAMES,
    Context,
    extract,
    model_view,
)
from guardian.net import ACK, RST, SYN, TCP, UDP, concat, ip, packets

BROKER = ip("192.168.50.1")


def mqtt_window(t0: float) -> np.ndarray:
    return concat([
        packets([t0 + 1], out=True, size=100, proto=TCP, peer=BROKER, port=1883, flags=ACK),
        packets([t0 + 1.01], out=False, size=58, proto=TCP, peer=BROKER, port=1883, flags=ACK),
    ])


def test_there_are_exactly_sixty_named_features():
    assert N_FEATURES == 60
    assert len(set(NAMES)) == 60
    assert all(f.label and f.group for f in FEATURES)
    assert not EXPLAIN_MASK[INDEX["hour_sin"]]


def test_empty_window_only_has_time_features():
    ctx = Context()
    x = extract(np.zeros(0, dtype=mqtt_window(0).dtype), 3600.0 * 3, ctx)
    nonzero = {NAMES[i] for i in np.flatnonzero(x)}
    assert nonzero <= {"hour_sin", "hour_cos", "hour_activity", "since_prev_active"}


def test_volume_and_protocol_features():
    ctx = Context()
    ctx.learn([(0.0, mqtt_window(0.0))])
    x = extract(mqtt_window(10.0), 10.0, ctx)
    assert x[INDEX["pkts_out"]] == 1 and x[INDEX["pkts_in"]] == 1
    assert x[INDEX["bytes_total"]] == 158
    assert x[INDEX["frac_mqtt"]] == 1.0
    assert x[INDEX["n_new_peers"]] == 0
    assert x[INDEX["n_lan_peers"]] == 1


def test_new_destination_and_new_network_are_counted():
    ctx = Context()
    ctx.learn([(0.0, mqtt_window(0.0))])
    evil = packets([12.0], out=True, size=300, proto=TCP, peer=ip("185.220.101.47"), port=443,
                   flags=ACK)
    x = extract(concat([mqtt_window(10.0), evil]), 10.0, ctx)
    assert x[INDEX["n_new_peers"]] == 1
    assert x[INDEX["n_new_external_nets"]] == 1
    assert x[INDEX["n_external_peers"]] == 1
    assert x[INDEX["frac_new_peer_pkts"]] == 1 / 3


def test_scan_shows_up_in_connection_features():
    ctx = Context()
    ctx.learn([(0.0, mqtt_window(0.0))])
    probes = [
        packets([10.0 + i * 0.05], out=True, size=60, proto=TCP,
                peer=ip(f"192.168.50.{20 + i}"), port=23, flags=SYN)
        for i in range(40)
    ]
    refused = [
        packets([10.01 + i * 0.05], out=False, size=54, proto=TCP,
                peer=ip(f"192.168.50.{20 + i}"), port=23, flags=RST | ACK)
        for i in range(10)
    ]
    x = extract(concat(probes + refused), 10.0, ctx)
    assert x[INDEX["n_syn"]] == 40
    assert x[INDEX["n_rst_in"]] == 10
    assert x[INDEX["n_conn_targets"]] == 40
    assert x[INDEX["failed_conn_ratio"]] == 1.0
    assert x[INDEX["n_lan_peers"]] == 40


def test_dns_and_streak_tracking():
    ctx = Context()
    dns = packets([1.0, 2.0], out=True, size=80, proto=UDP, peer=BROKER, port=53)
    a = extract(dns, 0.0, ctx)
    b = extract(dns, 10.0, ctx)
    assert a[INDEX["n_dns_queries"]] == 2
    assert b[INDEX["active_streak"]] == 2
    assert b[INDEX["since_prev_active"]] == 10.0


def test_model_view_logs_heavy_columns_only():
    x = np.zeros(N_FEATURES)
    x[INDEX["pkts_out"]] = np.e - 1
    x[INDEX["upload_frac"]] = 0.5
    v = model_view(x)
    assert np.isclose(v[INDEX["pkts_out"]], 1.0)
    assert v[INDEX["upload_frac"]] == 0.5
