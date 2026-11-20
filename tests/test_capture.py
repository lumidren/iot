import numpy as np

from guardian.capture import read_windows, write_pcap
from guardian.devices import DEVICE_INDEX, Home


def test_pcap_round_trip_preserves_what_the_detector_sees(tmp_path):
    home = Home(seed=2)
    ids = ["hub-1", "cam-1"]
    original = []
    for w in range(6 * 360, 6 * 360 + 30):  # 06:00 onwards
        win = home.window(w * 10.0, w * 10.0 + 10)
        original.append((w * 10.0, {d: win[d] for d in ids}))
    path = tmp_path / "home.pcap"
    triples = [(d, DEVICE_INDEX[d].address, pkts) for _, win in original
               for d, pkts in win.items()]
    n = write_pcap(path, triples, epoch=1_700_000_000.0 - (1_700_000_000.0 % 86400))
    assert n == sum(len(p) for _, _, p in triples)

    devices = {d: DEVICE_INDEX[d].address for d in ids}
    back = list(read_windows(path, devices))
    assert back[0][0] >= 6 * 3600  # time of day survives the round trip
    for d in ids:
        a = np.concatenate([win[d] for _, win in original])
        b = np.concatenate([win[d] for _, win in back])
        a.sort(order="t", kind="stable")
        assert len(a) == len(b), d
        assert np.allclose(a["t"], b["t"], atol=2e-6)
        for field in ("out", "size", "proto", "peer", "port", "flags"):
            assert np.array_equal(a[field], b[field]), field
    # each packet lands in the window its timestamp belongs to
    for t0, win in back:
        for pkts in win.values():
            assert np.all((pkts["t"] >= t0) & (pkts["t"] < t0 + 10))
