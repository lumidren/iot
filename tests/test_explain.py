import numpy as np

from guardian.detector import Identity, Score
from guardian.explain import classify, explain, recommend
from guardian.features import INDEX, N_FEATURES
from guardian.net import ip


def score(threat=90.0, ident=None, **features) -> Score:
    x = np.zeros(N_FEATURES)
    x[INDEX["pkts_total"]] = 10
    x[INDEX["hour_activity"]] = 0.5
    for k, v in features.items():
        x[INDEX[k]] = v
    return Score(3600.0 * 3.5, threat, 0.0, 0.0, 0.0, x, np.zeros(N_FEATURES),
                 ident or Identity())


def test_attack_names():
    assert classify(score(pkts_out=4000, n_peers=1, syn_ratio=0.7)).startswith("Flooding")
    lan = Identity(new_lan=[ip(f"192.168.50.{i}") for i in range(2, 30)])
    assert classify(score(ident=lan)).startswith("Network scanning")
    pool = Identity(new_external=[ip("51.68.190.10")], new_external_nets=[ip("51.68.190.0")],
                    new_ports=[3333], unsolicited_inbound=[ip("51.68.190.10")])
    assert classify(score(ident=pool)) == "Cryptomining pool connection"
    drop = Identity(new_external=[ip("45.137.21.9")], new_external_nets=[ip("45.137.21.0")])
    assert classify(score(ident=drop, bytes_out=400_000, upload_frac=0.95)) == "Data exfiltration"
    assert classify(score(ident=drop)) == "Command-and-control communication"
    assert classify(score()) == "Unusual behavior"


def test_explanation_cites_the_destination_and_time():
    drop = Identity(new_external=[ip("185.220.101.47")],
                    new_external_nets=[ip("185.220.101.0")])
    s = score(threat=92, ident=drop, hour_activity=0.01)
    e = explain(s, None, "Smart camera")
    text = e.render()
    assert "185.220.101.47" in text and "185.220.101.0/24" in text
    assert any(r.title == "Unusual activity time" for r in e.reasons)
    assert e.to_dict()["summary"].startswith("Command-and-control")


def test_quiet_window_needs_no_explanation_or_action():
    e = explain(score(threat=5), None, "Plug")
    assert e.reasons == [] and e.actions == []
    assert e.summary == "Behaving like itself."
    assert recommend("Unusual behavior", 40) == [
        "Watch the device; GUARDIAN will escalate if this continues"]
