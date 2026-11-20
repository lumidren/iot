import sys

import pytest

from guardian.devices import DEVICE_INDEX
from guardian.engine import Guardian
from guardian.net import SYN, TCP, ip, packets
from guardian.response import NftablesEnforcer, ResponsePolicy, Tier


def probes(t0: float):
    return packets([t0 + i * 0.2 for i in range(40)], out=True, size=60, proto=TCP,
                   peer=ip("192.168.50.77"), port=23, flags=SYN)


def test_observe_only_scores_but_never_enforces():
    spec = DEVICE_INDEX["hub-1"]
    g = Guardian([spec], policy=ResponsePolicy(observe_only=True))
    events = g.observe(0.0, {spec.id: probes(0.0)})
    assert events and events[0].threat >= 61
    assert events[0].action is None
    assert g.policy.state(spec.id).tier == Tier.MONITOR
    assert g.enforcer.applied == []


def test_release_of_a_device_that_is_not_restricted_is_a_no_op():
    spec = DEVICE_INDEX["hub-1"]
    g = Guardian([spec])
    assert g.release(spec.id, 0.0) is None
    assert g.enforcer.applied == []


def test_unknown_devices_are_ignored():
    g = Guardian([DEVICE_INDEX["hub-1"]])
    assert g.observe(0.0, {"stranger": probes(0.0)}) == []


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="checks the non-Linux guard")
def test_real_enforcement_refuses_to_run_off_a_linux_gateway():
    with pytest.raises(RuntimeError, match="Linux"):
        NftablesEnforcer()


def test_real_enforcement_needs_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/sbin/nft")
    monkeypatch.delenv("GUARDIAN_ENFORCE", raising=False)
    with pytest.raises(RuntimeError, match="GUARDIAN_ENFORCE"):
        NftablesEnforcer()
