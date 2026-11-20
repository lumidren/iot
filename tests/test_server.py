import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from guardian.server import LiveHome, clock, create_app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    live = LiveHome(seed=5, learn_hours=8, tick=0.5)
    app = create_app(live, run=False)
    with TestClient(app) as c:
        assert c.get("/api/state").json()["ready"] is False
        live.learn()
        yield c, live


def test_clock_format():
    assert clock(0) == "Day 1, 00:00"
    assert clock(86400 + 3600 * 14.5) == "Day 2, 14:30"


def test_dashboard_page_and_assets_are_served(client):
    c, _ = client
    page = c.get("/")
    assert page.status_code == 200 and "GUARDIAN" in page.text
    assert c.get("/static/app.js").status_code == 200
    assert c.get("/static/style.css").status_code == 200


def test_state_lists_all_devices_once_ready(client):
    c, live = client
    live.step()
    state = c.get("/api/state").json()
    assert state["ready"] is True
    assert len(state["devices"]) == 8
    assert all(d["phase"] == "protected" for d in state["devices"])
    assert len(state["attack_kinds"]) == 9


def test_attack_is_launched_contained_and_released(client):
    c, live = client
    r = c.post("/api/attack", json={"device": "hub-1", "kind": "ddos_flood"})
    assert r.status_code == 200
    for _ in range(4):
        live.step()
    state = c.get("/api/state").json()
    hub = next(d for d in state["devices"] if d["id"] == "hub-1")
    assert hub["tier"] in ("QUARANTINE", "BLOCK")
    assert state["alerts"] and state["alerts"][0]["explanation"]["reasons"]
    assert state["actions"] and state["actions"][0]["commands"]

    assert c.post("/api/release", json={"device": "hub-1", "trust": False}).status_code == 200
    hub = next(d for d in c.get("/api/state").json()["devices"] if d["id"] == "hub-1")
    assert hub["tier"] == "MONITOR"


def test_bad_requests_are_rejected(client):
    c, _ = client
    assert c.post("/api/attack", json={"device": "toaster", "kind": "scan"}).status_code == 400
    assert c.post("/api/attack", json={"device": "hub-1", "kind": "nope"}).status_code == 400
    assert c.post("/api/speed", json={"speed": 100}).json()["speed"] == pytest.approx(100)


def test_second_start_loads_the_saved_models(tmp_path):
    first = LiveHome(seed=6, learn_hours=6, models=tmp_path)
    first.learn()
    assert (tmp_path / "manifest.json").exists()
    second = LiveHome(seed=6, learn_hours=6, models=tmp_path)
    second.learn()
    assert second.ready and "loaded" in second.progress
    assert second.t == first.t
    second.step()
    assert all(d["phase"] == "protected" for d in second.snapshot()["devices"])
