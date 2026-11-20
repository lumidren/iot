import json

import numpy as np
import pytest

from guardian.attacks import Attack
from guardian.detector import DeviceDetector
from guardian.devices import DEVICE_INDEX, Home
from guardian.engine import Guardian
from guardian.net import concat
from guardian.store import load_models, save_models


@pytest.fixture(scope="module")
def trained():
    home = Home(seed=12)
    windows = [(w * 10.0, home.window(w * 10.0, w * 10.0 + 10)["hub-1"]) for w in range(3000)]
    det = DeviceDetector("hub-1", seed=1, trees=40, memory=500).fit(windows[:2250],
                                                                    windows[2250:])
    return home, det


def test_saved_model_scores_exactly_like_the_original(trained, tmp_path):
    home, det = trained
    save_models({"hub-1": det}, tmp_path)
    loaded = load_models(tmp_path)["hub-1"]
    assert loaded.forest is None  # scikit-learn is not needed to score
    attack_a = Attack("exfiltration", "hub-1", 3100 * 10.0 + 2, 60)
    attack_b = Attack("exfiltration", "hub-1", 3100 * 10.0 + 2, 60)
    rng_a, rng_b = np.random.default_rng(3), np.random.default_rng(3)
    det.reset_state()
    for w in range(3090, 3110):
        t = w * 10.0
        base = home.window(t, t + 10)["hub-1"]
        a = det.score(concat([base] + attack_a.emit(t, t + 10, rng_a)), t)
        b = loaded.score(concat([base] + attack_b.emit(t, t + 10, rng_b)), t)
        assert a.threat == pytest.approx(b.threat, abs=1e-9)
        assert a.ml == pytest.approx(b.ml, abs=1e-9)


def test_models_for_other_features_are_refused(trained, tmp_path):
    _, det = trained
    path = save_models({"hub-1": det}, tmp_path)
    manifest = json.loads(path.read_text())
    manifest["features"] = "something-else"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="different feature list"):
        load_models(tmp_path)


def test_unsafe_names_and_untrained_models_are_refused(trained, tmp_path):
    _, det = trained
    with pytest.raises(ValueError, match="not safe"):
        save_models({"../evil": det}, tmp_path)
    with pytest.raises(ValueError, match="trained"):
        DeviceDetector("x").to_arrays()


def test_engine_restarts_protected_from_saved_models(trained, tmp_path):
    _, det = trained
    save_models({"hub-1": det}, tmp_path)
    g = Guardian([DEVICE_INDEX["hub-1"], DEVICE_INDEX["temp-1"]])
    assert g.load(tmp_path) == ["hub-1"]
    phases = {row["id"]: row["phase"] for row in g.status(0.0)}
    assert phases == {"hub-1": "protected", "temp-1": "learning-rules"}
