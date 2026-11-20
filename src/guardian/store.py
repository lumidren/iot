"""Save and load trained device models.

A gateway that reboots should not need another 48 hours of learning. Each
device's model is written as one ``.npz`` of plain numeric arrays (loaded with
``allow_pickle=False``, so a model file can never execute code) plus a
``manifest.json`` that records the format version and the feature list the
models were trained on. Loading refuses models built for different features.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

import numpy as np

from . import __version__
from .detector import DeviceDetector
from .features import FEATURE_VERSION, NAMES

FORMAT = 1
_SAFE = re.compile(r"^[A-Za-z0-9_.-]+$")


def feature_signature() -> str:
    """A short hash of the feature list and version; models are only valid for the same."""
    text = f"v{FEATURE_VERSION}:" + ",".join(NAMES)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def save_models(detectors: dict[str, DeviceDetector], directory: str | Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    devices = {}
    for device_id, det in detectors.items():
        if not _SAFE.match(device_id):
            raise ValueError(f"device id {device_id!r} is not safe as a file name")
        np.savez_compressed(directory / f"{device_id}.npz", **det.to_arrays())
        devices[device_id] = {"file": f"{device_id}.npz",
                              "known_destinations": len(det.ctx.known_peers)}
    manifest = {
        "format": FORMAT,
        "guardian_version": __version__,
        "features": feature_signature(),
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "devices": devices,
    }
    path = directory / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def load_models(directory: str | Path) -> dict[str, DeviceDetector]:
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT:
        raise ValueError(f"unsupported model format {manifest.get('format')!r}")
    if manifest.get("features") != feature_signature():
        raise ValueError("models were trained on a different feature list; retrain them")
    out = {}
    for device_id, entry in manifest["devices"].items():
        if not _SAFE.match(device_id) or entry["file"] != f"{device_id}.npz":
            raise ValueError(f"unexpected entry for {device_id!r} in manifest")
        with np.load(directory / entry["file"], allow_pickle=False) as data:
            out[device_id] = DeviceDetector.from_arrays(device_id, dict(data))
    return out
