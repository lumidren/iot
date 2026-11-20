"""Live demo: the simulated home, GUARDIAN on its gateway, and a web dashboard.

Run ``guardian serve`` and open http://127.0.0.1:8000. The home is simulated
for a learning period, every device is trained, then the clock runs live
(one 10-second window per tick, 20x real time by default). Launch any attack
on any device from the dashboard and watch it get scored, explained and
contained; release a device to undo a decision.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np

from .attacks import ALL_ATTACKS, INTENSITY_BY_KIND, LABELS, Attack
from .devices import DEVICE_INDEX, DEVICES, GATEWAY, HOME_SERVER, Home
from .engine import Guardian
from .evaluate import COVER
from .net import concat

WEB = Path(__file__).parent / "web"
W = 10.0


def clock(t: float) -> str:
    day = int(t // 86400) + 1
    h = (t % 86400) / 3600
    return f"Day {day}, {int(h):02d}:{int((h % 1) * 60):02d}"


class LiveHome:
    def __init__(self, seed: int = 7, learn_hours: float = 36.0, tick: float = 0.5):
        self.seed = seed
        self.learn_hours = learn_hours
        self.tick = tick
        self.home = Home(seed=seed)
        self.guardian = Guardian(DEVICES, seed=seed)
        self.rng = np.random.default_rng(seed + 1)
        self.t = 0.0
        self.attacks: list[Attack] = []
        self.series = {d.id: deque(maxlen=90) for d in DEVICES}
        self.alerts: deque = deque(maxlen=40)
        self.actions: deque = deque(maxlen=40)
        self.ready = False
        self.progress = "starting"
        self.paused = False
        self.version = 0

    # -- setup -------------------------------------------------------------
    def learn(self) -> None:
        n = int(self.learn_hours * 3600 / W)
        history = {d.id: [] for d in DEVICES}
        t0 = time.perf_counter()
        for w in range(n):
            if w % 1000 == 0:
                self.progress = f"Simulating {self.learn_hours:.0f} h of normal traffic: " \
                                f"{w * 100 // n}%"
            for dev, pkts in self.home.window(w * W, (w + 1) * W).items():
                history[dev].append((w * W, pkts))
        self.progress = "Learning each device's behavioral identity"
        self.guardian.bootstrap(history)
        self.t = n * W
        self.progress = f"Ready (learned in {time.perf_counter() - t0:.0f} s)"
        self.ready = True

    # -- live loop ---------------------------------------------------------
    def step(self) -> None:
        t0 = self.t
        base = self.home.window(t0, t0 + W)
        for dev in base:
            parts = [base[dev]]
            for a in self.attacks:
                if a.device == dev and a.overlaps(t0, t0 + W):
                    parts += a.emit(t0, t0 + W, self.rng)
            base[dev] = concat(parts)
        events = self.guardian.observe(t0, base)
        for row in self.guardian.status(t0):
            self.series[row["id"]].append(row["threat"])
        for e in events:
            if e.explanation is not None and (e.action is not None
                                              or not self._recent_alert(e.device, t0)):
                self.alerts.appendleft(e.to_dict())
            if e.action is not None:
                self.actions.appendleft(e.action.to_dict())
        self.attacks = [a for a in self.attacks if a.end > t0 - 60]
        self.t += W
        self.version += 1

    def _recent_alert(self, device: str, t0: float) -> bool:
        """An alert for this device in the last 5 simulated minutes (avoid repeats)."""
        return any(a["device"] == device and t0 - a["t"] < 300 for a in self.alerts)

    def launch(self, device: str, kind: str, duration: float = 180.0) -> Attack:
        spec = DEVICE_INDEX[device]
        peer, port = COVER.get(device, (HOME_SERVER, 8080))
        if spec.kind == "sensor":
            peer, port = GATEWAY, 1883
        attack = Attack(kind, device, self.t + float(self.rng.uniform(0.5, 3)), duration,
                        INTENSITY_BY_KIND[spec.kind], cover_peer=peer, cover_port=port)
        self.attacks.append(attack)
        return attack

    def release(self, device: str, trust: bool) -> None:
        event = self.guardian.release(device, self.t, trust=trust)
        self.series[device].append(0.0)
        if event is not None and event.action is not None:
            self.actions.appendleft(event.action.to_dict())

    def snapshot(self) -> dict:
        status = self.guardian.status(self.t) if self.ready else []
        for row in status:
            row["series"] = list(self.series[row["id"]])
            row["under_attack"] = [LABELS[a.kind] for a in self.attacks
                                   if a.device == row["id"] and a.overlaps(self.t - W, self.t)]
        return {
            "ready": self.ready, "progress": self.progress, "t": self.t,
            "clock": clock(self.t), "speed": W / self.tick, "paused": self.paused,
            "devices": status, "alerts": list(self.alerts), "actions": list(self.actions),
            "attacks": [{"device": a.device, "kind": a.kind, "label": LABELS[a.kind],
                         "start": a.start, "end": a.end} for a in self.attacks
                        if a.end > self.t],
            "attack_kinds": [{"id": k, "label": LABELS[k]} for k in ALL_ATTACKS],
        }


try:  # the dashboard is an optional extra
    from pydantic import BaseModel
except ImportError:  # pragma: no cover
    BaseModel = object  # type: ignore[assignment,misc]


class AttackIn(BaseModel):
    device: str
    kind: str


class ReleaseIn(BaseModel):
    device: str
    trust: bool = True


class SpeedIn(BaseModel):
    speed: float | None = None
    paused: bool | None = None


def create_app(live: LiveHome | None = None, run: bool = True):
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles

    live = live or LiveHome()

    @asynccontextmanager
    async def lifespan(_app):  # pragma: no cover - exercised by the live server
        task = asyncio.create_task(runner()) if run else None
        yield
        if task is not None:
            task.cancel()

    app = FastAPI(title="GUARDIAN", lifespan=lifespan)
    app.state.live = live

    async def runner() -> None:
        await asyncio.to_thread(live.learn)
        while True:
            if not live.paused:
                live.step()
            await asyncio.sleep(live.tick)

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    @app.get("/api/state")
    def state():
        return live.snapshot()

    @app.get("/api/stream")
    async def stream():
        async def events():
            seen = -1
            while True:
                if live.version != seen or not live.ready:
                    seen = live.version
                    yield f"data: {json.dumps(live.snapshot())}\n\n"
                await asyncio.sleep(0.25)
        return StreamingResponse(events(), media_type="text/event-stream")

    @app.post("/api/attack")
    def attack(body: AttackIn):
        if body.device not in DEVICE_INDEX or body.kind not in ALL_ATTACKS:
            raise HTTPException(400, "unknown device or attack")
        a = live.launch(body.device, body.kind)
        return {"ok": True, "label": LABELS[a.kind], "start": a.start}

    @app.post("/api/release")
    def release(body: ReleaseIn):
        if body.device not in DEVICE_INDEX:
            raise HTTPException(400, "unknown device")
        live.release(body.device, body.trust)
        return {"ok": True}

    @app.post("/api/speed")
    def speed(body: SpeedIn):
        if body.speed:
            live.tick = max(0.05, min(5.0, W / body.speed))
        if body.paused is not None:
            live.paused = body.paused
        return {"ok": True, "speed": W / live.tick, "paused": live.paused}

    app.mount("/static", StaticFiles(directory=WEB), name="static")
    return app
