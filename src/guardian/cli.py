"""Command line: ``guardian eval``, ``guardian serve``, ``guardian demo``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _eval(args: argparse.Namespace) -> None:
    from .evaluate import main

    summary = main(args.seeds, Path(args.out), test_hours=args.hours)
    g = summary["detectors"]["guardian"]
    print(f"\nGUARDIAN: {g['detection_rate_headline'] * 100:.1f}% of headline attack episodes "
          f"detected, {g['false_alerts_per_device_day']:.2f} false alerts per device per day.")
    print(f"Full tables: {Path(args.out) / 'results.md'}")


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    from .server import LiveHome, create_app

    live = LiveHome(seed=args.seed, learn_hours=args.learn_hours, tick=10.0 / args.speed)
    print(f"GUARDIAN dashboard on http://{args.host}:{args.port} "
          f"(learning {args.learn_hours:.0f} simulated hours first)")
    uvicorn.run(create_app(live), host=args.host, port=args.port, log_level="warning")


def _demo(args: argparse.Namespace) -> None:
    import numpy as np

    from .attacks import ALL_ATTACKS, INTENSITY_BY_KIND, LABELS, Attack
    from .devices import DEVICE_INDEX, Home
    from .engine import Guardian
    from .net import concat

    spec = DEVICE_INDEX[args.device]
    home = Home(seed=args.seed)
    windows = int(args.learn_hours * 360)
    print(f"Learning {spec.name} ({spec.hardware}) for {args.learn_hours:.0f} simulated hours...")
    history = [(w * 10.0, home.window(w * 10.0, w * 10.0 + 10)[spec.id]) for w in range(windows)]
    g = Guardian([spec], seed=args.seed)
    g.bootstrap({spec.id: history})
    if args.attack not in ALL_ATTACKS:
        sys.exit(f"unknown attack {args.attack!r}; choose from {', '.join(ALL_ATTACKS)}")
    start = windows * 10.0 + 60
    attack = Attack(args.attack, spec.id, start + 3, 120, INTENSITY_BY_KIND[spec.kind])
    rng = np.random.default_rng(args.seed)
    print(f"Launching: {LABELS[args.attack]} against {spec.name}\n")
    shown = False
    for w in range(windows, windows + 24):
        t = w * 10.0
        pkts = concat([home.window(t, t + 10)[spec.id]] + attack.emit(t, t + 10, rng))
        for e in g.observe(t, {spec.id: pkts}):
            stamp = f"+{t + 10 - attack.start:5.0f}s" if t + 10 >= attack.start else "  pre "
            tier = e.action.after.name if e.action else e.tier.name
            print(f"[{stamp}] threat {e.threat:5.1f}  -> {tier}")
            if e.explanation and e.threat >= 61 and not shown:
                print("\n" + e.explanation.render() + "\n")
                shown = True
            if e.action:
                rules = [c for c in e.action.commands if "drop" in c or "accept" in c]
                print("          firewall: " + (rules[-1] if rules else e.action.commands[-1]))
    print(f"\nFinal tier: {g.policy.state(spec.id).tier.name}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="guardian", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("eval", help="run the reproducible evaluation")
    p.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    p.add_argument("--hours", type=float, default=24.0, help="test hours per seed")
    p.add_argument("--out", default="eval")
    p.set_defaults(func=_eval)

    p = sub.add_parser("serve", help="live dashboard on a simulated home")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--learn-hours", type=float, default=36.0)
    p.add_argument("--speed", type=float, default=20.0, help="simulated seconds per real second")
    p.set_defaults(func=_serve)

    p = sub.add_parser("demo", help="one attack against one device, in the terminal")
    p.add_argument("--device", default="cam-1")
    p.add_argument("--attack", default="exfiltration")
    p.add_argument("--seed", type=int, default=3)
    p.add_argument("--learn-hours", type=float, default=36.0)
    p.set_defaults(func=_demo)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
