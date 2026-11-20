# Contributing

## Setup

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .\scripts\setup.ps1
pip install -e ".[dashboard,dev]"
pytest -q && ruff check src tests
```

Use a 64-bit Python 3.11+. On 32-bit Python, scikit-learn has no wheels and
SciPy tries to build from source.

## Rules for numbers

- Every number in the README or a presentation must come from `guardian eval`
  (or a test) and be reproducible from a seed.
- Say "simulated" next to simulated results. Do not tune the detector on the
  test day: calibration uses the learning period only.
- If you change a feature's definition, bump `FEATURE_VERSION` in
  `features.py`, rerun `guardian eval`, and commit the new `eval/` files with
  the change that caused them.

## Commits

Small and focused: one logical change per commit, with a message that says what
changed and why (`fix(features): cap the activity streak so ...`). Tests go in
the same pull request as the code they cover.

## Safety

Attack scenarios generate traffic records only; nothing is sent on a network.
On the physical testbed, attack traffic stays on the isolated network and on
hosts the team owns.
