"""Regenerate docs/FEATURES.md from the feature definitions.

    python scripts/gen_features_doc.py
"""

from __future__ import annotations

from pathlib import Path

from guardian.features import FEATURE_VERSION, FEATURES

TITLES = {"volume": "Volume", "rates": "Rates and ratios", "timing": "Timing",
          "protocol": "Protocol mix", "identity": "Network identity",
          "connections": "Connection behavior", "time": "Time of day"}


def render() -> str:
    groups: dict[str, list] = {}
    for i, f in enumerate(FEATURES):
        groups.setdefault(f.group, []).append((i, f))
    lines = [
        "# The 60 behavioral features", "",
        "Computed for every device every 10 seconds from packet metadata only (time, direction,",
        "size, protocol, remote address and port, TCP flags), so they work on encrypted traffic.",
        f"Generated from `src/guardian/features.py` (feature version {FEATURE_VERSION}) by",
        "`scripts/gen_features_doc.py`.", "",
        "*Log* marks heavy-tailed features that the models see as log(1 + x). *Cited* marks",
        "features an explanation may quote; the rest only give the models context.", "",
    ]
    for group, items in groups.items():
        lines += [f"## {TITLES[group]} ({len(items)})", "",
                  "| # | Feature | Meaning | Unit | Log | Cited |",
                  "|---:|---|---|---|:---:|:---:|"]
        for i, f in items:
            lines.append(f"| {i} | `{f.name}` | {f.label} | {f.unit or '-'} "
                         f"| {'yes' if f.log else ''} | {'yes' if f.explain else ''} |")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "docs" / "FEATURES.md"
    out.write_text(render(), encoding="utf-8")
    print(f"wrote {out}")
