# Changelog

## 0.2.0

### Added
- Trained models are saved and loaded (`--models`, `--save-models`) as plain
  arrays with a feature-version check, so a gateway restart does not relearn.
- Daily drift review: small drift is absorbed, bigger drift asks the owner, and
  an approved change relearns the device from recent traffic.
- Dashboard: "Simulate firmware update" demo, drift questions on device cards,
  CSV download of every decision, keyboard-operable cards and live regions for
  screen readers.
- Windows scripts: `scripts/setup.ps1` (insists on 64-bit Python) and
  `scripts/serve.ps1` (works even when the venv's Python is not visible).
- Tests for pcap byte orders, nanosecond timestamps, raw IP and VLAN frames,
  observe-only mode, enforcement guards and the CLI workflows.

### Fixed
- The activity-streak feature is capped at one hour; before, a restart made
  always-on devices look unusual for hours.
- Saved models from an older feature definition are refused (and relearned by
  the dashboard) instead of being used silently.
- Speed buttons follow the server's real speed.

## 0.1.0

First complete version: eight simulated devices, nine attack scenarios, 60
features, three detection layers, plain-language explanations, graduated
response with nftables rules, hybrid startup, pcap reader/writer, live
dashboard, and a reproducible evaluation against a signature IDS and a generic
model.
