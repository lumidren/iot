# Physical testbed plan

The code in this repository runs today on simulated traffic and on packet
captures. The next milestone is the physical testbed from the project plan, so
that every number in the README can be re-measured on real devices.

## Hardware

| Role | Board | Count | What it does on the network |
|---|---|---:|---|
| Temperature, motion, environment sensors | ESP32 | 3 | MQTT publishes to the local broker, NTP |
| Smart plug, relay | ESP8266 | 2 | MQTT commands, TLS check-ins to a cloud endpoint |
| Sensor hub, media node | Raspberry Pi Zero | 2 | Aggregation, HTTPS sync, a nightly update job |
| Smart camera | ESP32-CAM | 1 | Snapshots and motion-triggered streams to a home server |
| Gateway | Raspberry Pi 4 (4 GB) | 1 | Wi-Fi access point, MQTT broker, GUARDIAN |

The simulator in `src/guardian/devices.py` models exactly these eight devices,
so firmware for the boards can copy their traffic patterns.

## Network

```
 ESP32 / ESP8266 / Pi Zero / ESP32-CAM
              │  Wi-Fi (isolated SSID)
              ▼
 ┌────────── Raspberry Pi 4 ──────────┐
 │ hostapd  ─►  br0  ─►  nftables     │  ◄─ GUARDIAN enforces tiers here
 │ mosquitto (MQTT broker, :1883)     │
 │ dnsmasq   (DHCP + DNS)             │
 │ tcpdump -i br0  ─►  GUARDIAN       │  ◄─ 10-second windows per device
 └────────────────┬───────────────────┘
                  ▼ uplink (internet)
```

Every device's traffic crosses the gateway, so the gateway sees all of it and
can isolate a device without touching the device itself.

## Steps

1. **Baseline.** Run all eight devices for 48 hours, capturing on `br0`:
   `tcpdump -i br0 -w baseline.pcap`.
2. **Attack captures.** Reproduce the six scenarios against one device at a
   time from an attacker host on the uplink side (flood target, C2 listener,
   exfil sink, mining stratum endpoint), plus the scan from inside.
3. **Offline check.** `guardian pcap --learn baseline.pcap --check attack.pcap
   --device cam=192.168.50.108 ...` gives the same explanations as the simulator.
4. **Live enforcement.** On the gateway, `GUARDIAN_ENFORCE=1` switches the
   enforcer from dry run to `nft` so quarantine and block really cut devices off.
5. **Re-measure.** Detection per scenario, false alerts per device per day,
   scoring latency and CPU on the Pi 4, replacing the simulated numbers.

## Safety

Attack traffic stays on the isolated testbed network and an attacker host the
team owns. Nothing is pointed at third-party systems.
