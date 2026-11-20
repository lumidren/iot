# The 60 behavioral features

Computed for every device every 10 seconds from packet metadata only (time, direction,
size, protocol, remote address and port, TCP flags), so they work on encrypted traffic.
Generated from `src/guardian/features.py`.

*Log* marks heavy-tailed features that the models see as log(1 + x). *Cited* marks
features an explanation may quote; the rest only give the models context.

## Volume (12)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 0 | `pkts_out` | Packets sent | packets | yes | yes |
| 1 | `pkts_in` | Packets received | packets | yes | yes |
| 2 | `bytes_out` | Bytes sent | bytes | yes | yes |
| 3 | `bytes_in` | Bytes received | bytes | yes | yes |
| 4 | `pkts_total` | Total packets | packets | yes | yes |
| 5 | `bytes_total` | Total bytes | bytes | yes | yes |
| 6 | `mean_size_out` | Average sent packet size | bytes |  | yes |
| 7 | `mean_size_in` | Average received packet size | bytes |  | yes |
| 8 | `std_size_out` | Sent packet size spread | bytes |  | yes |
| 9 | `std_size_in` | Received packet size spread | bytes |  | yes |
| 10 | `max_size` | Largest packet | bytes |  | yes |
| 11 | `large_pkt_frac` | Share of large packets (>1000 B) | ratio |  | yes |

## Rates and ratios (6)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 12 | `out_in_pkt_ratio` | Sent/received packet ratio | ratio | yes | yes |
| 13 | `out_in_byte_ratio` | Sent/received byte ratio | ratio | yes | yes |
| 14 | `upload_frac` | Upload share of bytes | ratio |  | yes |
| 15 | `small_pkt_frac` | Share of tiny packets (<100 B) | ratio |  | yes |
| 16 | `peak_pps` | Peak packets in one second | packets/s | yes | yes |
| 17 | `active_seconds` | Seconds with traffic | seconds |  | yes |

## Timing (6)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 18 | `iat_mean` | Average gap between packets | seconds |  | yes |
| 19 | `iat_std` | Gap variability | seconds |  | yes |
| 20 | `iat_min` | Shortest gap | seconds |  | yes |
| 21 | `iat_max` | Longest gap | seconds |  | yes |
| 22 | `iat_cv` | Gap irregularity (CV) | ratio |  | yes |
| 23 | `burstiness` | Burstiness (peak/average rate) | ratio |  | yes |

## Protocol mix (8)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 24 | `frac_tcp` | TCP share | ratio |  | yes |
| 25 | `frac_udp` | UDP share | ratio |  | yes |
| 26 | `frac_icmp` | ICMP share | ratio |  | yes |
| 27 | `frac_mqtt` | MQTT share | ratio |  | yes |
| 28 | `frac_http` | HTTP share | ratio |  | yes |
| 29 | `frac_https` | HTTPS/TLS share | ratio |  | yes |
| 30 | `frac_dns` | DNS share | ratio |  | yes |
| 31 | `frac_other_ports` | Unusual-port share | ratio |  | yes |

## Network identity (12)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 32 | `n_peers` | Distinct destinations | hosts | yes | yes |
| 33 | `n_ports` | Distinct ports | ports | yes | yes |
| 34 | `n_new_peers` | Never-seen destinations | hosts | yes | yes |
| 35 | `frac_new_peer_pkts` | Traffic to never-seen destinations | ratio |  | yes |
| 36 | `n_new_ports` | Never-seen ports | ports | yes | yes |
| 37 | `n_external_peers` | Internet destinations | hosts | yes | yes |
| 38 | `frac_external_pkts` | Internet share of traffic | ratio |  | yes |
| 39 | `n_new_external_nets` | Never-seen internet networks (/24) | networks | yes | yes |
| 40 | `peer_entropy` | Destination spread (entropy) | bits |  | yes |
| 41 | `port_entropy` | Port spread (entropy) | bits |  | yes |
| 42 | `n_lan_peers` | Local hosts contacted | hosts | yes | yes |
| 43 | `top_peer_frac` | Share of the busiest destination | ratio |  | yes |

## Connection behavior (10)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 44 | `n_syn` | Connection attempts (SYN) | attempts | yes | yes |
| 45 | `n_synack_in` | Accepted connections (SYN-ACK) | replies | yes | yes |
| 46 | `n_rst_in` | Refused connections (RST) | replies | yes | yes |
| 47 | `n_fin` | Connection closes (FIN) | packets | yes | yes |
| 48 | `syn_ratio` | SYN share of sent packets | ratio |  | yes |
| 49 | `n_conn_targets` | Distinct connection targets | targets | yes | yes |
| 50 | `failed_conn_ratio` | Unanswered connection share | ratio |  | yes |
| 51 | `n_dns_queries` | DNS lookups | queries | yes | yes |
| 52 | `dns_frac_out` | DNS share of sent packets | ratio |  | yes |
| 53 | `inbound_new_peer_pkts` | Packets from never-seen hosts | packets | yes | yes |

## Time of day (6)

| # | Feature | Meaning | Unit | Log | Cited |
|---:|---|---|---|:---:|:---:|
| 54 | `hour_sin` | Time of day (sin) | - |  |  |
| 55 | `hour_cos` | Time of day (cos) | - |  |  |
| 56 | `hour_activity` | Usual activity at this hour | ratio |  |  |
| 57 | `off_hours_activity` | Activity at an unusual hour | ratio |  | yes |
| 58 | `active_streak` | Consecutive active windows | windows | yes | yes |
| 59 | `since_prev_active` | Seconds since previous activity | seconds |  |  |
