# SentinelFlow — Results

Every number below was measured on the development machine (Intel i7-1165G7) and links to the section of [REPORT.md](REPORT.md) that holds the evidence: commands, outputs and what each result does and does not show.

## Key measurements

| Area | Result | Conditions | Source |
|---|---|---|---|
| Sensor throughput | **~0.40 Mpps median**, 25.8 MB peak RSS, 0 flows dropped | Offline, single thread, i7-1165G7. 124,070 packets merged from 576 nDPI test captures. Current binary: medians 407 k pps (`-A 60`) and 400 k pps (`-A 0`), range 0.36–0.42 Mpps over 10 runs. Before the Phase 4 changes: 0.40–0.44 Mpps. Live-capture throughput not measured. | [Part 3 §3.2](REPORT.md#part-3) |
| Memory safety | **0** AddressSanitizer / LeakSanitizer / UBSan errors | 16 PCAPs (1,890 flows) in Part 3; 10 PCAPs with `-A 30` in Part 4. LeakSanitizer shown active on a deliberate 4,242-byte leak. | [Part 3 §3.1](REPORT.md#part-3), [Part 4 §1.2](REPORT.md#part-4) |
| Delivery sensor → consumer | 9,694 / 9,694 flows, 0 dropped | Same merged capture, consumer attached. Earlier silent loss fixed (receive high-water mark). | [Part 3 §3.6](REPORT.md#part-3) |
| Labeled dataset | **12,250 flows from 624 PCAPs** | 2,846 malicious flows from 51 captures (40 malware-traffic-analysis.net cases with hand-curated IOC labels, plus nDPI samples). 0 rejected. Built through the production sensor → ZMQ path. Part 3 had 9,659 flows / 28 malicious captures; 23 cases added in Part 7. | [Part 3 §4–5](REPORT.md#part-3), [Part 7 §1–2](REPORT.md#part-7) |
| Model quality (grouped CV) | **ROC-AUC 0.991 ± 0.001, PR-AUC 0.972 ± 0.003** | Current model `58fb9fc3` (adds conversation timing features), 5-fold grouped by capture, 5 seeds. At the 0.80 alert threshold: recall 0.79 ± 0.03, precision 0.96 ± 0.01, FPR 1.0 % ± 0.1 %. Previous model `203d33a1` on the same data: PR-AUC 0.945, recall 0.65. C2 servers with ≥ 1 alert: 124 ± 4 of 186 (previous 128 ± 4). | [Part 9](REPORT.md#part-9), [Part 7 §0](REPORT.md#part-7) |
| Unseen infections (holdout) | **5 / 5 infections detected**; 18 / 23 malicious endpoints alerted; 71 % of malicious flows; precision 99.5 %, FPR 2.0 % | Current model `58fb9fc3`. 5 captures never used in training, replayed through the live daemon. Per-IP blocking: 14 / 23 malicious IPs, 2 benign (Microsoft) IPs. 10 false alerts out of 498 benign flows. Previous model `203d33a1`: 17 / 23 endpoints, 27 % of malicious flows, 12 false alerts, same blocking result. | [Part 9](REPORT.md#part-9), [Part 7 §3](REPORT.md#part-7) |
| ONNX export | 0 / 9,597 alert decisions differ from the native models | max \|Δp\| 3.7e-4 (LightGBM) | [Part 3 §8.1](REPORT.md#part-3) |
| Batch scoring in the daemon | **740 flows in 40.3 ms**; 1,000-flow batches in 36–47 ms | Feature extraction + both ONNX models, 1 onnxruntime thread | [Part 4 §7.2](REPORT.md#part-4), [Part 3 §9.2](REPORT.md#part-3) |
| Closed loop (capture → score → block → drop) | **0 / 50 packets delivered from the blocked C2 address; nft counter exactly 50 packets / 6,400 bytes; 50 / 50 delivered from a normal peer** | Holdout DarkGate capture replayed with `sensor -r`. Daemon scored it (0.991) and blocked both C2 endpoints in nftables automatically. Throwaway network namespaces. | [Part 4 §7.2](REPORT.md#part-4) |
| Per-IP blocking rule | **Benign IPs blocked 44 → 15**; malicious IPs 70 → 56; infections with a block 16 → 15 of 28 | Old rule (any flow ≥ 0.80) vs. new default (one flow ≥ 0.95 or 2 ≥ 0.80 per IP in 1 h), on out-of-fold training scores. On the holdout it doesn't help: 2 benign (Microsoft) blocks either way, 16 → 14 of 23 malicious IPs, 5 / 5 infections. | [Part 6 §1](REPORT.md#part-6) |
| Scan detection (rule, not ML) | Lab nmap session (1,000 ports from one host) **detected after 50 ports**; the model's highest score on it was 0.32 | ≥ 50 ports on one host or ≥ 100 hosts on one port (≤ 3-packet flows) in 60 s. Benign training traffic peaks at 9 ports / 40 hosts. Tested on a replay of the session, not live. | [Part 6 §1](REPORT.md#part-6) |
| `is_alert` default | Alerts on the lab nmap replay **1,031 → 1** of 1,137 flows | Default risk policy is now `severe` instead of `any` (any nDPI risk flagged 18 % of benign flows) | [Part 6 §0](REPORT.md#part-6), [Part 3 §8.4](REPORT.md#part-3) |
| Tests | Sensor: 13 + 24 C unit checks and 14 PCAP regression tests. Engine: 14 + 16 + 38 tests. All passing (2026-10-30) | `make test-sensor`, `make test-engine`. The lab nmap replay test uses `engine-ml/tests/data/lab_nmap_flows.jsonl.gz`. | [Part 6 §4](REPORT.md#part-6) |

## Stored schema

23 sensor fields (5-tuple, `app_protocol`, `ja4_client`, `ndpi_risk_mask`, `ndpi_risk_str`, packet/byte counts, duration, 4 IAT stats, 2 packet-length stats, 2 ratios, `first_seen_us`, `last_seen_us`), plus 6 daemon columns (`ingested_at_us`, `ml_anomaly_score`, `is_alert`, `ml_c2_proba`, `ml_iforest_score`, `ml_model`) = **29 columns**. Both SQLite and ClickHouse report 29 columns for `network_flows`. Earlier documents said "24-field schema"; the sensor emits 23.

## Blocking on the holdout

**Blocking on the 5 holdout infections (remote IPs; the per-IP rows are the same for the current model `58fb9fc3` and the previous `203d33a1`, the per-flow row was measured with `203d33a1`):**

| Rule | Malicious IPs blocked | Infections with a block | Benign IPs blocked |
|---|---|---|---|
| per flow (any flow ≥ 0.80, Part 4 rule) | 17 / 23 | 5 / 5 | 5 (2 Microsoft, 3 Google) |
| **per IP (default since Part 6)** | **14 / 23** | **5 / 5** | **2 (Microsoft)** |
| per IP + `config/default_allowlist.txt` | 14 / 23 | 5 / 5 | 0 |

The 2 Microsoft addresses score ≥ 0.95, so per-IP counting can't remove them; they are in `config/default_allowlist.txt`. That last row is not an independent test, because the allowlist entries came from the holdout. The Part 4 per-flow threshold comparison is in [REPORT Part 4 §5](REPORT.md#part-4).

## Engineering issues found and fixed

| Bug | Effect | Fix |
|---|---|---|
| Garbage `ja4_client` on non-TLS flows | Invalid UTF-8 in the JSON; 9 flows in 7 nDPI test captures | nDPI keeps per-protocol data in a union; the field is now read only for TLS-family flows, with format validation |
| Out-of-order packet timestamps | Unsigned underflow: durations of ~584,000 years; 17 flows in 8 captures | min/max timestamps; a backwards step counts as IAT 0 |
| Non-Ethernet captures | 53 of 631 test captures silently produced nothing | Linux cooked, BSD loopback and raw-IP framing added; 45 now decode |
| Slow consumer | Flows lost with no error (1,001 of 1,105 delivered) | Unlimited receive buffer in the consumer; drops counted and reported; drain on close |
| Number formatting | Flows longer than ~17 min lost microsecond precision | 15 significant digits instead of 9 |
| Header reads | Undefined-behaviour misaligned reads (UBSan) | Headers copied into aligned locals |

Each fix has a regression test that fails on the old binary ([Part 3 §3](REPORT.md#part-3)). One finding is documented but deliberately not changed, to keep Part 3 reproducible: offline replay checks idle expiry only every 1,000 packets ([Part 4 §1.3](REPORT.md#part-4)).

## What is not shown

- **Unattended blocking on real hosts.** On benign captures from three real machines (two of the author's PCs, one Windows 7 host), dry-run made 22, 9 and 67 block decisions per hour on benign traffic. Benign training data from real hosts is the fix; until then, run dry-run with an allowlist ([Part 9](REPORT.md#part-9)).
- **Raw-TCP RAT beacons.** njRAT's beacon is still missed in cross-validation (0.01 per flow) even with the timing features ([Part 9 §3](REPORT.md#part-9)).
- **Detection rates in general.** Malicious traffic comes from malware-traffic-analysis.net lab captures and nDPI samples. The holdout is 5 captures from the same source; families seen in only one capture are mostly missed in CV ([Part 3 §7.3](REPORT.md#part-3)).
- **Live-capture throughput, line-rate behaviour, daemon throughput under load.** Only offline sensor throughput was measured.
- **The closed loop on live capture or against a real C2 session.** It ran on an offline replay with synthetic follow-up traffic; time from detection to block wasn't measured.
- **XDP blocking.** `mitigation-ebpf/` compiles, but attaching failed: iproute2's libbpf rejects the map definition. No XDP result is claimed ([Part 4 §6](REPORT.md#part-4)).
- **Safe production use without an allowlist.** The policy would block shared Microsoft/Cloudflare addresses seen in the data. `config/default_allowlist.txt` is only a starting point (6 addresses). Supply `--allowlist-file` with the cloud/CDN ranges you depend on ([Part 4 §2.1](REPORT.md#part-4)).
- **Scan detection in general.** The scan rule was tested on one lab nmap replay and synthetic probes. Its thresholds come from lab and corpus traffic, and slow scans (< 50 ports per minute) are not caught by design. Detection happens about 30 s after the 50th port, because the sensor exports a flow after 30 s idle. A scan "from" a server the network used in the last 24 h is reported, not blocked, because the source address can be forged; this leaves gaps listed in [Part 8 §6](REPORT.md#part-8).
- **The `pyzmq` transport.** Untested; the C `zmq_sink` path is the one that was verified.
