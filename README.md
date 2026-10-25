# SentinelFlow — Encrypted-Traffic C2 Detection and Kernel Blocking, Without Decryption

SentinelFlow watches network flows, recognises command-and-control (C2) traffic **without decrypting TLS**, and blocks the C2 server in the Linux kernel. It uses flow metadata only: nDPI protocol classification, JA4 TLS fingerprints, nDPI risk flags, packet-size and inter-arrival-time statistics.

- **Plane 1:** a C sensor (libpcap + nDPI 6.1) turns packets into 23-field flow records and pushes them over ZeroMQ.
- **Plane 2:** a Python daemon validates and stores them (SQLite / ClickHouse) and scores them with a LightGBM model exported to ONNX.
- **Plane 3:** blocks the remote C2 address through an nftables set with per-address drop counters.

> **New here? Start with [`sentinel-flow/docs/GUIDE.md`](sentinel-flow/docs/GUIDE.md)**: the whole project and every tool explained in plain language.
>
> **How to read this README.** Every number below was measured on the reference host and is quoted from the project report, [`sentinel-flow/docs/REPORT.md`](sentinel-flow/docs/REPORT.md) (Parts 1–8 in one file). Each part ends with a "may / must not be said" section, and this README follows it. Limits are listed in [What is not shown](#what-is-not-shown). Planned work: [`sentinel-flow/docs/NEXT_STEPS.md`](sentinel-flow/docs/NEXT_STEPS.md).

**Status (2026-10-24):**

| Phase | Status |
|---|---|
| 1. C sensor | done |
| 2. Ingestion & analytics | done |
| 3. ML pipeline | done; dataset expanded and model retrained in Part 7 |
| 4. Kernel mitigation | done with nftables; per-IP blocking rule + scan detector (Part 6); XDP experimental, not attached |
| Packaging & VM install | done: installer, live runner, lab guide; fresh Ubuntu 24.04 VM passes all tests (Part 5) |
| 5. Demo | not started |

The original blueprint and roadmap are kept in [`sentinel-flow/docs/BLUEPRINT.md`](sentinel-flow/docs/BLUEPRINT.md).

---

## Architecture

```
 NIC / veth / PCAP file
        │
        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ PLANE 1 — C sensor  (sensor-c/, libpcap + nDPI 6.1, single thread)        │
│  • link types: Ethernet (+802.1Q), Linux cooked v1/v2, BSD loopback, raw IP│
│  • 5-tuple flow table (uthash), 30 s idle timeout, -A active timeout       │
│  • nDPI app protocol, JA4 client fingerprint (TLS-family flows only),      │
│    64-bit nDPI risk mask, Welford IAT / packet-length statistics           │
│  • 23-field JSON per flow ──► ZeroMQ PUSH                                  │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │  ipc:///tmp/ndpi_flows.sock
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ PLANE 2 — engine-ml/daemon.py (Python standard library + optional ONNX)   │
│  • ZMQ PULL (pyzmq if present, else the C zmq_sink helper)                 │
│  • validates the 23 fields, batches 1,000 rows or 1 s                      │
│  • features.py (61 features) ─► ONNX LightGBM  ─► ml_anomaly_score         │
│                                 ONNX IsolationForest ─► ml_iforest_score   │
│    (falls back to a stdlib heuristic when onnxruntime is unavailable)      │
│  • + 6 enrichment columns = 29 columns per flow                            │
│  • SQLite (WAL) + JSONL always; ClickHouse when reachable ─► Grafana       │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │  scored batch
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ PLANE 3 — engine-ml/mitigator.py                                          │
│  • BlockPolicy, per remote IP: one flow ≥ 0.95, OR 2 flows ≥ 0.80 within  │
│    1 h, OR severe nDPI risk → block the remote peer;                       │
│    port scan (≥ 50 ports / 60 s) or host sweep (≥ 100 hosts / 60 s)        │
│    → block the scanning source;                                            │
│    never RFC 1918 / loopback / link-local / multicast / allowlisted /      │
│    own addresses; protected scanners, and scans "from" servers the         │
│    network used in the last 24 h (may be forged), are only reported        │
│  • nftables: table inet sentinel, set blocked_ipv4 { flags timeout;        │
│    timeout 15m; counter; }, drop in prerouting (saddr), output/forward     │
│    (daddr); per-address packet/byte counters read back every 10 s          │
│  • audit: mitigations.jsonl, SQLite blocked_ips, ClickHouse mitigations    │
│  • XDP (mitigation-ebpf/): sources compile, NOT attached (experimental)     │
└───────────────────────────────────────────────────────────────────────────┘
```

**Stored schema:** 23 sensor fields (5-tuple, `app_protocol`, `ja4_client`, `ndpi_risk_mask`, `ndpi_risk_str`, packet/byte counts, duration, 4 IAT stats, 2 packet-length stats, 2 ratios, `first_seen_us`, `last_seen_us`), plus 6 daemon columns (`ingested_at_us`, `ml_anomaly_score`, `is_alert`, `ml_c2_proba`, `ml_iforest_score`, `ml_model`) = **29 columns**. Both SQLite and ClickHouse report 29 columns for `network_flows`. Earlier documents said "24-field schema"; the sensor emits 23.

---

## Key verified metrics

| Area | Result | Conditions | Source |
|---|---|---|---|
| Sensor throughput | **~0.40 Mpps median**, 25.8 MB peak RSS, 0 flows dropped | Offline, single thread, i7-1165G7. 124,070 packets merged from 576 nDPI test captures. Current binary: medians 407 k pps (`-A 60`) and 400 k pps (`-A 0`), range 0.36–0.42 Mpps over 10 runs. Before the Phase 4 changes: 0.40–0.44 Mpps. Live-capture throughput not measured. | [Part 3 §3.2](sentinel-flow/docs/REPORT.md#part-3) |
| Memory safety | **0** AddressSanitizer / LeakSanitizer / UBSan errors | 16 PCAPs (1,890 flows) in Part 3; 10 PCAPs with `-A 30` in Part 4. LeakSanitizer shown active on a deliberate 4,242-byte leak. | [Part 3 §3.1](sentinel-flow/docs/REPORT.md#part-3), [Part 4 §1.2](sentinel-flow/docs/REPORT.md#part-4) |
| Delivery sensor → consumer | 9,694 / 9,694 flows, 0 dropped | Same merged capture, consumer attached. Earlier silent loss fixed (receive high-water mark). | [Part 3 §3.6](sentinel-flow/docs/REPORT.md#part-3) |
| Labeled dataset | **12,250 flows from 624 PCAPs** | 2,846 malicious flows from 51 captures (40 malware-traffic-analysis.net cases with hand-curated IOC labels, plus nDPI samples). 0 rejected. Built through the production sensor → ZMQ path. Part 3 had 9,659 flows / 28 malicious captures; 23 cases added in Part 7. | [Part 3 §4–5](sentinel-flow/docs/REPORT.md#part-3), [Part 7 §1–2](sentinel-flow/docs/REPORT.md#part-7) |
| Model quality (grouped CV) | **ROC-AUC 0.984 ± 0.001, PR-AUC 0.945 ± 0.005** | Current model `203d33a1`, 5-fold grouped by capture, 5 seeds. At the 0.80 alert threshold: recall 0.65 ± 0.04, precision 0.95 ± 0.01, FPR 1.0 % ± 0.1 %. Part 3 model on the smaller set: PR-AUC 0.905, recall 0.45 (different data, not like-for-like). | [Part 7 §0](sentinel-flow/docs/REPORT.md#part-7), [Part 3 §7.1](sentinel-flow/docs/REPORT.md#part-3) |
| Unseen infections (holdout) | **5 / 5 infections detected**; 17 / 23 malicious endpoints alerted; precision 98.6 %, FPR 2.4 % | Current model `203d33a1`. 5 captures never used in training, replayed through the live daemon. Per-IP blocking: 14 / 23 malicious IPs, 2 benign (Microsoft) IPs. 12 false alerts out of 498 benign flows: 7 internal (never blocked, 6 likely attacker WinRM), 2 Microsoft, 3 long Google TLS sessions (alerted, not blocked). Previous model `2005d025`: 15 / 23 endpoints, 3 false alerts, same blocking result. | [Part 7 §3](sentinel-flow/docs/REPORT.md#part-7), [Part 3 §9.1](sentinel-flow/docs/REPORT.md#part-3) |
| ONNX export | 0 / 9,597 alert decisions differ from the native models | max \|Δp\| 3.7e-4 (LightGBM) | [Part 3 §8.1](sentinel-flow/docs/REPORT.md#part-3) |
| Batch scoring in the daemon | **740 flows in 40.3 ms**; 1,000-flow batches in 36–47 ms | Feature extraction + both ONNX models, 1 onnxruntime thread | [Part 4 §7.2](sentinel-flow/docs/REPORT.md#part-4), [Part 3 §9.2](sentinel-flow/docs/REPORT.md#part-3) |
| Closed loop (capture → score → block → drop) | **0 / 50 packets delivered from the blocked C2 address; nft counter exactly 50 packets / 6,400 bytes; 50 / 50 delivered from a normal peer** | Holdout DarkGate capture replayed with `sensor -r`. Daemon scored it (0.991) and blocked both C2 endpoints in nftables automatically. Throwaway network namespaces. | [Part 4 §7.2](sentinel-flow/docs/REPORT.md#part-4) |
| Per-IP blocking rule | **Benign IPs blocked 44 → 15**; malicious IPs 70 → 56; infections with a block 16 → 15 of 28 | Old rule (any flow ≥ 0.80) vs. new default (one flow ≥ 0.95 or 2 ≥ 0.80 per IP in 1 h), on out-of-fold training scores. On the holdout it doesn't help: 2 benign (Microsoft) blocks either way, 16 → 14 of 23 malicious IPs, 5 / 5 infections. | [Part 6 §1](sentinel-flow/docs/REPORT.md#part-6) |
| Scan detection (rule, not ML) | Lab nmap session (1,000 ports from one host) **detected after 50 ports**; the model's highest score on it was 0.32 | ≥ 50 ports on one host or ≥ 100 hosts on one port (≤ 3-packet flows) in 60 s. Benign training traffic peaks at 9 ports / 40 hosts. Tested on a replay of the session, not live. | [Part 6 §1](sentinel-flow/docs/REPORT.md#part-6) |
| `is_alert` default | Alerts on the lab nmap replay **1,031 → 1** of 1,137 flows | Default risk policy is now `severe` instead of `any` (any nDPI risk flagged 18 % of benign flows) | [Part 6 §0](sentinel-flow/docs/REPORT.md#part-6), [Part 3 §8.4](sentinel-flow/docs/REPORT.md#part-3) |
| Tests | 13 + 24 + 11 sensor tests, 15 + 32 engine tests, all passing | `make test-sensor`, `make test-engine`. The lab nmap replay test uses `engine-ml/tests/data/lab_nmap_flows.jsonl.gz`. | [Part 6 §4](sentinel-flow/docs/REPORT.md#part-6) |

---

## Quick start

### One-command setup (Ubuntu / Debian / Kali)

```bash
git clone https://github.com/AbdeldjallilZennir/sentinel-flow && cd <repository>
bash sentinel-flow/scripts/install_deps.sh            # core: packages, nDPI (pinned commit), sensor, ONNX runtime, tests
bash sentinel-flow/scripts/install_deps.sh --all      # + training venv, tshark/7z, Docker, clang (see --help)
```

Run it as your normal user; it uses `sudo` only for `apt`. It clones nDPI to `~/nDPI` at the commit this project was verified with (`90eb617a4`), builds it and the sensor, creates `engine-ml/.venv-runtime`, and runs both test suites.

Then capture live on one interface (dry-run by default; Ctrl+C stops everything cleanly):

```bash
cd sentinel-flow
bash scripts/run_live.sh -i <interface> -a <your admin IP> --serve
```

For a two-machine VM lab (host-only network, dashboard over an SSH tunnel, optional Grafana), see [`sentinel-flow/docs/LAB_SETUP.md`](sentinel-flow/docs/LAB_SETUP.md).

### Prerequisites (manual setup)

| Requirement | Notes |
|---|---|
| Linux, gcc, cmake, libpcap, libzmq | build the sensor |
| nDPI 6.x built from source at `~/nDPI` | set `-DNDPI_ROOT=…` for another path. At runtime: `export LD_LIBRARY_PATH=~/nDPI/src/lib` |
| Python 3 | the daemon and dashboard need only the standard library |
| ONNX scoring | numpy + onnxruntime, provided by `make runtime-venv` |
| Training only | `engine-ml/requirements-train.txt` |
| `sudo` | only for the closed-loop test (network namespaces + nftables) |
| Docker | only for ClickHouse + Grafana |

### Build and test

```bash
cd sentinel-flow
make sensor            # C sensor, zmq_sink, unit-test binaries
make test-sensor       # test_flow 13/13, test_stats 24/24, PCAP regression tests 11/11
make test-engine       # daemon 15/15, mitigator 32/32
make runtime-venv      # self-contained numpy + onnxruntime 1.31.0 for the ONNX scorer
```

### Closed-loop kernel-blocking test

```bash
make verify-closed-loop     # calls sudo itself; don't run "sudo make", which would build as root
```

This creates two throwaway network namespaces, replays a holdout capture through the sensor into `daemon.py --scorer onnx --mitigate nftables`, then sends packets from the blocked address and from a normal one. It prints PASS/FAIL per check and removes the namespaces on exit. The host's own nftables ruleset is not touched.

### Run the pipeline on a capture

```bash
export LD_LIBRARY_PATH=~/nDPI/src/lib
engine-ml/.venv-runtime/bin/python engine-ml/daemon.py --scorer onnx &   # add --mitigate dry-run to see block decisions
#   blocking with the starter allowlist (Microsoft, api.ipify.org, public DNS):
#   ... --mitigate dry-run --allowlist-file config/default_allowlist.txt
./sensor-c/build/sensor -r capture.pcap                                 # or: sudo ./sensor-c/build/sensor -i eth0
make dashboard                                                          # 7 panels in the terminal (SQLite)
make dashboard-web                                                      # same panels at http://127.0.0.1:8080
```

### ClickHouse + Grafana

```bash
docker compose up -d        # ClickHouse 24.8 on 127.0.0.1:8123, Grafana 13.0.1 on 127.0.0.1:3000
engine-ml/.venv-runtime/bin/python engine-ml/daemon.py --backend both --scorer onnx
```

- **Dashboard:** open http://127.0.0.1:3000. Anonymous read-only viewing is on; admin login is `admin` / `sentinel`. The provisioned "SentinelFlow" dashboard has 6 panels: protocols, traffic volume, JA4 fingerprints with ML score, alerts, ML detections, and kernel mitigations with drop counters.
- **First start needs internet:** Grafana downloads its ClickHouse plugin on first start.
- **Credentials are dev defaults,** bound to 127.0.0.1 only.

### Rebuild the ML pipeline

```bash
python3 -m venv --system-site-packages engine-ml/.venv-train
engine-ml/.venv-train/bin/pip install -r engine-ml/requirements-train.txt
make fetch-data   # MTA training + holdout captures (PCAP + IOC text only, never malware samples)
make dataset      # sensor -> ZMQ -> labeled rows (JSONL, SQLite, ClickHouse sentinel.training_flows)
make train        # grouped CV over 5 seeds, calibration, ONNX export, parity check
make holdout      # 5 unseen captures through the live daemon
```

---

## Screenshots

**Phase 2: flows from the 6 test PCAPs** (protocol mix, traffic volume, JA4 fingerprints, nDPI-risk alerts):

![Grafana — Phase 2](sentinel-flow/docs/part2_grafana.png)

**Phase 3: ML scoring of the 5 holdout infections** (JA4 fingerprints ranked by ML score, alerts, ML detections; the known C2 endpoints are at the top):

![Grafana — Phase 3](sentinel-flow/docs/part3_grafana.png)

---

## How detection works

- **Features (61):** volume, timing (IAT mean/stddev/min/max), packet-size shape, upload/download asymmetry, 26 individual nDPI risk bits, protocol class, and the parsed JA4_a part (TLS version, cipher and extension counts, ALPN). IP addresses and timestamps are deliberately excluded so the model can't memorise hosts or captures.
- **Models:**
  - LightGBM (benign vs malicious). Each capture's weight is capped so one long beacon can't dominate training.
  - IsolationForest trained on benign flows only. It's stored as `ml_iforest_score` but not used for alerting: it added false alerts without catching anything in cross-validation.
- **Calibration:** the LightGBM probability is mapped so 0.80 corresponds to 1 % of held-out benign flows, using the median over 5 CV seeds.
- **Evaluation discipline:**
  - Cross-validation is grouped by capture.
  - The holdout captures were labeled before the model saw them.
  - Labels distinguish malicious, benign and ambiguous. Ambiguous means shared services abused by malware (Dropbox, Telegram, IP-lookup sites, compromised sites), which are excluded.
- **Alert rule (`is_alert`):** ML score ≥ 0.80 or one of 6 severe nDPI risks (DGA domain, risky domain, malicious fingerprint or certificate, possible exploit, malware host contacted). This `severe` policy is the default since Part 6. In Part 3, alerting on *any* nDPI risk flagged ~18 % of real Windows background flows.
- **Blocking policy (per remote IP, Part 6):** one flow ≥ 0.95 from a trained model, or 2 flows ≥ 0.80 to the same IP within an hour, or a severe nDPI risk. A separate rule blocks the *source* of a port scan or host sweep. The ML model can't see scans: each probe looks harmless on its own. `--block-high-score 0.80 --block-repeat 1` restores the per-flow rule.

**Blocking on the 5 holdout infections (current model `203d33a1`, remote IPs):**

| Rule | Malicious IPs blocked | Infections with a block | Benign IPs blocked |
|---|---|---|---|
| per flow (any flow ≥ 0.80, Part 4 rule) | 17 / 23 | 5 / 5 | 5 (2 Microsoft, 3 Google) |
| **per IP (default since Part 6)** | **14 / 23** | **5 / 5** | **2 (Microsoft)** |
| per IP + `config/default_allowlist.txt` | 14 / 23 | 5 / 5 | 0 |

The 2 Microsoft addresses score ≥ 0.95, so per-IP counting can't remove them; they are in `config/default_allowlist.txt`. That last row is not an independent test, because the allowlist entries came from the holdout. The Part 4 per-flow threshold comparison is in [REPORT Part 4 §5](sentinel-flow/docs/REPORT.md#part-4).

---

## Engineering issues found and fixed

| Bug | Effect | Fix |
|---|---|---|
| Garbage `ja4_client` on non-TLS flows | Invalid UTF-8 in the JSON; 9 flows in 7 nDPI test captures | nDPI keeps per-protocol data in a union; the field is now read only for TLS-family flows, with format validation |
| Out-of-order packet timestamps | Unsigned underflow: durations of ~584,000 years; 17 flows in 8 captures | min/max timestamps; a backwards step counts as IAT 0 |
| Non-Ethernet captures | 53 of 631 test captures silently produced nothing | Linux cooked, BSD loopback and raw-IP framing added; 45 now decode |
| Slow consumer | Flows lost with no error (1,001 of 1,105 delivered) | Unlimited receive buffer in the consumer; drops counted and reported; drain on close |
| Number formatting | Flows longer than ~17 min lost microsecond precision | 15 significant digits instead of 9 |
| Header reads | Undefined-behaviour misaligned reads (UBSan) | Headers copied into aligned locals |

Each fix has a regression test that fails on the old binary ([Part 3 §3](sentinel-flow/docs/REPORT.md#part-3)). One finding is documented but deliberately not changed, to keep Part 3 reproducible: offline replay checks idle expiry only every 1,000 packets ([Part 4 §1.3](sentinel-flow/docs/REPORT.md#part-4)).

---

## What is not shown

- **Detection rates in general.** Malicious traffic comes from malware-traffic-analysis.net lab captures and nDPI samples. The holdout is 5 captures from the same source; families seen in only one capture are mostly missed in CV ([Part 3 §7.3](sentinel-flow/docs/REPORT.md#part-3)).
- **Live-capture throughput, line-rate behaviour, daemon throughput under load.** Only offline sensor throughput was measured.
- **The closed loop on live capture or against a real C2 session.** It ran on an offline replay with synthetic follow-up traffic; time from detection to block wasn't measured.
- **XDP blocking.** `mitigation-ebpf/` compiles, but attaching failed: iproute2's libbpf rejects the map definition. No XDP result is claimed ([Part 4 §6](sentinel-flow/docs/REPORT.md#part-4)).
- **Safe production use without an allowlist.** The policy would block shared Microsoft/Cloudflare addresses seen in the data. `config/default_allowlist.txt` is only a starting point (6 addresses). Supply `--allowlist-file` with the cloud/CDN ranges you depend on ([Part 4 §2.1](sentinel-flow/docs/REPORT.md#part-4)).
- **Scan detection in general.** The scan rule was tested on one lab nmap replay and synthetic probes. Its thresholds come from lab and corpus traffic, and slow scans (< 50 ports per minute) are not caught by design. Detection happens about 30 s after the 50th port, because the sensor exports a flow after 30 s idle. A scan "from" a server the network used in the last 24 h is reported, not blocked, because the source address can be forged; this leaves gaps listed in [Part 8 §6](sentinel-flow/docs/REPORT.md#part-8).
- **The `pyzmq` transport.** Untested; the C `zmq_sink` path is the one that was verified.

---

## Repository layout

```
sentinel-flow/
├── sensor-c/            Plane 1: C sensor, zmq_sink, unit + PCAP regression tests
├── engine-ml/
│   ├── daemon.py        Plane 2: ingestion, validation, ONNX scoring, storage, --mitigate
│   ├── features.py      shared feature vector (training = inference)
│   ├── mitigator.py     Plane 3: BlockPolicy, dry-run / nftables backends, audit sinks, CLI
│   ├── query_dashboard.py  7 panels in terminal or HTML (SQLite / ClickHouse), incl. mitigation & scan events
│   ├── models/          build_dataset, train_pipeline, evaluate_holdout, compare_holdout, *.onnx, model_meta.json
│   ├── datasets/        fetch_mta.py + curated IOC labels (captures are downloaded, not committed)
│   ├── sql/             ClickHouse schema
│   └── tests/           daemon, mitigator, nftables namespace lab; data/ = lab nmap session flows
├── mitigation-ebpf/     XDP program + map tool (experimental, not attached)
├── config/              default_allowlist.txt (starter allowlist for --allowlist-file)
├── dashboard/grafana/   provisioned datasource + 6-panel dashboard
├── scripts/             install_deps.sh, run_live.sh, colab_train.sh, colab_holdout.sh
├── tests/verify_closed_loop.sh
├── docs/
│   ├── GUIDE.md         plain-language explanation of the project and every tool  ← start here
│   ├── REPORT.md        full project report, Parts 1–8 (all measurements and evidence)
│   ├── NEXT_STEPS.md    proposed datasets and open items
│   ├── LAB_SETUP.md     two-machine VirtualBox lab
│   ├── BLUEPRINT.md     original project plan (kept unchanged)
│   └── *.png            dashboard screenshots
├── docker-compose.yml   ClickHouse + Grafana
└── Makefile             build, test, dataset, train, holdout targets
```
