# SentinelFlow

**Detects malware command-and-control (C2) traffic inside encrypted connections, without decrypting them, and blocks the C2 server with nftables.**

`C` · `libpcap` · `nDPI` · `ZeroMQ` · `Python` · `LightGBM` · `ONNX Runtime` · `SQLite` / `ClickHouse` · `Grafana` · `nftables` · `eBPF/XDP (experimental)`

Most malware now talks to its C2 server over TLS, so reading the payload no longer works. SentinelFlow uses only what is still visible from outside the encryption: packet sizes and timing, the TLS client fingerprint (JA4), protocol and risk flags from nDPI, and whether a host keeps checking in with the same server at a regular rhythm (beaconing).

![Grafana: ML scores on the holdout infections. The known C2 endpoints rank at the top.](sentinel-flow/docs/part3_grafana.png)

## How it works

```
 network interface or .pcap
        │
        ▼
 ┌─ 1. Sensor (C) ─────────────────────────────────────────────┐
 │ libpcap capture → 5-tuple flow table (uthash) → nDPI         │
 │ protocol + JA4 + risk flags, Welford timing/size statistics  │
 │ → one 23-field JSON record per flow, pushed over ZeroMQ      │
 └──────────────────────────────┬───────────────────────────────┘
                                ▼
 ┌─ 2. Daemon (Python) ────────────────────────────────────────┐
 │ validate → 66 features (incl. per-conversation beacon        │
 │ timing) → LightGBM in ONNX Runtime → calibrated score        │
 │ → SQLite + JSONL, and ClickHouse/Grafana when running        │
 └──────────────────────────────┬───────────────────────────────┘
                                ▼
 ┌─ 3. Mitigator (Python) ─────────────────────────────────────┐
 │ per-IP block policy + port-scan / host-sweep rule            │
 │ → nftables set with timeouts and per-address drop counters   │
 │ never blocks private, own, DNS-resolver or allowlisted IPs   │
 └──────────────────────────────────────────────────────────────┘
```

## Results

| What was tested | Result |
|---|---|
| **5 infections never seen in training** (replayed through the live daemon) | 5 / 5 detected, 18 / 23 malicious endpoints alerted, precision 99.5 %, 10 false alerts in 498 benign flows |
| **Cross-validation**, 12,250 flows from 624 captures, grouped by capture, 5 folds × 5 seeds | ROC-AUC 0.991, PR-AUC 0.972; at the alert threshold: recall 0.79, precision 0.96, false-positive rate 1.0 % |
| **Closed loop** in throwaway network namespaces | replayed DarkGate infection → scored 0.991 → C2 blocked automatically → 0 / 50 packets from it delivered, 50 / 50 from a normal peer |
| **Sensor** | ~0.40 M packets/s offline on one core, 0 flows dropped, 0 AddressSanitizer / UBSan / LeakSanitizer errors |
| **Port scan** (rule, not ML) | lab nmap scan caught after 50 ports; the ML model alone scored it 0.32 |
| **Tests** | 51 sensor checks and 68 engine tests, all passing |

Malicious training traffic is 40 hand-labeled infection captures from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) plus nDPI's test corpus. Every number, with the command that produced it, is in [docs/RESULTS.md](sentinel-flow/docs/RESULTS.md).

## How detection works

- **No IPs or timestamps as features**, so the model can't memorise hosts or captures. It sees volume, timing, packet-size shape, up/down asymmetry, 26 nDPI risk bits, protocol class, the parsed JA4 fingerprint, and 5 conversation features: how regular earlier connections to the same server were, the typical gap, and whether their sizes repeat.
- **Evaluation that can't leak:** cross-validation is grouped by capture, and the holdout captures were labeled before any model saw them. Shared services that malware abuses (Dropbox, Telegram, IP-lookup sites) are labeled *ambiguous* and excluded rather than guessed.
- **Calibrated alert threshold:** a score of 0.80 means about 1 % of held-out benign flows would alert.
- **Blocking is stricter than alerting:** one flow ≥ 0.95, or two flows ≥ 0.80 to the same IP within an hour, or a severe nDPI risk. On the training data this cut benign IPs blocked from 44 to 15.
- **Safety rules:** private, loopback and own addresses, DNS resolvers and allowlisted ranges are never blocked. A "scan" from a server the network recently used is reported, not blocked, because its source address can be forged.

## Quick start

Linux (Ubuntu, Debian or Kali):

```bash
git clone https://github.com/AbdeldjallilZennir/sentinel-flow.git ~/sentinel
cd ~/sentinel/sentinel-flow
bash scripts/install_deps.sh --with-data   # nDPI + sensor build, Python env, 7z/tshark, runs the tests

# Demo: replay a real DarkGate infection in network namespaces and watch its C2 get blocked
python3 engine-ml/datasets/fetch_mta.py --holdout --only 2023/11/20   # one public capture, no malware
make verify-closed-loop                                              # needs sudo; prints PASS/FAIL

# Live, dry-run (nothing is blocked), dashboard on 127.0.0.1:8080
bash scripts/run_live.sh -i eth0 --serve
```

Every program, option and `make` target, plus retraining and troubleshooting: [docs/USAGE.md](sentinel-flow/docs/USAGE.md).

## Limits

- **Not ready for unattended blocking on real machines.** On normal traffic from three real hosts, dry-run made 9–67 block decisions per hour. The model needs benign training data from real hosts; until then, run it in dry-run with an allowlist.
- Malicious data comes from public lab captures, and the holdout is only 5 captures from the same source. Performance on company networks is not shown.
- njRAT's raw-TCP beacon is still missed by the model.
- Only offline sensor speed was measured, not live capture under load. IPv4 only.
- The XDP (eBPF) drop path compiles but is not attached yet; blocking uses nftables.

Full list: [docs/RESULTS.md, "What is not shown"](sentinel-flow/docs/RESULTS.md#what-is-not-shown).

## Roadmap

- XDP backend: fix the BPF map definition, share the pinned map with `xdp_ctl`, add it to the mitigator
- Rule-based beacon report for C2 the model misses (njRAT-style raw-TCP beacons)
- Benign training data from real hosts, and a larger holdout of recent infections
- Write-up of tests against live RAT samples in an isolated Windows VM

## Repository

```
sentinel-flow/
├── sensor-c/          C sensor, zmq_sink helper, unit + PCAP regression tests
├── engine-ml/         daemon, features, mitigator, dashboard, training + evaluation, tests
├── mitigation-ebpf/   XDP program and map tool (experimental)
├── dashboard/         Grafana provisioning
├── scripts/           installer, live runner, Colab training
├── tests/             closed-loop test (capture → score → block → drop)
└── docs/              USAGE, RESULTS, GUIDE (plain-language), REPORT (engineering log), LAB_SETUP
```

The [engineering log](sentinel-flow/docs/REPORT.md) records each phase, including the 15 bugs found in a code review and their regression tests. Built with AI pair-programming (Claude Code); each part of the log states what was verified and how.
