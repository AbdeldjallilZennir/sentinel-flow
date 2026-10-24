> Original project blueprint and roadmap (the root README.md before 2026-10-24), kept unchanged for reference. The current status is in the root README.md and [REPORT.md](REPORT.md).

# Project Blueprint: SentinelFlow — Zero-Decrypt Encrypted Traffic Analyzer & XDP IPS

> **Status (2026-10-23):** Phases 1–3 built and verified — see [REPORT.md](REPORT.md), Parts 1–3.  
> Phase 1: C sensor (nDPI 6.x, JA4, Welford stats, ZMQ) · Phase 2: ingestion daemon, SQLite/ClickHouse, Grafana · Phase 3: labeled dataset, LightGBM + IsolationForest → ONNX, live scoring in `daemon.py`.  
> **Next:** Phase 4 (nftables / XDP mitigation)

## 1. Executive Summary (PFE / Internship Pitch)
Modern network threats (Cobalt Strike C2, ransomware beacons, DNS-over-HTTPS tunneling, and data exfiltration) operate almost exclusively over TLS 1.3 and QUIC, rendering traditional payload-based Deep Packet Inspection (DPI) blind. 
**SentinelFlow** is a high-performance Network Detection and Response (NDR) system that combines a C-based packet sensor (`libpcap` + `nDPI 6.0`), a real-time Machine Learning inference engine (`LightGBM`/`ONNX`) analyzing encrypted flow metadata (JA4 fingerprints, packet size distributions, and inter-arrival times), a columnar time-series store (`ClickHouse`), and an active kernel-level mitigation engine (`eBPF/XDP` & `nftables`).

---

## 2. System Architecture & Data Pipeline

[NIC / veth0] 
   │
   ▼
[Plane 3: eBPF XDP Filter (Kernel Space)]
   ├── Lookup src_ip in BPF_MAP_TYPE_HASH (blocked_ips)
   ├── Match Found? ──► XDP_DROP (Dropped at driver level, zero CPU wasted)
   └── No Match?    ──► XDP_PASS (Passed to user space)
                           │
                           ▼
[Plane 1: C Flow Sensor (User Space: libpcap + libndpi 6.0)]
   ├── Tracks 5-tuple flows in a custom C hash table
   ├── Dissects L7 protocol, JA4 fingerprint, SNI/ALPN, and nDPI flow_risks
   ├── Computes statistical telemetry over first N packets (IAT & packet lengths)
   └── Serializes flow JSON/MsgPack ──► [ZeroMQ PUSH Socket (ipc:///tmp/ndpi_flows.sock)]
                                               │
                                               ▼
[Plane 2: ML Analytics & Ingestion Daemon (Python + PyZMQ + ONNX Runtime)]
   ├── Pulls flow records asynchronously from ZeroMQ
   ├── Evaluates Encrypted Traffic Feature Vector via ONNX (LightGBM + IsolationForest)
   ├── If Threat Score > Threshold (or nDPI risk_mask != 0):
   │     └── Updates eBPF XDP Map / nftables blocklist to drop offending IP
   └── Buffers flows and bulk-inserts every 1,000 records / 1 sec into [ClickHouse DB]
                                                                              │
                                                                              ▼
                                                       [Grafana + FastAPI/TUI Control Center]

---

## 3. Repository Directory Structure

> **Scaffold status:** All directories and stub files below have been created at `cv_work/sentinel-flow/`.

```
sentinel-flow/
├── docker-compose.yml          # ClickHouse, Grafana, and simulated target containers
├── Makefile                    # One-command build, test, and PCAP replay automation
├── sensor-c/                   # Plane 1: High-speed C packet capture & nDPI engine
│   ├── CMakeLists.txt
│   └── src/
│       ├── main.c              # libpcap loop & signal handling
│       ├── flow_table.c        # 5-tuple hash table & flow expiration logic
│       ├── ndpi_wrapper.c      # nDPI 6.0 initialization, JA4 & risk extraction
│       ├── stats.c             # Welford's algorithm for running IAT/pkt size mean/stddev
│       └── zmq_publisher.c     # ZeroMQ non-blocking IPC push
├── mitigation-ebpf/            # Plane 3: Active kernel packet dropping
│   ├── xdp_blocker.bpf.c       # 50-line XDP program checking blocked_ips BPF map
│   └── nftables_fallback.sh    # Dynamic nftables set setup script
├── engine-ml/                  # Plane 2: Python ZeroMQ consumer, ML inference & DB writer
│   ├── requirements.txt
│   ├── daemon.py               # Async ZeroMQ consumer + ClickHouse batch inserter
│   ├── mitigator.py            # Updates pinned BPF map or nftables set on alert
│   └── models/
│       ├── train_pipeline.py   # Trains LightGBM & IsolationForest on PCAP flow datasets
│       └── c2_detector.onnx    # Exported production model for sub-ms inference
├── dashboard/                  # Provisioned Grafana dashboards & TUI/Web alert viewer
│   └── grafana/
└── pcaps/                      # Normal traffic + Cobalt Strike / C2 PCAPs for tcpreplay
```

---

## 4. Phase 1 — ✅ COMPLETE

**C Sensor with nDPI 6.x, JA4 extraction, and ZMQ export is fully operational.**

### Quick Start
```bash
cd sentinel-flow
make              # Build the C sensor
make test         # Run on test DNS PCAP
```

### Build from Source
```bash
cd sensor-c
mkdir -p build && cd build
cmake ..
make -j$(nproc)
./sensor -r /path/to/capture.pcap
./sensor -i eth0  # live capture (requires root)
```

### Validated Features
- ✅ **libpcap** offline (`-r`) and live (`-i`) packet capture
- ✅ **nDPI 6.1.0** protocol detection (HTTP, DNS, TLS, QUIC, SSH, etc.)
- ✅ **JA4 TLS fingerprint** extraction from `flow->metadata.protos.tls_quic.ja4_client`
- ✅ **nDPI risk bitmask** (64-bit anomaly flags: self-signed cert, unsafe cipher, etc.)
- ✅ **Welford's statistics** for IAT and packet length (mean, stddev, min, max)
- ✅ **uthash** 5-tuple flow table with 30s idle expiration
- ✅ **ZeroMQ PUSH** non-blocking JSON export over IPC/TCP
- ✅ **24-field JSON schema** per flow (the sensor actually emits 23 fields; see [REPORT.md](REPORT.md), Part 3)
- ✅ Clean shutdown (SIGINT/SIGTERM), no memory leaks

### Test Results (Validated on nDPI test corpus)
```
dns.pcap         → 17 packets, 1 flow exported    ✅
http.pcapng      → 10 packets, 1 flow exported    ✅
443-chrome.pcap  → 1 packet, 1 flow exported      ✅
```

**Next:** Phase 4 (active mitigation). Phases 2 and 3 are documented in [REPORT.md](REPORT.md), Parts 2 and 3.

See [REPORT.md](REPORT.md), Parts 1 and 1.2, for implementation details.

---

## 5. Encrypted Traffic Feature Vector (The Academic PFE Core)
Without decrypting TLS 1.3 or QUIC payloads, the C sensor extracts the following features across the first 15 packets of every bidirectional flow:

1. **Cryptographic & Handshake Metadata (from nDPI 6.0):**
   - `ja4_client`: JA4 TLS/QUIC client fingerprint (identifies the underlying TLS library/malware stub even if SNI is spoofed).
   - `tls_version`, `alpn_list`, `cipher_suites_count`, `cert_self_signed` flag.
   - `ndpi_risk_bitmask`: Built-in nDPI 6.0 risk flags (e.g., Known Malware Contact, Slow DoS, Suspicious Entropy, TLS Not Carrying HTTPS).
2. **Temporal Features (Detects C2 Beaconing & Heartbeats):**
   - `iat_mean`, `iat_stddev`, `iat_min`, `iat_max`: Packet Inter-Arrival Time statistics (Calculated on the fly in C using Welford's online algorithm so individual packet timestamps don't need to be stored).
   - `flow_duration_ms`: Total elapsed time of the flow window.
3. **Volumetric & Asymmetry Features (Detects Data Exfiltration & C2 Commands):**
   - `pkt_len_mean`, `pkt_len_stddev`: Mean and standard deviation of L4 payload sizes.
   - `bytes_up_down_ratio`: Ratio of client-to-server bytes vs. server-to-client bytes (high outbound ratio over unusual TLS sessions indicates exfiltration).
   - `small_pkt_ratio`: Proportion of packets with payload < 100 bytes (typical of interactive reverse shells or SSH/TLS tunnels).

---

## 5. Phased Implementation Roadmap (Avoid Overwhelm)

### Phase 1: The C Sensor & IPC Spine (Days 1–5)
- [ ] Write a minimal C program using `libpcap` that reads from either a live interface (`eth0`/`veth0`) or an offline `.pcap` file (`pcap_open_offline` is much easier for debugging!).
- [ ] Integrate `libndpi` (v6.0) and implement a basic 5-tuple hash table (`uthash.h` is a single-header C library that makes hash tables in C effortless).
- [ ] Extract protocol name, JA4 fingerprint, and `ndpi_flow_risk_bitmap`.
- [ ] Implement Welford's running variance in C to compute `iat_mean`, `iat_stddev`, `pkt_len_mean`, and `pkt_len_stddev` per flow.
- [ ] Send completed/expired flows as JSON strings over a ZeroMQ `ZMQ_PUSH` socket (`ipc:///tmp/ndpi_flows.sock`).

### Phase 2: ClickHouse Ingestion & Instant Visibility (Days 6–8)
- [ ] Spin up ClickHouse and Grafana via `docker-compose.yml`.
- [ ] Write `daemon.py` using `pyzmq` (`ZMQ_PULL`) and `clickhouse-connect`.
- [ ] Buffer incoming flows in memory and flush them to a ClickHouse `MergeTree` table (`network_flows`) every 1 second or 1,000 rows.
- [ ] Connect Grafana to ClickHouse and build 4 panels: Top Application Protocols, JA4 Fingerprint anomalies, Traffic Volume over Time, and High-Risk Flows.

### Phase 3: The Encrypted Traffic ML Pipeline (Days 9–14)
- [ ] Download benign PCAPs + malicious C2/exfiltration PCAPs (from *Malware-Traffic-Analysis.net* or the *CIC-Bell-DNS / CIC-IDS* datasets).
- [ ] Run those PCAPs through your Phase 1 C sensor (`./sensor -r capture.pcap`) to generate labeled rows in ClickHouse! (This ensures zero feature mismatch between training and live production).
- [ ] Train a `LightGBM` classifier (benign vs. C2/Exfiltration) and an unsupervised `IsolationForest` model in `train_pipeline.py`, then export to `.onnx`.
- [ ] Load the `.onnx` model inside `daemon.py` using `onnxruntime` to score incoming flow batches in real time.

### Phase 4: Active Mitigation Engine (Days 15–18)
- [ ] Step A (Fast Win): Create an `nftables` table with a dynamic timeout set (`blocked_ips`). Have `mitigator.py` add any IP with `ml_anomaly_score > 0.85` to the set for 10 minutes.
- [ ] Step B (Systems Flex): Write `xdp_blocker.bpf.c` using `libbpf`. Pin a `BPF_MAP_TYPE_HASH` at `/sys/fs/bpf/blocked_ips`. When `mitigator.py` writes a 32-bit IPv4 key into that map, XDP drops all packets from that IP at line rate and increments a drop counter.

### Phase 5: Reproducible Demo & Polish (Days 19–21)
- [ ] Write a `Makefile` target (`make demo`) that creates a Linux virtual ethernet pair (`veth0` <-> `veth1`), attaches the C sensor and XDP program to `veth0`, and uses `tcpreplay` on `veth1` to replay a mixed benign + Cobalt Strike PCAP.
- [ ] Record a 45-second terminal + Grafana video showing the exact moment the C2 beacon is fingerprinted by JA4/ML and blocked by XDP.


### 3 Practical Rules So You Don't Scrap It Again

1. **Use `uthash.h` and `cJSON.h` in your C sensor:** Don't waste three days writing your own hash table or string-formatting JSON by hand in C. Drop `uthash.h` (single header file) and `cJSON.h` into your `sensor-c/src/` folder. You will have a bug-free 5-tuple flow table working in two hours.
    
2. **Test with `pcap_open_offline()` before live interfaces:** Developing on live network interfaces is frustrating because traffic is unpredictable. Build your C sensor so passing `-r sample.pcap` reads deterministically from a saved file, and `-i eth0` reads live. You can even use your own C sensor to convert training `.pcap` files into CSV/ClickHouse rows for your ML model.
    
3. **Use Welford's Algorithm for Flow Features:** Never store an array of every packet's timestamp or size inside your C flow struct—it wastes RAM and causes segfaults on long flows. Welford's online algorithm lets you update the running `mean` and `variance` of packet sizes and inter-arrival times using just **three `double` variables** per flow.

## questions:

-  why does using TLS 1.3 and QUIC render traditional payload-based Deep Packet Inspection (DPI) blind.
- 