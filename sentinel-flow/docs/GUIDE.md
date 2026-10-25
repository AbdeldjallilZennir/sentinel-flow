# SentinelFlow — The Plain-Language Guide

This guide explains the whole project in simple words: what it does, how the parts fit together, what was done in each phase, and **every tool** that was used, with a short "what is it / why here" for each one.

- Exact numbers and evidence: [REPORT.md](REPORT.md) (Parts 1–8)
- What to do next: [NEXT_STEPS.md](NEXT_STEPS.md)
- Short technical overview: the root [README.md](../../README.md)

## Contents

1. [What SentinelFlow does, in one minute](#1-what-sentinelflow-does-in-one-minute)
2. [Network basics you need](#2-network-basics-you-need)
3. [How the pieces fit together](#3-how-the-pieces-fit-together)
4. [What was done, phase by phase](#4-what-was-done-phase-by-phase)
5. [Machine-learning ideas, simply](#5-machine-learning-ideas-simply)
6. [Every tool, explained](#6-every-tool-explained)
7. [The project's own programs and scripts](#7-the-projects-own-programs-and-scripts)
8. [Current results in plain words](#8-current-results-in-plain-words)
9. [Common commands](#9-common-commands)
10. [Folder map](#10-folder-map)

---

## 1. What SentinelFlow does, in one minute

When a computer gets infected with malware, the malware usually "phones home" to a server run by the attacker, to receive orders and send back stolen data. That server is called a **C2 server** (command and control). Today this traffic is almost always **encrypted** (HTTPS / TLS), so you can't read what is being said.

SentinelFlow spots this traffic **without decrypting it**. It looks only at the *shape* of the conversation:

- how many packets were sent, and how big they are
- how regular the timing is (malware often "beacons" on a fixed schedule)
- which protocol it is, and the "fingerprint" of the program that opened the connection
- warning flags raised by a traffic-analysis library

A machine-learning model turns these measurements into a score from 0 to 1. When the evidence is strong enough, SentinelFlow **blocks the attacker's address** in the Linux kernel, so the infected machine can't talk to it any more. It also detects **port scans** (someone probing many ports) with a simple rule.

> Analogy: you can't read sealed letters, but if one house sends a letter to the same unknown address every 60 seconds, always the same size, at 3 a.m., that's suspicious, even without opening the envelope.

---

## 2. Network basics you need

| Term | Plain meaning |
|---|---|
| **Packet** | A small piece of data sent over the network, like one envelope. A web page is many packets. |
| **IP address** | The address of a machine, e.g. `185.39.19.96`. |
| **Port** | A numbered "door" on a machine. Web servers use 443 (HTTPS) or 80 (HTTP), DNS uses 53. |
| **TCP / UDP** | Two ways to send packets. TCP is a phone call (connection, delivery checked); UDP is a postcard (just sent). |
| **Flow** | All packets of one conversation between two programs. Identified by the **5-tuple**: source IP, destination IP, source port, destination port, protocol. SentinelFlow works on flows, not single packets. |
| **TLS / HTTPS** | The encryption used by websites and most apps. The content is hidden, but the packet sizes and timing are still visible. |
| **TLS ClientHello** | The first message a program sends when starting a TLS connection. It's not encrypted, and it lists the program's preferences, which works like a fingerprint. |
| **DNS** | The internet's phone book: turns names (`example.com`) into IP addresses. |
| **C2 server / beacon** | The attacker's control server. A **beacon** is the malware checking in regularly ("any orders?"). |
| **PCAP file** | A recording of network traffic (`.pcap` / `.pcapng`). It can be replayed later as if it were live. |
| **IOC (Indicator of Compromise)** | A known-bad sign: an attacker's IP address, domain name or file hash, published by researchers. |
| **Private address (RFC 1918)** | Addresses used inside home and office networks (`10.x`, `172.16–31.x`, `192.168.x`). SentinelFlow never blocks these by default, so it can't cut off your own machines. |
| **CDN / cloud address** | Big shared services (Cloudflare, Microsoft, Google). One address serves thousands of sites, so blocking it hurts a lot of legitimate traffic. |
| **Allowlist** | A list of addresses that must never be blocked. |
| **Port scan / host sweep** | A port scan tries many doors on one machine; a host sweep tries one door on many machines. Attackers (and tools like nmap) do this to find targets. |
| **WinRM / SMB** | Windows remote-management and file-sharing protocols. Attackers use them to move between machines inside a network ("lateral movement"). |
| **Kernel** | The core of the operating system. Blocking there means packets are dropped before any program sees them. |

---

## 3. How the pieces fit together

```
  network card or PCAP file
            │  packets
            ▼
  ┌──────────────────────┐   Plane 1: the SENSOR (C program, sensor-c/)
  │ group packets into   │   - uses libpcap to read packets
  │ flows, measure them  │   - uses nDPI to name the protocol, flag risks,
  │                      │     fingerprint TLS (JA4)
  └─────────┬────────────┘   - sends one JSON record per finished flow
            │ ZeroMQ (fast local message pipe)
            ▼
  ┌──────────────────────┐   Plane 2: the DAEMON (Python, engine-ml/daemon.py)
  │ check, score, store  │   - checks each record is valid (23 fields)
  │                      │   - turns it into 61 numbers ("features")
  │                      │   - the ML model gives a score 0..1
  │                      │   - saves to SQLite + JSONL (+ ClickHouse)
  └─────────┬────────────┘
            │ scored flows
            ▼
  ┌──────────────────────┐   Plane 3: the MITIGATOR (engine-ml/mitigator.py)
  │ decide and block     │   - per remote address: enough evidence? → block
  │                      │   - port-scan rule → block the scanner
  │                      │   - blocking is done by nftables in the kernel
  └─────────┬────────────┘   - every decision is written to an audit log
            ▼
  dashboards: terminal / web page (query_dashboard.py) or Grafana
```

Two flows of work exist side by side:

- **Live / replay path** (above): what runs when SentinelFlow protects a network.
- **Training path:** download labeled malware recordings → run them through the same sensor → label each flow (malicious / benign / unsure) → train the model → test it on recordings it has never seen → export it as an ONNX file that the daemon loads.

---

## 4. What was done, phase by phase

**Part 1 — the sensor (C program).** The existing C sensor was built and audited. It reads packets, groups them into flows, asks nDPI what protocol each flow is, computes the JA4 fingerprint and timing statistics, and sends JSON over ZeroMQ. Several bugs were fixed, and missing pieces were found (for example, a hand-written ZeroMQ header).

**Part 1.2 — sensor follow-up.** Fixed the case where messages never arrived over ZeroMQ, fixed timestamp precision, added unit tests for byte counting, and compared results with nDPI's own tool (`ndpiReader`).

**Part 2 — receiving and storing.** Built the daemon: it receives flows, checks them, adds a score (at first a simple hand-made formula), and stores them in SQLite, a JSONL file and, optionally, ClickHouse with a Grafana dashboard.

**Part 3 — machine learning.** A full audit found and fixed seven more sensor bugs (bad memory reads, garbage fingerprints on non-TLS flows, negative durations from out-of-order packets, captures silently ignored, lost messages, and more). Then the **dataset**: 22 real malware infections from malware-traffic-analysis.net plus nDPI's test recordings, about 9,700 labeled flows. A **LightGBM** model was trained, checked with grouped cross-validation, exported to **ONNX**, and tested on **5 infections it had never seen** (the "holdout"): all 5 detected. Key finding: the old alert rule ("any nDPI warning = alert") fired on 18 % of normal traffic.

**Part 4 — blocking.** Added the mitigator: decides which address to block (never your own machines) and blocks it with **nftables**, with a timeout and per-address drop counters. Also added an "active timeout" to the sensor, so long connections are reported while still open. A **closed-loop test** in isolated virtual networks proved it end to end: replay an infection → model flags it → address blocked → 0 of 50 packets from the attacker got through, while a normal address still worked. Faster blocking with XDP was tried but couldn't be attached (needs a fix).

**Part 5 — packaging and first live test.** One-command installer, live-capture script and a two-machine lab guide. A fresh Ubuntu virtual machine passed all tests. In a live lab, an **nmap port scan** was captured completely; it wasn't blocked (the model only knows malware traffic, and private addresses are protected), and it revealed a real bug: big 64-bit risk flags were corrupted because the JSON library stores numbers as floating point. Fixed, and the model retrained.

**Part 6 — smarter rules.** The dashboard alert now uses only **severe** nDPI warnings. Blocking became **per address** instead of per flow: block when one flow is very suspicious (≥ 0.95), or when two flows to the same address are suspicious (≥ 0.80) within an hour. On training data this cut wrongly blocked normal servers from 44 to 15. A **port-scan detector** was added (50+ ports on one machine, or 100+ machines on one port, within 60 s); it catches the lab nmap scan. Then: a dashboard panel shows "detected, not blocked" events, and a starter **allowlist** file was added.

**Part 7 — more and better data.** 23 more infection recordings were labeled by hand from their IOC lists (the training set went from 28 to 51 infected recordings), and the model was retrained. On the 5 unseen infections it now spots more attacker servers (17 of 23, was 15), including delivery servers it missed before, with more false alerts (12 instead of 3; most are internal traffic, which is never blocked). Blocking results stayed the same.

**Part 8 — bug hunt.** The code was reviewed twice: once by running the dashboard on real data, and once by an automated multi-agent code review of all 41 code files. 15 bugs were found and fixed, and each one was reproduced on the old code. The most important ones:
- **Faked port scans.** An attacker could fake the sender's address on a port scan, so the system blocked the wrong server, for example your DNS server. A faked scan gives the attacker no results, because the answers go to the faked address. So scans from servers your network used in the last 24 hours are now reported but not blocked; every other scanner is still blocked at once.
- **Blocking itself.** On a machine with a public address, the blocker could block that machine itself. The daemon now reads the machine's own addresses and never blocks them.
- **Fake flows from fragments.** Split-up (fragmented) packets created fake flows that looked like a port scan. They are now grouped correctly.
- **Long connections counted many times.** The sensor reports long connections every 60 s, and these reports were counted as separate flows. The blocking rule and the dashboard totals now count each connection once.
- **Crashes and lost data.** These include a memory overwrite in `zmq_sink`, a daemon crash on one malformed record, and rows silently lost when ClickHouse failed.
- **Live-run problems.** Ctrl+C could leave the root daemon running, and a `--block` run left files that the next normal run couldn't write.
- **Dashboard.** Blocks shown as "active" forever, a page that grew without limit, an alerts panel listing non-alerts, and crashes on a busy port or a root-owned folder.

Details and limits: [REPORT.md Part 8](REPORT.md#part-8).

**Cleanup.** Unused files were removed (old copies, PDF exports, unused tools), the seven reports were merged into [REPORT.md](REPORT.md), and this guide and [NEXT_STEPS.md](NEXT_STEPS.md) were written.

---

## 5. Machine-learning ideas, simply

| Idea | Plain meaning |
|---|---|
| **Feature** | One number describing a flow, e.g. "number of packets" or "how regular the timing is". The model sees **61 features** per flow. IP addresses are deliberately *not* features, so the model can't just memorize bad addresses. |
| **Label** | The right answer for a training example: **malicious** (1), **benign** (0), or **ambiguous** (excluded: shared services like Dropbox or IP-lookup sites that malware also uses). |
| **Training** | Showing the model many labeled flows so it learns which feature patterns mean "malicious". |
| **Model** | The learned rule set. Here: **LightGBM**, many small decision trees voting together. |
| **Score** | The model's output, 0 to 1. Close to 1 = looks like C2 traffic. |
| **Threshold** | The score above which we act. Here 0.80 for an alert. |
| **Calibration** | Adjusting scores so 0.80 always means the same thing: here, only about 1 % of normal flows score that high. |
| **Cross-validation (CV)** | Split the data into 5 parts; train on 4, test on the 5th; repeat 5 times. **Grouped** means flows from the same recording are never split between training and testing, so the model can't "cheat" by seeing the same infection twice. Repeated with 5 random **seeds** to check the result is stable. |
| **Holdout** | Recordings kept completely aside and used **only** for the final test. The most honest measurement. Here: 5 infections. |
| **True / false positive** | A true positive is a correct alert on malware; a false positive (false alarm) is an alert on normal traffic. |
| **Precision** | Of all alerts, how many were really malicious. 0.95 = 95 % of alerts are correct. |
| **Recall** | Of all malicious flows, how many were caught. 0.65 = 65 % caught. |
| **False-alarm rate (FPR)** | Of all normal flows, how many were wrongly flagged. 1 % = 1 in 100. |
| **ROC-AUC / PR-AUC** | Single numbers (0 to 1) for how well the model ranks bad above good, across all thresholds. 1.0 is perfect. |
| **Overfitting** | Memorizing the training examples instead of learning general patterns. Grouped CV and the holdout guard against it. |
| **Anomaly detection** | Learning only what "normal" looks like and flagging anything unusual. The **IsolationForest** model does this; it's stored but not used for alerts, because it added false alarms. |
| **Parity check** | Making sure the exported ONNX model gives the same answers as the original model. Here: 0 different decisions on 12,127 flows. |

---

## 6. Every tool, explained

Each entry: **what it is** → **why it's used here** → *where in the project*.

### 6.1 Languages and building

- **C** — A fast, low-level programming language. → The sensor must handle hundreds of thousands of packets per second, so it's written in C. *`sensor-c/src/`*
- **Python 3** — An easy-to-read language with great data and ML libraries. → The daemon, dashboard, mitigator, dataset builder and training are Python. The daemon and dashboard use only Python's built-in library, so they run anywhere. *`engine-ml/`*
- **gcc** — The C compiler: turns C source code into a program you can run. *Used by the build.*
- **CMake** — Generates build instructions for C projects (which files, which libraries). *`sensor-c/CMakeLists.txt`*
- **Make** — Runs named recipes like `make test-engine`, so you don't have to remember long commands. *`sentinel-flow/Makefile`*
- **Bash** — The Linux command-line language. → Install, live-run, lab-test and Colab scripts. *`scripts/`, `tests/verify_closed_loop.sh`*
- **venv / pip** — `venv` makes a private Python environment for one project; `pip` installs packages into it. → `.venv-runtime` (to run the model) and `.venv-train` (to train), so project packages don't clash with the system. *`engine-ml/requirements*.txt`*

### 6.2 Capturing and understanding traffic

- **libpcap** — The standard library for capturing packets from a network card or reading PCAP files (the same engine behind tcpdump and Wireshark). → The sensor's eyes. *`sensor-c/src/main.c`*
- **PCAP / PCAPNG** — File formats for recorded traffic. → All training and test data are PCAP files. *`pcaps/` (4 small tests); downloaded malware recordings in `engine-ml/datasets/` (not stored in git)*
- **nDPI** — An open-source "deep packet inspection" library from ntop. It recognizes hundreds of protocols and apps (TLS, DNS, Microsoft 365…) from traffic patterns, and raises **risk flags** (e.g. "self-signed certificate", "suspicious DGA domain"). → Gives each flow its protocol name and a 64-bit **risk mask** (one bit per kind of warning). Built from source at a pinned version. *`sensor-c/src/ndpi_wrapper.c`; library in `~/nDPI`*
- **ndpiReader** — nDPI's own command-line tool. → Used as a reference to check the sensor gives the same answers (e.g. the same JA4 fingerprint).
- **JA4** — A modern fingerprint of a TLS client, computed from its ClientHello (TLS version, how many ciphers and extensions, application protocol). Different programs (Chrome, curl, malware) have different fingerprints. → One of the inputs to the model. *Computed by nDPI; part of the flow record*
- **Welford's algorithm** — A math method to compute an average and spread (standard deviation) step by step, without storing every value. → The sensor computes timing and packet-size statistics for every flow with very little memory. *`sensor-c/src/stats.c`*
- **uthash** — A small C library for hash tables (fast lookup tables). → The sensor's flow table: "which flow does this packet belong to?" *`sensor-c/src/uthash.h`*
- **tshark (Wireshark)** — Wireshark is the best-known traffic viewer; tshark is its command-line version. → Reads DNS answers and TLS server names from recordings, so labels written as domain names can be matched to IP addresses. Also used to check labels (Part 7). *`engine-ml/models/build_dataset.py`*
- **nmap** — A network scanner that probes which ports are open. → The live lab test (Part 5) was an nmap scan; it's now the test case for the scan detector. *`engine-ml/tests/data/lab_nmap_flows.jsonl.gz`*

### 6.3 Moving and formatting data

- **ZeroMQ (libzmq)** — A fast messaging library: one program "pushes" messages, another "pulls" them, here through a local socket file (`ipc:///tmp/ndpi_flows.sock`). → The pipe between the C sensor and the Python daemon. *`sensor-c/src/zmq_publisher.c`, `zmq_sink.c`*
- **zmq_sink** — A tiny C helper written for this project. Python's ZeroMQ package (`pyzmq`) wasn't installed, so this helper receives the messages and prints them as text lines for the daemon. *`sensor-c/src/zmq_sink.c`*
- **JSON / JSONL** — JSON is a text format for structured data (`{"src_ip": "10.0.0.5", …}`). JSONL is one JSON record per line, easy to append and replay. → Each flow is one JSON record with **23 fields**; the daemon also keeps a JSONL copy of everything.
- **cJSON** — A small C library to build and read JSON. → The sensor uses it to write flow records. (Its numbers are floating point, which caused the 64-bit risk-mask bug fixed in Part 5.) *`sensor-c/src/cJSON.c`*

### 6.4 Storing and showing data

- **SQLite** — A complete database in a single file, no server needed. **WAL mode** lets the dashboard read while the daemon writes. → Default storage for flows and mitigation events. *`engine-ml/data/sentinel_flows.db` (local, not in git)*
- **ClickHouse** — A database built for huge amounts of event data and fast analytics. → Optional storage for large volumes, and the source for Grafana. *Runs in Docker; schema in `engine-ml/sql/init_clickhouse.sql`*
- **Grafana** — A dashboard tool that draws charts and tables from databases. → Panels for protocols, traffic, JA4 fingerprints, alerts, ML detections and blocks. *`dashboard/grafana/`*
- **Docker / Docker Compose** — Docker runs software in isolated "containers"; Compose starts several of them with one command. → Starts ClickHouse and Grafana without installing them on the system. *`docker-compose.yml`*
- **query_dashboard.py** — The project's own small dashboard: the same panels in the terminal, or as a web page that refreshes every 10 s. No extra software needed. *`engine-ml/query_dashboard.py`*

### 6.5 Machine learning

- **LightGBM** — A popular, fast "gradient-boosted decision trees" library: many small trees, each fixing the mistakes of the previous ones. Works very well on tables of numbers. → The main C2 detector.
- **scikit-learn** — The standard Python ML toolbox. → Cross-validation splitting (`StratifiedGroupKFold`), the IsolationForest model, and metrics.
- **IsolationForest** — An anomaly detector: it isolates unusual points with random splits; points that are easy to isolate are "weird". → Trained only on normal traffic; its score is stored for information only.
- **numpy** — Fast number arrays for Python. → Feature matrices for training and scoring.
- **ONNX** — A standard file format for trained models, so a model trained in one tool can run anywhere. → The trained models are saved as `c2_detector.onnx` and `anomaly_iforest.onnx`. *`engine-ml/models/`*
- **skl2onnx / onnxmltools** — Converters from scikit-learn / LightGBM to ONNX. *Used by `train_pipeline.py`*
- **onnxruntime** — Microsoft's engine for running ONNX models quickly. → The daemon scores 1,000 flows in about 30–45 ms. It checks the model file's **SHA-256** fingerprint first (a checksum proving the file wasn't changed) and falls back to the simple formula if anything is wrong.

### 6.6 Data sources

- **malware-traffic-analysis.net (MTA)** — A long-running site by a security researcher, publishing recordings of real malware infections in lab networks, each with an IOC list. Downloads are password-protected ZIP files, so nobody opens them by accident. → The main source of malicious *and* realistic normal Windows traffic. Only the traffic recordings and IOC text are downloaded, **never** malware files. *`engine-ml/datasets/fetch_mta.py`, labels in `mta_labels.json`, holdout labels in `mta_holdout_labels.json`*
- **nDPI test corpus** — Hundreds of small recordings that ship with nDPI for its own tests (many apps and protocols). → Variety of normal traffic, plus a few tunnel samples.
- **7-Zip (7z)** — An archive tool. → Opens MTA's password-protected ZIP files.
- **Google Colab** — Free cloud computers that run in your browser (Jupyter notebooks). → Big downloads and training run there, so they don't use your mobile data. *`scripts/colab_train.sh`, `scripts/colab_holdout.sh`*

### 6.7 Blocking traffic in the kernel

- **nftables** — The modern Linux firewall. You create tables of rules; a **set** is a list of addresses that rules can match. Elements can have a **timeout** (auto-removed) and a **counter** (packets/bytes dropped). → SentinelFlow adds the attacker's address to the set `blocked_ipv4` in its own table `inet sentinel`, for 15 minutes by default, and drops traffic to and from it. It never touches your other firewall rules. *`engine-ml/mitigator.py`*
- **Dry-run mode** — The mitigator decides and logs what it *would* block, without blocking anything. Default in `run_live.sh`.
- **XDP / eBPF** — eBPF lets small, safety-checked programs run inside the Linux kernel; XDP runs them at the earliest point when a packet arrives (fastest possible drop). → An XDP blocker exists but couldn't be attached yet (needs a fix). *`mitigation-ebpf/`*
- **clang / libbpf / iproute2** — clang compiles the eBPF program; libbpf loads it; iproute2 (the `ip` command) attaches it to a network interface. → Used in the XDP attempt.
- **Network namespaces + veth** — A namespace is a separate, throwaway network stack inside the same Linux machine (like a mini virtual machine for networking); a veth pair is a virtual cable between two of them. → The closed-loop test builds a fake "attacker" and "victim" this way, so blocking can be tested safely without touching your real network. *`tests/verify_closed_loop.sh`, `engine-ml/tests/lab_nftables_netns.py`*

### 6.8 Testing and code quality

- **Unit tests (Python `unittest`, C test programs)** — Small automatic checks that each piece behaves as expected. Counts: sensor 13 + 24 + 11, daemon 15, mitigator 32. *`make test-sensor`, `make test-engine`*
- **Regression test** — A test that reproduces a bug that was fixed, so it can't come back unnoticed. Every sensor bug fixed from Part 3 on has one.
- **Sanitizers (AddressSanitizer, LeakSanitizer, UBSan)** — Compiler options that make a program check itself while running: bad memory access, memory leaks, undefined behavior. → The sensor ran clean on many recordings with them on.
- **valgrind** — Another popular memory checker. It was **not** used (not installed); the sanitizers above did that job from Part 3 on. Part 1 lists it as "not run".
- **Headless Chromium** — A browser without a window. → Used to take the Grafana screenshots.

### 6.9 Environment and workflow

- **Kali Linux / Ubuntu** — Linux distributions. Development happens on Kali; Ubuntu Server 24.04 was used for the fresh-install test.
- **VirtualBox** — Runs virtual machines. → The two-machine lab (sensor VM + attacker/admin machine). *`docs/LAB_SETUP.md`*
- **SSH tunnel** — Forwards a port from a remote machine over SSH. → Lets you open the VM's dashboard (port 8080) in your own browser safely.
- **Git / GitHub** — Git records every version of the code; GitHub hosts it online. A **commit** is a saved version; a **push** uploads commits. A **personal access token** is a password for scripts; never paste it into chats.
- **git stash** — A drawer where unfinished changes are put aside. → Holds unfinished code for attack-family data (see NEXT_STEPS).
- **Claude Code** — The AI coding assistant that did much of the building, testing and documentation in these sessions, through the terminal. Each report says what was and wasn't verified.

---

## 7. The project's own programs and scripts

| File | What it does |
|---|---|
| `sensor-c/build/sensor` | The packet sensor. `-i eth0` = live capture (needs root), `-r file.pcap` = replay a recording, `-A 60` = report long flows every 60 s. |
| `sensor-c/build/zmq_sink` | Receives ZeroMQ messages and prints them for the daemon. |
| `engine-ml/daemon.py` | Receives, checks, scores and stores flows; with `--mitigate dry-run` or `--mitigate nftables` it also decides and blocks. |
| `engine-ml/features.py` | Turns a flow record into the 61 numbers the model reads (shared by training and live scoring, so both always match). |
| `engine-ml/mitigator.py` | The blocking policy (what to block and why), the nftables backend, the audit log; also a small command tool: `setup`, `list`, `block IP`, `unblock IP`, `teardown`. |
| `engine-ml/query_dashboard.py` | Terminal or web dashboard, 7 panels (includes "Recent Mitigation & Scan Events"). |
| `engine-ml/datasets/fetch_mta.py` | Downloads the MTA training and holdout recordings (traffic + IOC text only). |
| `engine-ml/models/build_dataset.py` | Runs every recording through the real sensor and labels each flow. |
| `engine-ml/models/train_pipeline.py` | Trains, cross-validates (5 seeds), calibrates, exports ONNX, checks parity. |
| `engine-ml/models/evaluate_holdout.py` | Replays the 5 unseen infections through the live daemon and reports detection. |
| `engine-ml/models/compare_holdout.py` | Before/after table between two holdout results. |
| `config/default_allowlist.txt` | Starter "never block" list (2 Microsoft addresses, api.ipify.org, public DNS). Add your own. |
| `scripts/install_deps.sh` | One-command setup on Ubuntu/Debian/Kali. |
| `scripts/run_live.sh` | Live protection on one network interface (dry-run by default, `--block` for real). |
| `scripts/colab_train.sh` | Full retrain on Colab: baseline test → download data → label check → train → test → comparison → zip. |
| `scripts/colab_holdout.sh` | Re-runs only the holdout test on Colab. |
| `tests/verify_closed_loop.sh` | The safe end-to-end blocking test in throwaway network namespaces. |

---

## 8. Current results in plain words

Model `lgbm+iforest-fv1-203d33a1` (Part 7):

- **Unseen infections:** all **5 of 5** detected. The model raised alerts on **17 of 23** attacker servers.
- **Blocking (per-address rule):** **14 of 23** attacker servers blocked, at least one in every infection. **2** normal servers wrongly blocked (two Microsoft addresses), **0** if you use the starter allowlist.
- **False alerts:** 12 of 498 normal flows were flagged. 7 are internal traffic (never blocked; 6 of them are probably the attacker moving inside the network, which the labels count as normal), 2 are the Microsoft addresses, 3 are long Google connections (shown on the dashboard, not blocked).
- **Cross-validation:** catches **65 %** of malicious flows with **95 %** of alerts being correct, at about a **1 %** false-alarm rate.
- **Port scans:** the lab nmap scan is detected after 50 ports. A scanner inside your own network is reported as "detected, not blocked", and so is a scan "from" a server your network used in the last 24 hours (the sender may be faked).
- **Why "only" 27 % of malicious flows are flagged on the holdout:** most malicious flows are the same beacon repeated thousands of times. Flagging one or two is enough to block the server.

What is **not** proven: performance on real company networks, live capture speed, against malware families very different from the training data. See "What is not shown" in the README.

---

## 9. Common commands

Run from the `sentinel-flow/` folder.

```bash
# set up everything on a new Ubuntu/Debian/Kali machine
bash scripts/install_deps.sh

# run all tests
make test-sensor
make test-engine

# protect one interface live, in dry-run mode, with a web dashboard on port 8080
bash scripts/run_live.sh -i <interface> -a <your admin IP> --serve

# replay a recording through the full pipeline
export LD_LIBRARY_PATH=~/nDPI/src/lib
engine-ml/.venv-runtime/bin/python engine-ml/daemon.py --scorer onnx --mitigate dry-run \
    --allowlist-file config/default_allowlist.txt &
./sensor-c/build/sensor -r some_capture.pcap
make dashboard            # terminal view; make dashboard-web for the browser

# see / remove kernel blocks
sudo python3 engine-ml/mitigator.py list
sudo python3 engine-ml/mitigator.py unblock 203.0.113.7

# safe end-to-end blocking test (uses sudo itself)
make verify-closed-loop
```

Retraining is easiest on Colab; see [NEXT_STEPS.md](NEXT_STEPS.md#colab-commands).

---

## 10. Folder map

```
cv_work/                      the git repository
├── README.md                 technical overview with key numbers
└── sentinel-flow/
    ├── sensor-c/             Plane 1: the C sensor and its tests
    ├── engine-ml/            Plane 2 + 3: daemon, model, mitigator, dashboard
    │   ├── models/           training / evaluation programs + the trained ONNX models
    │   ├── datasets/         download script + hand-written labels (recordings not in git)
    │   ├── tests/            Python tests (+ data/ with the lab nmap session)
    │   ├── sql/              ClickHouse table definitions
    │   └── data/             local runtime data and training set (not in git)
    ├── mitigation-ebpf/      experimental XDP blocker (not attached yet)
    ├── config/               default_allowlist.txt
    ├── dashboard/grafana/    Grafana setup and dashboard
    ├── scripts/              install, live run, Colab scripts
    ├── tests/                closed-loop blocking test
    ├── pcaps/                4 small test recordings
    ├── docs/                 GUIDE.md (this file), REPORT.md, NEXT_STEPS.md,
    │                         LAB_SETUP.md, BLUEPRINT.md, screenshots
    ├── docker-compose.yml    ClickHouse + Grafana
    └── Makefile              build / test / data / train shortcuts
```
