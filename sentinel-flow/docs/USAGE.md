# How to run SentinelFlow

Install, run, replay, retrain and troubleshoot, with every option. For the project overview, see the [README](../../README.md).

Run every command from the `sentinel-flow/` folder unless it says otherwise.

**Contents:** [How the parts fit](#how-the-parts-fit) · [1. Install](#1-install-once) · [2. Run live](#2-run-it-live-one-command) · [3. Replay a capture](#3-replay-a-capture-file) · [4. Every program and option](#4-every-program-and-its-options) · [5. `make` targets](#5-what-each-make-target-does) · [6. Rebuilding](#6-rebuilding-after-a-change) · [7. Retraining the model](#7-retraining-the-model) · [8. Environment variables](#8-environment-variables) · [9. Troubleshooting](#9-troubleshooting)

## How the parts fit

```
 network interface  or  capture file (.pcap)
          │
          ▼
 sensor   sensor-c/build/sensor (C)        packets → flows, one 23-field JSON record per flow
          │  ZeroMQ socket  ipc:///tmp/ndpi_flows.sock
          ▼
 daemon   engine-ml/daemon.py (Python)     checks each record, scores it with the ML model,
          │                                stores it, and (if asked) blocks the attacker
          ├─► SQLite + JSONL in engine-ml/data/      always
          ├─► ClickHouse                              when it is running
          └─► nftables blocks                         with --mitigate nftables
          ▼
 dashboards   engine-ml/query_dashboard.py   terminal tables or a web page (SQLite or ClickHouse)
              Grafana                        charts (ClickHouse only)
```

- **The ML model is not a separate program.** The daemon loads it from `engine-ml/models/`: `c2_detector.onnx` and `anomaly_iforest.onnx`, checked against `model_meta.json`. Loading it needs `numpy` and `onnxruntime`, which are installed in `engine-ml/.venv-runtime`. So start the daemon with `engine-ml/.venv-runtime/bin/python` (`make daemon` and `run_live.sh` do this). If it starts with a Python that lacks `onnxruntime`, it logs `ONNX unavailable` and falls back to a simple formula (`heuristic_v1`) that never blocks anything.
- **Start the daemon before the sensor.** The daemon creates the socket that the sensor sends to.

## 1. Install (once)

```bash
git clone https://github.com/AbdeldjallilZennir/sentinel-flow.git ~/sentinel
cd ~/sentinel/sentinel-flow
bash scripts/install_deps.sh            # core: everything needed to capture, score, store and block
bash scripts/install_deps.sh --all      # core + training, dataset tools, Docker, XDP compiler
```

Run it as your normal user; it uses `sudo` only for `apt`. Supported: Ubuntu, Debian, Kali. It does these steps:

1. installs packages: compiler, cmake, libpcap, libzmq, Python venv, nftables, iproute2
2. clones nDPI to `~/nDPI`, checks out the commit this project was verified with (`90eb617a4`) and builds it
3. builds the sensor (`make sensor`)
4. creates `engine-ml/.venv-runtime` with `numpy` + `onnxruntime 1.31.0`, for the ML model
5. runs `make test-sensor` and `make test-engine`

| Option | What it adds or changes |
|---|---|
| `--with-training` | `engine-ml/.venv-train` with LightGBM, scikit-learn and the ONNX export tools (to retrain the model) |
| `--with-data` | `tshark` and `7z` (to rebuild the training dataset) |
| `--with-docker` | Docker + Compose (for ClickHouse and Grafana) |
| `--with-xdp` | clang/llvm for the experimental XDP code (not attached; [Part 4 §6](REPORT.md#part-4)) |
| `--all` | all four above |
| `--ndpi-dir DIR` | build nDPI somewhere other than `~/nDPI` |
| `--ndpi-ref REF` | build a different nDPI commit |
| `--skip-tests` | don't run the tests at the end |
| `-h`, `--help` | show this list |

Without a terminal (e.g. over `ssh` from a script), set `SUDO_ASKPASS` to a program that prints the sudo password.

**Manual install instead:** Linux with gcc, cmake, libpcap and libzmq; nDPI 6.x built from source (default path `~/nDPI`); then `make sensor` and `make runtime-venv`. Python 3 alone is enough for the dashboard and for the daemon without the ML model. `sudo` is needed for live capture and real blocking. Docker is needed only for ClickHouse + Grafana.

## 2. Run it live (one command)

```bash
bash scripts/run_live.sh -i eth0 -a 192.168.56.1 --serve      # watch and decide, block nothing (dry-run)
bash scripts/run_live.sh -i eth0 -a 192.168.56.1 --block      # really block, with nftables
```

`run_live.sh` does this:
1. starts the daemon with the ML model (`--scorer onnx`)
2. with `--serve`, starts the web dashboard on http://127.0.0.1:8080
3. starts the sensor on the interface, with `sudo`

**Ctrl+C** stops the sensor first, so it sends its open flows. Then the script stops the daemon and the dashboard, and prints the last daemon lines.

| Option | Meaning | Default |
|---|---|---|
| `-i IFACE` | interface to capture on (**required**). List them with `ip -br addr` | – |
| `-a IP` or `-a CIDR` | never block this address, e.g. your own admin machine. Repeatable | none |
| `-A SEC` | active timeout: report long connections every SEC seconds while they are still open | 60 |
| `--block` | block for real with nftables (table `inet sentinel`); the daemon then runs as root. Blocks expire after 15 min | dry-run |
| `--serve` | also start the web dashboard on 127.0.0.1:8080 | off |
| `--data-dir DIR` | where the database, flows, decisions and logs go | `engine-ml/data` |
| `--no-clickhouse` | don't write to ClickHouse, even if it is running | write if running |
| `-h`, `--help` | show the options | |

- **Dry-run vs. block:** in dry-run, every decision (block, or "detected, not blocked") goes to `mitigations.jsonl` and dashboard panels 6 / 6b, and nothing is blocked. Start with dry-run and look at what *would* be blocked.
- **Files it writes** (in the data dir): `sentinel_flows.db` (SQLite), `flows.jsonl` (every flow), `mitigations.jsonl` (every decision), `rejected.jsonl` (invalid records), and `logs/sensor-*.log`, `logs/daemon-*.log`, `logs/dashboard-*.log`.
- **After a `--block` run**, the script gives root-owned output files back to you, so normal runs can write them.
- **From another machine**, open the dashboard through an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 user@sensor-host`, then browse http://127.0.0.1:8080. Two-machine VM lab: [`docs/LAB_SETUP.md`](LAB_SETUP.md).
- **Other daemon options** (for example `--allowlist-file config/default_allowlist.txt`) aren't passed by `run_live.sh`. For those, run the parts by hand (sections 3 and 4).

## 3. Replay a capture file

No root needed. Use two terminals:

```bash
# terminal 1 — the daemon with the ML model; add --mitigate dry-run to see block decisions
engine-ml/.venv-runtime/bin/python engine-ml/daemon.py --mitigate dry-run

# terminal 2 — push a capture through the sensor (try pcaps/test_http.pcapng)
sensor-c/build/sensor -r capture.pcap

# then look at the results (terminal 2)
make dashboard          # tables in the terminal
make dashboard-web      # the same as a web page on http://127.0.0.1:8080 (Ctrl+C to stop)
```

- The daemon keeps listening after the capture ends. Stop it with Ctrl+C; it writes its last batch first.
- Results **add up across runs** in `engine-ml/data/`. For a clean start, move those files away, or give the daemon and dashboard another `--db` (and the daemon another `--jsonl`).
- To replay **stored records without the sensor** (e.g. a `flows.jsonl`): `daemon.py --from-jsonl FILE`.
- To **stop automatically**: `daemon.py --max-messages N` exits after N flows.

## 4. Every program and its options

### Sensor — `sensor-c/build/sensor`

```bash
sensor-c/build/sensor -r capture.pcap        # read a capture file
sudo sensor-c/build/sensor -i eth0           # live capture (needs root)
sensor-c/build/sensor -r capture.pcap -v     # also print each flow's JSON
```

| Option | Meaning | Default |
|---|---|---|
| `-r FILE` | read a capture file (pcap or pcapng) | – |
| `-i IFACE` | capture live from an interface (needs root or `CAP_NET_RAW`) | – |
| `-z ENDPOINT` | ZeroMQ address to send flows to; must match the daemon's `--endpoint` | `ipc:///tmp/ndpi_flows.sock` |
| `-A SEC` | active timeout: send a snapshot of a connection still open after SEC seconds, then every SEC seconds (0 = off, max 86400). Values below 30 (the idle timeout) also snapshot short flows that already ended, so the sensor warns | 60 |
| `-v` | also print every flow record to stdout | off |
| `-h` | help | |

- **When a flow is sent:** after 30 s without packets (idle timeout), at each active-timeout snapshot, and for every open flow when the file ends or you press Ctrl+C. In file replay, the idle check runs every 1,000 packets.
- **What is decoded:** IPv4 only. Link types: Ethernet, Linux cooked (SLL/SLL2), BSD loopback, raw IP.
- **At exit** it waits up to 60 s for the daemon to take queued flows, then prints a summary: packets, flows, exported, dropped.

### Daemon — `engine-ml/daemon.py`

```bash
engine-ml/.venv-runtime/bin/python engine-ml/daemon.py [options]
```

Input:

| Option | Meaning | Default |
|---|---|---|
| `-e`, `--endpoint ADDR` | ZeroMQ address to listen on | `ipc:///tmp/ndpi_flows.sock` |
| `--transport auto\|pyzmq\|zmq_sink` | how to listen: `pyzmq` if that Python package is installed (untested), otherwise the C helper `zmq_sink` | auto |
| `--zmq-sink PATH` | path of the `zmq_sink` helper | `sensor-c/build/zmq_sink` |
| `--from-jsonl FILE` | read records from a file instead of the sensor (`-` = stdin); for replays and backfills | – |
| `--max-messages N` | exit after N accepted flows (0 = run until stopped) | 0 |

Storage:

| Option | Meaning | Default |
|---|---|---|
| `--backend auto\|sqlite\|clickhouse\|both` | `auto`: SQLite + JSONL always, ClickHouse when reachable (checked again every 30 s). `sqlite`: never ClickHouse. `clickhouse`: ClickHouse only; stops with an error if a write fails. `both`: all three; exits at start if ClickHouse is down | auto |
| `--db FILE` | SQLite database | `engine-ml/data/sentinel_flows.db` |
| `--jsonl FILE` | every stored flow, one JSON object per line | `engine-ml/data/flows.jsonl` |
| `--rejected FILE` | records that failed validation, with the reason | `engine-ml/data/rejected.jsonl` |
| `--ch-url URL` | ClickHouse HTTP address | `$CLICKHOUSE_URL` or `http://localhost:8123` |
| `--ch-table NAME` | ClickHouse table | `sentinel.network_flows` |
| `--ch-user`, `--ch-password` | ClickHouse login | `$CLICKHOUSE_USER` / `$CLICKHOUSE_PASSWORD`, or `sentinel` / `sentinel` |
| `--batch-size N` | rows per write | 1000 |
| `--flush-interval SEC` | write a partial batch after this long | 1.0 |

Scoring and alerts:

| Option | Meaning | Default |
|---|---|---|
| `--scorer auto\|onnx\|heuristic` | `auto`: the ML model if it loads, otherwise the heuristic. `onnx`: exit if the model can't load. `heuristic`: simple formula only (never blocks) | auto |
| `--models-dir DIR` | where the `.onnx` files and `model_meta.json` are | `engine-ml/models` |
| `--lab-conversations` | also keep conversation history (timing features) for private servers. Only for host-only lab tests: the model was trained on Internet servers only | off |
| `--alert-risk-policy severe\|any\|none` | which nDPI risks set `is_alert` on their own (an ML score ≥ 0.80 always does). `severe`: the 6 serious risks. `any`: every risk, the old Part 2 rule (fires on ~18 % of normal flows). `none`: ML score only | severe |

Blocking (`--mitigate`; rules explained in [How detection works](../../README.md#how-detection-works)):

| Option | Meaning | Default |
|---|---|---|
| `--mitigate none\|dry-run\|nftables` | `none`: no blocking. `dry-run`: decide and log, block nothing. `nftables`: block in the kernel (needs root, or passwordless `sudo` for `nft`) | none |
| `--block-timeout SEC` | how long a block lasts | 900 (15 min) |
| `--block-high-score X` | one flow scoring ≥ X blocks its remote address | 0.95 |
| `--block-repeat N` | N flows ≥ 0.80 to one remote address block it | 2 |
| `--block-repeat-window SEC` | time in which those N flows must happen | 3600 |
| `--no-severe-risk-blocks` | don't block on severe nDPI risks, only on the ML score | off |
| `--scan-ports N` | port scan: N ports on one host from one source within the scan window (0 = off) | 50 |
| `--sweep-hosts N` | host sweep: N hosts on one port from one source, short flows only (0 = off) | 100 |
| `--scan-window SEC` | scan / sweep time window | 60 |
| `--protected-cidr CIDR` | never block these; repeatable or comma-separated. **Replaces** the default list | RFC 1918 + 127.0.0.0/8 |
| `--allow-private-blocks` | remove RFC 1918 from the protected list (lab tests only) | off |
| `--allowlist IP/CIDR` | never block this; repeatable | none |
| `--allowlist-file FILE` | file of IPs / CIDRs never blocked (`#` comments), e.g. `config/default_allowlist.txt` | none |
| `--mitigate-netns NAME` | apply nftables inside this network namespace (used by the tests) | – |
| `--mitigations-jsonl FILE` | log of every decision | `engine-ml/data/mitigations.jsonl` |

- **Never blocked, whatever the options:** loopback, link-local, multicast, broadcast, reserved addresses, and this machine's own addresses. A scan "from" a server your network used in the last 24 h is reported, not blocked, because the sender's address can be faked ([Part 8](REPORT.md#part-8)).
- **Blocks outlive the daemon:** when it stops, existing blocks stay until they expire. See them with `sudo nft list table inet sentinel` or `python3 engine-ml/mitigator.py list`.
- **Stopping:** Ctrl+C or SIGTERM writes the pending batch, then exits.

### Dashboard — `engine-ml/query_dashboard.py`

```bash
python3 engine-ml/query_dashboard.py                      # tables in the terminal   (= make dashboard)
python3 engine-ml/query_dashboard.py --serve              # web page on 127.0.0.1:8080 (= make dashboard-web)
python3 engine-ml/query_dashboard.py --backend clickhouse # read ClickHouse instead of SQLite
python3 engine-ml/query_dashboard.py --new-test "nmap scan"   # start a new test (same as the page's button)
```

**Tests (telling runs apart).** Click **Start new test** on the web page (optionally with a name), or run `--new-test NAME`. From then on, the page and the terminal show only flows and blocking events stored after that moment, so each test starts empty. A clock shows when the test started and how long it has run.
- **Nothing is deleted:** pick an earlier test or **All flows** under *View* on the page, or use `--test N` / `--test all` in the terminal.
- **Where tests are kept:** in `sentinel_flows.tests.json` next to the database, so the page, the terminal and later runs agree. The database itself stays read-only, so this works even when it belongs to root.
- **Where test times come from:** a flow belongs to the test that was running when the daemon *stored* it, not to the time inside the capture. So replaying an old capture lands in the current test.

| Option | Meaning | Default |
|---|---|---|
| `--backend sqlite\|clickhouse` | where to read from | sqlite |
| `--db FILE` | SQLite database (must exist: run the daemon first) | `engine-ml/data/sentinel_flows.db` |
| `--ch-url`, `--ch-user`, `--ch-password` | ClickHouse address and login (same defaults as the daemon) | |
| `--show-sql` | also print each panel's SQL | off |
| `--json` | print everything as JSON instead of tables | off |
| `--serve` | serve a web page that reloads every 10 s; the data is also at `/api/panels.json` | off |
| `--host ADDR` | address the web page listens on | 127.0.0.1 |
| `--port N` | port of the web page | 8080 |
| `--test N\|latest\|all` | which test the terminal / `--json` output shows | latest |
| `--new-test [NAME]` | start a new test now and exit (no name: "Test N") | – |
| `--tests-file FILE` | where tests are saved | next to the database, `*.tests.json` |

- **Summary line:** number of flows, alerts, flows with an nDPI risk, timestamp mismatches, flows with ML score ≥ 0.80, and the scorer in use.
- **Panels:**
  - **1** protocol breakdown
  - **2** JA4 fingerprints (newest 100 TLS flows)
  - **3** alerts (top 100 by score)
  - **4** timestamp check (mismatches first, then the newest 100)
  - **5** top 15 ML scores
  - **6** blocked addresses, with status, the last block time and kernel drop counters
  - **6b** the latest 50 block / scan / "detected, not blocked" events
- **Counting:** each connection counts once, by its latest snapshot.
- **Panels 6 and 6b** say "no mitigation data yet" until the daemon has run with `--mitigate`.
- **Safe to run while the daemon is writing:** it opens the database read-only.
- **The web page** updates itself every 10 s without reloading. It has **Pause** and a light / dark theme switch, and shows times in your local time zone; the terminal prints UTC.

### Grafana + ClickHouse (optional)

```bash
docker compose up -d                                     # or: make stack-up
engine-ml/.venv-runtime/bin/python engine-ml/daemon.py   # backend auto also writes to ClickHouse once it is up
docker compose down                                      # or: make stack-down (data is kept)
```

- **Grafana:** http://127.0.0.1:3000. Anonymous read-only viewing; admin login `admin` / `sentinel`. The provisioned "SentinelFlow" dashboard has 6 panels: protocols, traffic volume, JA4 fingerprints with ML score, alerts, ML detections, and kernel blocks with drop counters.
- **ClickHouse:** http://127.0.0.1:8123, login `sentinel` / `sentinel`. Both ports are bound to 127.0.0.1 only, and the logins are development defaults.
- **First start needs internet:** Grafana downloads its ClickHouse plugin.
- **Schema:** ClickHouse creates its tables from `engine-ml/sql/init_clickhouse.sql` on first start, when its data volume is new.
- **Data is kept** in the Docker volumes `clickhouse-data` and `grafana-data`. `docker compose down -v` **deletes** them.
- **Backfill** flows ClickHouse missed while it was down: `daemon.py --from-jsonl engine-ml/data/flows.jsonl --backend clickhouse`. It inserts every line, so rows ClickHouse already has are stored twice.

### Manual blocking — `engine-ml/mitigator.py`

```bash
python3 engine-ml/mitigator.py list                      # current blocks, time left, dropped packets/bytes
python3 engine-ml/mitigator.py block 203.0.113.7         # block one address (refuses protected ones)
python3 engine-ml/mitigator.py unblock 203.0.113.7
python3 engine-ml/mitigator.py setup                     # create the nftables table (the daemon does this itself)
python3 engine-ml/mitigator.py teardown                  # delete the table and ALL blocks
```

| Option | Meaning | Default |
|---|---|---|
| `--backend nftables\|dry-run` | `dry-run` changes nothing (for trying it out) | nftables |
| `--timeout SEC` | block duration for `block` | 900 |
| `--netns NAME` | run `nft` inside this network namespace | – |
| `--allowlist-file FILE` | `block` also refuses addresses in this file | – |

It runs `nft` through `sudo -n` when you are not root.

### Helper — `sensor-c/build/zmq_sink`

`zmq_sink [-n N] [ENDPOINT]` listens like the daemon and prints every record the sensor sends, without checking or storing anything. Use it to see the raw sensor output; `-n N` exits after N records. `sensor -v` shows the same records.

## 5. What each `make` target does

Run `make` from `sentinel-flow/`. **Don't use `sudo make`:** it would build as root. Targets that need root (`verify-closed-loop`) call `sudo` themselves. `make help` prints a short version of this table.

| Target | What it does | Needs |
|---|---|---|
| `make` = `make sensor` = `make build` | Runs cmake and compiles `sensor-c/build/`: `sensor`, `zmq_sink` and the unit-test programs `test_flow` and `test_stats`. Only changed files are recompiled | nDPI at `~/nDPI` |
| `make clean` | Deletes `sensor-c/build/`, so the next build starts from scratch | |
| `make runtime-venv` | Creates `engine-ml/.venv-runtime` with `numpy` + `onnxruntime 1.31.0` (downloads them) | internet |
| `make daemon` | Builds the sensor, then runs the daemon with default options, using the runtime venv when it exists. Add options with `ARGS`, e.g. `make daemon ARGS="--mitigate dry-run"` | |
| `make dashboard` | Dashboard tables in the terminal (SQLite). `ARGS="--show-sql"` etc. adds options | a database |
| `make dashboard-web` | Dashboard web page on http://127.0.0.1:8080 | a database |
| `make stack-up` / `make stack-down` | `docker compose up -d` / `docker compose down` (ClickHouse + Grafana) | Docker |
| `make test-sensor` | Builds, then runs the C unit tests and the PCAP regression tests (`sensor-c/tests/test_sensor_pcaps.py`) | |
| `make test-engine` | Daemon and mitigator unit tests. No root, no network | |
| `make verify-closed-loop` | Builds, then `sudo bash tests/verify_closed_loop.sh`. In two throwaway network namespaces it replays a holdout infection → the model flags it → nftables blocks the C2 address → real packets check the block. Prints PASS/FAIL; the host's own firewall rules are not touched | sudo, runtime venv |
| `make test` / `test-http` / `test-tls` | Builds, then runs the sensor on one capture in `pcaps/` and prints its summary. Nothing is stored unless a daemon is running | |
| `make fetch-data` | Downloads the malware-traffic-analysis.net captures and IOC lists (training + holdout) into `engine-ml/datasets/`. Never malware samples. Hundreds of MB, so use Colab on a metered connection | internet |
| `make dataset` | Builds the sensor, runs every training capture through sensor → `zmq_sink`, labels each flow → `engine-ml/data/training/` | `fetch-data`, nDPI test captures in `~/nDPI/tests` |
| `make train` | Trains, cross-validates (5 folds × 5 seeds), calibrates and exports the model → `engine-ml/models/` | training venv (`TRAIN_PY=` to use another Python) |
| `make holdout` | Builds the sensor, replays the 5 holdout captures through the real daemon → `engine-ml/models/evaluation_holdout.json` | `fetch-data` |
| `make phase3` | `dataset` + `train` + `holdout` | |

Two live tests aren't make targets (both need passwordless `sudo`): `python3 engine-ml/tests/lab_nftables_netns.py` checks the nftables backend in network namespaces, and `python3 sensor-c/tests/live_quiet_interface.py` checks that on an idle interface a flow is still exported after the 30 s idle timeout and Ctrl+C stops the sensor at once.

## 6. Rebuilding after a change

| What changed | What to do |
|---|---|
| C code in `sensor-c/`, or you pulled new commits | `make sensor`, then `make test-sensor` |
| A fresh copy on another machine | `bash scripts/install_deps.sh`, or `make sensor runtime-venv` if nDPI is already built |
| Build errors after moving or updating nDPI | `make clean && make sensor`. For nDPI outside `~/nDPI`: `cd sensor-c/build && cmake -DNDPI_ROOT=/path/to/nDPI .. && make` |
| Another nDPI version | `bash scripts/install_deps.sh --ndpi-ref <commit>`, then `make clean && make sensor && make test-sensor` |
| Python code (daemon, mitigator, dashboard) | Nothing to build. Restart the program |
| The runtime venv is broken or missing | `make runtime-venv` |
| A new model in `engine-ml/models/` | Restart the daemon; it loads the model at start |
| Grafana dashboard JSON | Grafana re-reads the file by itself (about every 10 s); or `docker compose restart grafana` |
| `engine-ml/sql/init_clickhouse.sql` | Applied only to a new ClickHouse volume. The daemon adds the ML columns to an older table itself |

The sensor build records where `libndpi.so` is, so `LD_LIBRARY_PATH` is only needed if you move nDPI after building. `run_live.sh` sets it anyway, from `NDPI_LIB`.

## 7. Retraining the model

Training needs about 700 MB of downloads, so on mobile data run it on **Google Colab**, which does everything and packages the result:

```
!git clone -q https://github.com/AbdeldjallilZennir/sentinel-flow.git /root/cv_work
!bash /root/cv_work/sentinel-flow/scripts/colab_train.sh
from google.colab import files; files.download("/root/sentinel_model.zip")
```

`colab_train.sh` does these steps:
1. scores the current model on the holdout (the "before" result)
2. downloads and builds the dataset
3. checks that every case got malicious flows
4. trains the new model
5. scores the new model on the holdout and prints a before / after table

To run only the holdout again later, use `scripts/colab_holdout.sh`. Unzip the result into `engine-ml/models/`.

**On a local machine:**

```bash
bash scripts/install_deps.sh --with-training --with-data    # once: training venv, tshark, 7z
make fetch-data && make dataset && make train && make holdout
python3 engine-ml/models/compare_holdout.py OLD_evaluation_holdout.json engine-ml/models/evaluation_holdout.json
```

| Script | Options |
|---|---|
| `engine-ml/datasets/fetch_mta.py` | `--only 2024/04/18 ...` (only these cases), `--holdout` (the holdout cases) |
| `engine-ml/models/build_dataset.py` | `--no-clickhouse`, `--ch-url`, `--ch-user`, `--ch-password` |
| `engine-ml/models/train_pipeline.py` | `--folds N` (5), `--seeds N` (5), `--class-balance`, `--no-export` (cross-validate only, keep the current model) |
| `engine-ml/models/evaluate_holdout.py` | `--risk-policy severe\|any\|none` (severe) |
| `engine-ml/models/compare_holdout.py` | `BEFORE.json AFTER.json` |

- **What a retrain overwrites** in `engine-ml/models/`: `c2_detector.onnx`, `anomaly_iforest.onnx`, `model_meta.json`, `evaluation.json` and, after `make holdout`, `evaluation_holdout.json`.
- **Safety check:** the daemon refuses model files whose SHA-256 doesn't match `model_meta.json`.
- **Going back to the committed model:** `git checkout -- engine-ml/models/`.

## 8. Environment variables

| Variable | Used by | Meaning | Default |
|---|---|---|---|
| `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | daemon, dashboard, `build_dataset.py` | ClickHouse address and login | `http://localhost:8123`, `sentinel`, `sentinel` |
| `NDPI_LIB` | `run_live.sh`, `verify_closed_loop.sh` | folder containing `libndpi.so` | `~/nDPI/src/lib` |
| `LD_LIBRARY_PATH` | sensor | only if nDPI was moved after building | |
| `TRAIN_PY` | `make train` | Python with the training packages | `engine-ml/.venv-train/bin/python` |
| `ARGS` | `make daemon`, `make dashboard`, `make dashboard-web` | extra options | |
| `SUDO_ASKPASS` | `install_deps.sh` | sudo without a terminal | |
| `CAPTURE`, `FLAGGED_PEER`, `NORMAL_PEER`, `PY_DAEMON` | `verify_closed_loop.sh` | capture to replay, address that must get blocked, address that must keep working, Python for the daemon | a holdout case, `45.154.98.21`, `203.0.113.10`, the runtime venv |

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Daemon log: `ONNX unavailable … using heuristic_v1` | That Python has no `onnxruntime`. Use `engine-ml/.venv-runtime/bin/python` (or `make daemon`); create the venv with `make runtime-venv` |
| No flows from a live interface | The sensor needs root: `sudo`, or use `run_live.sh`. Check the interface name with `ip -br addr`. Flows appear after 30 s of silence, or every `-A` seconds for long connections |
| Dashboard: `database not found` | The daemon hasn't run yet with that `--db` |
| Dashboard: `cannot listen on 127.0.0.1:8080` | Another program uses the port: add `--port 8081` |
| Daemon: `PermissionError` in `engine-ml/data` | Files left by a root run. `run_live.sh` fixes them at start, or run `sudo chown -R $USER engine-ml/data` |
| Addresses still blocked after stopping | Blocks last `--block-timeout` (15 min). Remove one with `python3 engine-ml/mitigator.py unblock IP`, or all with `teardown` |
| Panel 6 still says "no mitigation data yet" | The daemon hasn't run with `--mitigate` on this database |
| Grafana panels empty on first start | It needs internet once to download its ClickHouse plugin, and the daemon must have written to ClickHouse |
| Sensor: `unsupported link type` | The capture's framing isn't one of Ethernet, Linux cooked, loopback or raw IP |
