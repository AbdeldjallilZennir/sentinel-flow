# SentinelFlow lab setup (two machines)

A small lab: an **admin machine** (your workstation) and a **sensor VM** (Ubuntu Server) that runs the sensor and daemon on a private network between the two. Everything below was done on Ubuntu Server 24.04.4 (VirtualBox, 2 CPUs, 4 GB RAM) and a Kali workstation.

```
 admin machine (e.g. 192.168.56.1)  ── host-only network vboxnet0 ──  sensor VM (e.g. 192.168.56.101)
   browser, ssh                                                       sensor -i enp0s8  ->  daemon.py
                                                                      dashboard on 127.0.0.1:8080
```

## 1. VM network

In VirtualBox, VM **Settings → Network**:

| Adapter | Type | Purpose |
|---|---|---|
| 1 | NAT, with a port-forward rule host `2222` → guest `22` | internet access and `ssh -p 2222 user@localhost` |
| 2 | **Host-only Adapter**, `vboxnet0` | the lab network the sensor watches |

Then, on the VM:

```bash
ip -br addr          # the host-only interface is usually enp0s8, e.g. 192.168.56.101
```

If it has no address, enable DHCP on it with netplan (`/etc/netplan/*.yaml`, `enp0s8: {dhcp4: true}`, then `sudo netplan apply`).

## 2. Install on the VM

```bash
git clone https://github.com/AbdeldjallilZennir/sentinel-flow.git ~/cv_work
cd ~/cv_work
bash sentinel-flow/scripts/install_deps.sh        # ~10 min: packages, nDPI (pinned), sensor, ONNX runtime, tests
```

- Run it as your normal user; it asks for your password once for `apt`.
- Over a non-interactive SSH session, set `SUDO_ASKPASS` to a program that prints the password (see the script header).
- At the end it prints test results. All of them should pass. The daemon test may show 3 skips under the system Python; those 3 ONNX tests pass with `engine-ml/.venv-runtime/bin/python engine-ml/tests/test_daemon.py`.
- Add the line it prints to `~/.bashrc` (`export LD_LIBRARY_PATH=$HOME/nDPI/src/lib…`).

## 3. Run (one interface)

```bash
cd ~/cv_work/sentinel-flow
bash scripts/run_live.sh -i enp0s8 -a 192.168.56.1 --serve
```

| Option | Meaning |
|---|---|
| `-i enp0s8` | capture on that interface only |
| `-a 192.168.56.1` | never block this address (your admin machine); repeat `-a` for more |
| `--serve` | dashboard on the VM's `127.0.0.1:8080` |
| *(default)* | **dry-run**: every block decision is logged, nothing is blocked |
| `--block` | enforce with nftables (`table inet sentinel`, blocks expire after 15 min) |
| `--data-dir DIR` | keep a session's results separate |
| `--no-clickhouse` | SQLite + JSONL only |

**Ctrl+C** stops the sensor (open flows are flushed), then the daemon and dashboard.

## 4. Dashboard from the admin machine

The dashboard listens only on the VM's loopback. Reach it through an SSH tunnel:

```bash
ssh -p 2222 -L 8080:127.0.0.1:8080 joe@localhost     # leave this open
```

Then open **http://127.0.0.1:8080**. The page updates itself every 10 s; the data is also at `/api/panels.json`.

**Before each test,** click **Start new test** (give it a name, e.g. "nmap from host"). The page then shows only what happens from that moment on; older flows are hidden, not deleted (*View* → an earlier test or *All flows*).

## 5. Results

On the VM, after a run:

```bash
cd ~/cv_work/sentinel-flow
engine-ml/.venv-runtime/bin/python engine-ml/query_dashboard.py      # all 6 panels in the terminal
cat engine-ml/data/mitigations.jsonl                                 # each block decision: ip, reason, score, flow
ls engine-ml/data/logs/                                               # sensor / daemon / dashboard logs per run
```

- **Panel 5:** flows with their ML score (`ml_anomaly_score`, 0–1).
- **Panel 6:** the addresses the policy decided to block. In dry-run they're logged, not enforced.
- **Blocking policy (per remote IP):** one flow with score ≥ 0.95, or 2 flows ≥ 0.80 to the same IP within an hour, or a severe nDPI risk; a port scan or host sweep blocks the scanning source. Private (RFC 1918), loopback, link-local, multicast and allowlisted addresses are never blocked; detections on them show as "detected, not blocked" in dashboard panel 6b. Details: [REPORT.md](REPORT.md), Parts 4 and 6.

In `--block` mode:

```bash
sudo engine-ml/.venv-runtime/bin/python engine-ml/mitigator.py list              # active blocks + drop counters
sudo engine-ml/.venv-runtime/bin/python engine-ml/mitigator.py unblock 203.0.113.7
sudo engine-ml/.venv-runtime/bin/python engine-ml/mitigator.py teardown          # remove table inet sentinel
```

## 6. Optional: ClickHouse + Grafana on the VM

```bash
bash sentinel-flow/scripts/install_deps.sh --with-docker      # then log out and back in (docker group)
cd ~/cv_work/sentinel-flow && docker compose up -d             # first start downloads the Grafana plugin
ssh -p 2222 -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 joe@localhost   # from the admin machine
```

Grafana: **http://127.0.0.1:3000** (anonymous read-only; `admin` / `sentinel`). The daemon writes to ClickHouse automatically when it's reachable, unless `--no-clickhouse` is given.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `error while loading shared libraries: libndpi.so.6` | `export LD_LIBRARY_PATH=$HOME/nDPI/src/lib` (run_live.sh sets it for you) |
| `no such interface` | check `ip -br addr`; use the host-only interface, not `lo` |
| daemon log: `No module named 'onnxruntime'` | use `engine-ml/.venv-runtime/bin/python` (or rerun `install_deps.sh`); the system Python has no onnxruntime |
| `sudo: a terminal is required` during install | run it in an interactive shell, or set `SUDO_ASKPASS` |
| dashboard tunnel: `bind ... Address already in use` | another tunnel already holds local port 8080; close it or use `-L 8081:127.0.0.1:8080` |
| no flows after Ctrl+C | check `engine-ml/data/logs/sensor-*.log` for the interface/permission error; the sensor needs root (run_live.sh uses sudo) |
