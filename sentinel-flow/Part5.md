# SentinelFlow — Part 5: Packaging, VM Deployment, First Live Test, Risk-Mask Fix, Retrain

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Tree:** `/home/joe/cv_work/sentinel-flow/`, GitHub `AbdeldjallilZennir/sentinel-flow`
**Date:** 2026-10-24
**Status:**
- The project is packaged (portfolio README, installer, live runner, lab guide) and was installed on a fresh Ubuntu Server 24.04 VM, where all tests pass and results match the development host.
- A first live test (an nmap scan in a two-machine lab) was captured completely. It wasn't blocked, as designed, and it exposed a real sensor bug: corrupted 64-bit risk masks. The bug is fixed and verified.
- The model was retrained on the corrected data and committed: `lgbm+iforest-fv1-2005d025`.
- Expanding the training data with common attacks was started but **not completed** (§6).

> [!info] Claim discipline
> Same rule as Parts 1–4: a statement is made here only if the output that supports it was captured in this session. §8 lists what was not shown.

---

## 0. Project status at a glance

| Phase | Report | State | Key verified results |
|---|---|---|---|
| 1. C sensor | `part1.md`, `part1_2.md`, `Part3.md` §3 | done | libpcap + nDPI 6.1, JA4, Welford stats, ZeroMQ export; 7 bugs fixed in Part 3, 1 more here (§4); ~0.40 Mpps offline |
| 2. Ingestion & analytics | `part2.md` | done | stdlib daemon, SQLite/JSONL/ClickHouse, Grafana, 29 columns per flow |
| 3. ML pipeline | `Part3.md` | done; model updated here (§5) | 9,659 labeled flows; grouped CV ROC-AUC 0.980; holdout 5/5 infections |
| 4. Kernel mitigation | `Part4.md` | done with nftables; XDP not attached | closed loop passed 5/5 checks: 0/50 delivered from the blocked C2, exact counters |
| Packaging & lab | this report | done | installer + runner + guide; fresh-VM install passes all tests |
| Attack-data expansion | this report §6 | not done | stopped; unfinished code kept in a git stash |

---

## 1. Packaging

| File | What it does |
|---|---|
| `README.md` (repo root) | Portfolio document: architecture, metrics table (each number linked to its report section), quick start, screenshots, limits. The original blueprint moved unchanged to `sentinel-flow/docs/BLUEPRINT.md`. |
| `sentinel-flow/scripts/install_deps.sh` | One-command setup for Ubuntu / Debian / Kali: apt packages, nDPI at the verified commit `90eb617a4`, sensor build, `engine-ml/.venv-runtime` (numpy + onnxruntime 1.31.0), both test suites. Opt-in `--with-training`, `--with-data`, `--with-docker`, `--with-xdp`. |
| `sentinel-flow/scripts/run_live.sh` | Live capture on one interface: daemon (dry-run by default; `-a` allowlist; `--block` = nftables) + sensor + optional dashboard (`--serve`). Clean shutdown on Ctrl+C. `--data-dir`, `--no-clickhouse`. |
| `sentinel-flow/docs/LAB_SETUP.md` | Two-machine VirtualBox lab: host-only network, install, run, dashboard over an SSH tunnel, results, optional Grafana, troubleshooting. |

### 1.1 Installer fixes found on a fresh machine

Installing on a fresh Ubuntu Server 24.04.4 VM (2 CPUs, 3.8 GB RAM) over SSH found two installer bugs; both are fixed:

| Problem on the fresh VM | Fix |
|---|---|
| `sudo` can't prompt for a password over a non-interactive SSH session | `SUDO_ASKPASS` support: the script uses `sudo -A` |
| `make: *** No targets specified and no makefile found`: at the pinned commit, nDPI's `autogen.sh` doesn't run `./configure` | the script runs `./configure` when no Makefile was produced |

### 1.2 Result on the VM

```text
libndpi: /home/joe/nDPI/src/lib/libndpi.so.6.1.0
ONNX scorer loads: lgbm+iforest-fv1-6e986f14
=== Results: 13 passed, 0 failed ===        (test_flow)
=== Results: 24 passed, 0 failed ===        (test_stats)
Ran 10 tests … OK                           (sensor PCAP tests)
Ran 15 tests … OK (skipped=3)               (daemon, system Python: no numpy)
Ran 15 tests … OK                           (daemon, runtime venv: ONNX tests included)
Ran 18 tests … OK                           (mitigator)
INSTALL_EXIT=0
```

Smoke test on the VM: `test_tls_full.pcap` + `malware.pcap` → daemon with ONNX, dry-run. 7/7 flows stored, and the 3 dry-run blocks carry the same scores as on the development host (0.841, 0.973, 0.976).

### 1.3 `run_live.sh` check (development host, loopback)

```text
mode: dry-run (decisions are logged to …/data/mitigations.jsonl, nothing is blocked)
  [daemon] scorer: lgbm+iforest-fv1-6e986f14  alert-risk-policy: any
capturing on lo (active timeout 60s) — Ctrl+C to stop
║  Flows exported:    14  ║  Flows dropped:     0  ║
[daemon] stopped: accepted=14 rejected=0 clickhouse_failed=0
=== flows to :18081 stored: 3
{'src_ip': '127.0.0.1', 'dst_ip': '127.0.0.1', 'dst_port': 18081, 'app_protocol': 'HTTP', 'pkt_count': 13, 'ml_anomaly_score': 0.003936, …}
```

**Incident during this check.** An earlier run of the test, before `--no-clickhouse` existed, wrote 384 loopback flows into the host's ClickHouse `sentinel.network_flows`, because ClickHouse was running and the daemon attaches to it automatically. They were deleted by ingest time (`384` rows ingested that day, `3604` before). The table is back to exactly the 3,604 Part 4 rows. `--no-clickhouse` was added to prevent a repeat.

---

## 2. GitHub

- The repository was created and first pushed by the project owner. Later commits were pushed from this session with a personal access token the owner provided. The token was passed through a temporary credential helper that was deleted after each push; it isn't in `.git/config`, the remote URL, or any commit (checked with `git grep` over all revisions).
- The token was pasted into the conversation, so it must be **revoked** on GitHub.
- One push was first rejected because of a README edit made on GitHub (`afc7e1f`). The local commit was rebased on top of it, with no overlap (the edit touched only `README.md`), and pushed.

Commits since Part 4 (newest first):

| Commit | Content |
|---|---|
| `e6444c6` | this report |
| `0ffe7ec` | retrained model on exact risk masks (§5) |
| `d68a0e0` | sensor: exact 64-bit `ndpi_risk_mask` (§4) |
| `afc7e1f` | README edit (project owner, on GitHub) |
| `fa38185` | `run_live.sh` + `LAB_SETUP.md` |
| `9d96df8`, `379994c`, `af55cd8` | installer fixes (§1.1) |

---

## 3. First live test: an nmap scan in a two-machine lab

The test ran on a separate machine pair (VMware network `192.168.230.0/24`) with `run_live.sh` in dry-run mode, capturing on `eth0`. The data folder was transferred as a zip and analysed here. A first copy contained only `sentinel_flows.db` without its `-wal` file, so it was empty: SQLite in WAL mode keeps recent rows in the `-wal` file.

### 3.1 What was captured

```text
Packets processed: 2926   Flows tracked: 1119   Flows exported: 1137 (18 snapshots)   Flows dropped: 0
flows.jsonl: 1137 records; sqlite network_flows: 1137
top src->dst pairs: (192.168.230.1 -> 192.168.230.128): 1124
distinct dst ports on the most-contacted host: 1003
src ports: 36280 used by 1000 flows; pkt_count=2 for 1026 flows (44 B up / 40 B down)
risk strings: 'TCP Connection Issues, Probing Attempt' 973, '(Possible) Slow DoS' 36, …
is_alert: 1033      ml_anomaly_score: max 0.320, >= 0.5: 0, >= 0.8: 0
```

A classic nmap SYN scan: 1,000 probes from one fixed source port, plus service and version probes (short SSH exchanges from consecutive ports) and ICMP.

### 3.2 Why nothing was blocked

| Reason | Detail |
|---|---|
| The model isn't trained on scans | It was trained on C2 and malware sessions. Scan captures were deliberately excluded from the training data (`Part3.md` §4.2). One flow at a time, a scan probe is a 2-packet failed connection. |
| "Probing Attempt" isn't a severe risk | Only 6 severe nDPI risks block without an ML score (`Part4.md` §2) |
| Both addresses are private | The policy never blocks RFC 1918 addresses. The logged decision: `skip_protected … both endpoints protected` |
| Allowlist pointed at the target | `-a 192.168.230.128` was the scanned VM itself; the scanning machine was `.1` |

---

## 4. Bug: 64-bit risk mask corrupted

### 4.1 How it was found

The one logged decision in §3 cited four "severe" risks (suspicious DGA, risky domain, malicious fingerprint, malicious SHA-1 certificate) on an RDP scan probe:

```text
ndpi_risk_mask: 37154697999548400
ndpi_risk_str : 'Desktop/File Sharing, TCP Connection Issues, Probing Attempt'
set bits: [4, 5, …, 29, 50, 55]        expected: [30, 50, 55]
```

### 4.2 Cause and fix

- **Cause:** the embedded cJSON stores numbers as doubles, which hold integers exactly only up to 2⁵³. "Probing Attempt" is bit 55, so 2³⁰ + 2⁵⁰ + 2⁵⁵ = `37154697999548416` was printed as `37154697999548400`, corrupting the low bits.
- **Fix (`d68a0e0`):**
  - new `cJSON_CreateRaw` / `cJSON_AddRawToObject`;
  - `main.c` prints the mask with `PRIu64`.
- **Who was affected:** every flow with a risk at bit 53 or above, notably "Malware Host Contacted" (53), "Probing Attempt" (55) and "Obfuscated Traffic" (56).

### 4.3 Verification

```text
pcaps=630 flows=9952 mask_diffs=63 other_field_diffs=0 new masks>=2^53: 63;
new masks whose bit count != number of nDPI risk names: 0
```

| Check | Result |
|---|---|
| Old vs new sensor on the full nDPI corpus | exactly the 63 flows with masks ≥ 2⁵³ change; no other field changes anywhere |
| Mask vs nDPI's own risk names | every new mask's bit count equals the number of risk names nDPI reports |
| Regression test `test_risk_mask_is_exact_above_2_53` (`tcp_scan.pcapng`) | passes on the new binary; fails on the old one (`3.71546969258066e+16 is not an instance of <class 'int'>`) |
| ASan / LSan / UBSan | 5 captures, 2,010 flows, 0 errors |
| Sensor suite | 11/11 tests |

### 4.4 Impact on earlier results

- **Training data:** 79 of the 9,659 training flows (0.8 %) had corrupted masks, and 9 of them showed fake severe bits. Part 3's metrics were computed on that data; §5 shows the retrain on corrected data.
- **Blocking policy:** it reads the same mask, so before the fix a scan could produce a fake "severe" risk and a block for the wrong reason.

---

## 5. Retrain on corrected data (`0ffe7ec`)

`make dataset train holdout` was run on the development host on 2026-10-24 (17:25–17:27). The dataset was rebuilt with the fixed sensor from the same 601 PCAPs. Composition is unchanged (9,659 flows, 1,825 malicious in 28 captures). The difference: the 79 masks ≥ 2⁵³ are now exact integers.

| | Previous model `6e986f14` | New model `2005d025` |
|---|---|---|
| CV recall @0.80 (5 seeds) | 0.452 ± 0.042 | 0.449 ± 0.020 |
| CV precision | 0.907 ± 0.031 | 0.922 ± 0.015 |
| CV false-alarm rate | 1.1 % ± 0.4 % | 0.9 % ± 0.2 % |
| ROC-AUC / PR-AUC | 0.980 / 0.905 | 0.980 / 0.901 |
| Calibration threshold (raw) | 0.330 | 0.353 |
| ONNX parity | 0 / 9,597 differ | 0 / 9,597 differ |
| Holdout: infections / endpoints / false alerts | 5/5 / 15/23 / 3 of 498 | 5/5 / 15/23 / 3 of 498 |

All differences are within the seed spread. The new model has the same quality with less variance across seeds, and is built on correct inputs. The daemon loads it after the SHA-256 check (`OnnxScorer loads: lgbm+iforest-fv1-2005d025`); daemon 15/15 and mitigator 18/18 tests pass.

**Why it wasn't saved straight away.** The retrain wasn't run by this session. When new model files appeared, they were left uncommitted because their origin wasn't yet confirmed and committing them replaces the production model. After the comparison above they were committed. Earlier reports (Part 3, Part 4, README) quote the previous model; those numbers remain the record of what was measured then.

---

## 6. Attempted, not completed

| Item | State |
|---|---|
| **Training on common attacks:** nDPI corpus scans / web attacks / DoS / exploits, plus the lab nmap session | The builder changes were written. Creating the lab-session files was stopped by Anthropic's safety system partway through, and earlier related tools (a session "flywheel" and a dataset collector) were stopped the same way. Not pursued further. The unfinished builder change is kept in `git stash` ("unfinished: attack families + lab sessions in build_dataset.py"). |
| **XDP blocking** | `Part4.md` §6: sources compile, attaching failed in libbpf |
| **Labeling for outside datasets** (CIC-IDS2017 etc.) | Not written. A Colab script that runs the **existing** pipeline in the cloud was provided in conversation; it is untested on Colab. |
| **Scan detection** | Proposed, not built: per-source fan-out (distinct ports/hosts in a time window). The §3 scan (1,003 ports from one source) would stand out to such a rule but not to the per-flow model. |

---

## 7. Open items

1. **Revoke the GitHub token** that was pasted into the conversation.
2. **`git pull` on the VMs** so they use the new model (`0ffe7ec`, pushed to GitHub).
3. **For lab runs:** allowlist the machine you administer from, not the sensor VM. Private-to-private traffic is never blocked, so lab results show up as logged decisions.
4. **Offline idle expiry** still runs only every 1,000 packets (`Part4.md` §1.3); unchanged to keep earlier results reproducible.
5. `engine-ml/models/threshold_table.json` and the README metrics still describe the previous model. Re-run `threshold_table.py` if you want them for `2005d025`.
6. **Untracked files in the repo root:** `data-20261024T154543Z-1-001.zip` (the nmap session) and an empty `sentinel_flows.db`. These are the project owner's files and were left as they are.

---

## 8. What may and may not be said

**May be said:**
- The installer sets the project up on a fresh Ubuntu Server 24.04.4 VM, where all test suites pass, and the VM scores test captures identically to the development host.
- In a live lab, the sensor captured an nmap scan completely (1,137 flows, 0 dropped) and nDPI flagged it as probing.
- The 64-bit risk mask was corrupted for risks at bit 53 and above. It's fixed, and verified on 9,952 corpus flows with a regression test.
- The model retrained on corrected data matches the previous one within the seed spread, with lower variance, and was committed.

**Must not be said:**
- **That SentinelFlow detects port scans.** The live scan scored at most 0.32, and scans aren't in the training data.
- **That the model generalises to attack types beyond the C2/malware families it was trained on.**
- **That `run_live.sh --block` was tested live.** Only dry-run was used in the live lab; nftables enforcement was verified in `Part4.md` §7.
- **That the Colab script works.** It hasn't been run on Colab.
