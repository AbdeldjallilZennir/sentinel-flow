# SentinelFlow — Part 4: Active Mitigation (nftables), Active Flow Timeout, Blocking Policy

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Tree:** `/home/joe/cv_work/sentinel-flow/`
**Date:** 2026-10-23
**Host:** Kali Linux 6.16.8, nftables 1.1.3, iproute2 6.16.0, clang 19.1.7, Python 3.14.7
**Status:**
- Done and tested: active flow timeout in the sensor, the blocking policy, the mitigator (dry-run and nftables backends, audit trail), daemon integration, and the 6th dashboard panel.
- nftables enforcement was verified on real packets in throwaway network namespaces, with the block placed directly through `Mitigator`.
- **The fully automatic closed loop** (capture → daemon → automatic nft block → kernel drops) passed all 5 checks in `tests/verify_closed_loop.sh` (§7.2, run 2; run 1 failed on an environment issue that was fixed, §7.1).
- **XDP enforcement is not done** (§6).

> [!info] Claim discipline
> Same rule as `part1.md` §12, `part2.md` §10 and `Part3.md` §11: a statement is made only if the output that supports it was captured in this session and is quoted here. §9 lists what was not shown.

---

## 0. Summary

| Item | Result |
|---|---|
| Sensor active timeout `-A <sec>` (default 60, `0` = off) | Long-lived flows get a cumulative snapshot record every `<sec>` s while still active. `-A 0` output is byte-identical to the Part 3 sensor on the 9-PCAP regression set and has the same flow count on all 577 Ethernet corpus captures. 4 new sensor tests; the sensor suite passes 10/10. |
| Offline idle-expiry finding | Documented, not changed (§1.3): offline idle expiry runs only every 1,000 packets, so small captures never idle-expire. |
| Blocking policy (`BlockPolicy`) | Blocks only when `ml_anomaly_score ≥ 0.80` from a trained model, or when a severe nDPI risk is present. Targets the remote peer; never RFC 1918 (default), loopback, link-local, multicast, unspecified, reserved, or allowlisted addresses. `--allowlist-file` added. |
| `mitigator.py` | `dry-run` and `nftables` backends; audit trail in JSONL, SQLite (`mitigation_events`, `blocked_ips`) and ClickHouse (`sentinel.mitigations`); CLI. **18/18 unit tests.** |
| nftables on real packets (namespace lab) | Blocked peer: **0/50 delivered**, nft counter **50 packets / 6,400 bytes** (exact). Benign peer: **50/50 delivered**. 3 s expiry and manual unblock both work. |
| Daemon `--mitigate dry-run` on the 11 Part 3 captures | 24 blocks + 7 protected skips = **31 events, identical in JSONL, SQLite and ClickHouse**. Panel 6 shows 24 rows in `query_dashboard.py` (SQLite and ClickHouse identical) and Grafana (HTTP 200, 24 rows). |
| Threshold × risk-policy table | Holdout at 0.80 + `severe`: **16/23 malicious endpoints, 2/61 benign endpoints blocked, 5/5 infections** (§5). |
| Automatic closed loop with nftables | Run 1 failed: the daemon couldn't import `onnxruntime` under `sudo` (§7.1). After the fix, **run 2 passed all 5 checks** (§7.2): capture replay → ONNX score 0.991 → automatic nft block of `45.154.98.21`; then 0/50 delivered from it (counter exactly 50 pkts / 6,400 B) while the normal peer got 50/50. |
| XDP | Both provided sources compile; attaching failed in libbpf. **Not done** (§6). |

---

## 1. Sensor: active flow timeout (`-A`)

### 1.1 Behavior

- `-A <sec>` (default **60**, `0` disables, valid 0–86400). A flow that is **still active** (seen within the 30 s idle timeout) and hasn't produced a record for `<sec>` seconds gets a **snapshot**: the same 23-field JSON, cumulative since `first_seen_us`. The flow stays in the table, and its final record follows when it ends (idle expiry or shutdown).
- Snapshots are checked every 1 s of packet time, **before** the current packet joins its flow. A flow that was idle before this packet is never snapshotted.
- During live capture (`-i`), the same check also runs on the wall clock when no packets arrive, together with idle expiry. Before this change, live capture never expired flows while traffic was quiet.
- A flow can therefore appear several times downstream (same 5-tuple and `first_seen_us`, growing `pkt_count` / `last_seen_us`). The summary prints `Snapshot records: N`.
- The Phase 3 tools pin **`-A 0`**: `build_dataset.py` and `evaluate_holdout.py` pass it explicitly. That keeps the training set and holdout evaluation on the flow definition the models were trained on.

### 1.2 Evidence

```text
sensor -h:
  -A <sec>        Active timeout: also export a snapshot of flows
                  still active after <sec> s, then every <sec> s
                  (default 60, 0 = off; idle timeout is 30 s)

9-PCAP set, -A 0: byte-identical to the Part 3 sensor (38 flows)
9-PCAP set, -A 60: 49 records
corpus, Part 3 sensor: {"records": 9738, "snapshots": 0}
corpus, new -A 0:      {"records": 9738, "snapshots": 0}
corpus, new -A 60:     {"records": 10937, "snapshots": 1199}
files whose flow count differs (-A 0 vs Part 3 sensor): 0
ASan/LSan/UBSan with -A 30 on 10 PCAPs: 0 errors
```

New tests in `sensor-c/tests/test_sensor_pcaps.py`:

| Test | What it proves |
|---|---|
| `test_active_timeout_snapshots` | A packet every 10 s for 150 s: default `-A 60` gives `pkt_count` `[6, 12, 16]` with one shared `first_seen_us` and `last_seen_us` at t = 50 / 110 / 150 s. `-A 0` gives `[16]`. `-A 30` gives `[3, 6, 9, 12, 15, 16]`. |
| `test_no_snapshot_of_idle_flow` | Two packets 5,000 s apart: one record, no snapshot. |
| `test_active_timeout_rejects_bad_values` | `-A abc`, `-A -5`, `-A 100000` → exit 1. |
| (unchanged) `test_long_flow_duration_keeps_microseconds` | Passes in its original Part 3 form. |

```text
Ran 10 tests in 12.132s
OK
test_flow: 13 passed, 0 failed     test_stats: 24 passed, 0 failed
```

### 1.3 Finding (documented, not changed): offline idle expiry only every 1,000 packets

When reading a file (`-r`), idle expiry runs only at every 1,000th IPv4 packet, which is unchanged since Phase 1. **A capture with fewer than 1,000 packets never idle-expires**, so a 30 s gap doesn't split a flow. Examples:

- `test_dns.pcap`: its DNS flow has a 40.8 s gap and is reported as one 3-packet flow.
- `tplink_shp.pcap`: 8 flows would be 251 with per-second expiry checks.

An experimental build that also expired idle flows on a 1 s packet-time clock changed **93 of 577** corpus files, turning 9,738 flows into 11,258. Because that would change the Part 1–3 evidence, the training set and the models, the behavior was **kept as is**. Live capture is not affected: it now expires on the wall clock. Fixing offline mode means rebuilding the dataset and retraining (`make phase3`).

---

## 2. Blocking policy (`engine-ml/mitigator.py`, `BlockPolicy`)

- **Trigger:** either of
  - `ml_anomaly_score ≥ threshold` (default 0.80), but only when `ml_model` is a trained model. Records scored by `heuristic_v1` never block.
  - `ndpi_risk_mask & features.SEVERE_MASK` (suspicious DGA, risky domain, malicious fingerprint, malicious SHA-1 certificate, possible exploit, malware host contacted), unless `--no-severe-risk-blocks`.

  No other nDPI risk blocks on its own: "any risk" alerted on ~18 % of real Windows background flows in Part 3 (§8.4).
- **Target:** the responder (`dst_ip`) unless it's protected, then `src_ip`. If both are protected, nothing is blocked and a `skip_protected` event is logged.
- **Never blocked:**

| Rule | Configurable? |
|---|---|
| loopback, link-local, multicast, unspecified, reserved, 255.255.255.255 | always; cannot be disabled |
| RFC 1918 + 127.0.0.0/8 | default `--protected-cidr`; `--allow-private-blocks` drops RFC 1918 (lab only) |
| `--allowlist` IPs/CIDRs and **`--allowlist-file`** (one IP/CIDR per line, `#` comments; an invalid line is an error naming file and line) | yes |
| non-IPv4 | always (the sensor and the set are IPv4) |

### 2.1 Cloud/CDN allowlist recommendation

The built-in list is deliberately minimal, so the holdout numbers in §5 aren't flattered by a hand-made allowlist. In the Part 3 data, the policy would also block a Cloudflare address serving `api.ipify.org` (`172.67.74.152`) and two Microsoft addresses (`13.107.213.57` / azureedge.net, `20.190.135.18` / login.live.com). Blocking shared cloud or CDN addresses cuts off unrelated services behind them. Before using `--mitigate nftables` on a real host, **provide an `--allowlist-file` with the cloud/CDN/SaaS ranges the site depends on** (from the providers' published range lists), and keep the default 15-minute block timeout.

### 2.2 Unit tests (`engine-ml/tests/test_mitigator.py`): 18/18

```text
Policy: blocks remote C2 not victim; inbound flow blocks the other side; threshold inclusive (0.80 blocks,
0.7999 doesn't); heuristic scores never block; only the 6 severe risks block without ML; both-private skipped;
--allow-private-blocks; special addresses always protected; allowlist + custom protected CIDRs;
--allowlist-file (incl. error on a bad line); IPv6 never blocked
Mitigator: one block per IP; benign/heuristic records do nothing; protected skip audited; backend error
logged not raised; counters + expiry events and re-block after expiry; SQLite state table; CLI refuses
a protected IP
Ran 18 tests in 0.051s
OK
```

---

## 3. `mitigator.py` backends, audit trail, daemon integration

### 3.1 Backends

| Backend | Kernel state |
|---|---|
| `dry-run` | none; in-memory record of what would be blocked |
| `nftables` | its own table only, `inet sentinel` (other tables are never modified): set `blocked_ipv4 { type ipv4_addr; flags timeout; timeout 15m; counter; }`; `prerouting` (priority raw) drops `ip saddr @blocked_ipv4`; `output` and `forward` drop `ip daddr @blocked_ipv4`. Each element carries its own packet/byte counter. `--mitigate-netns` applies it inside a network namespace. |

CLI: `python3 engine-ml/mitigator.py [--backend nftables|dry-run] [--netns NS] [--allowlist-file F] setup|list|block IP|unblock IP|teardown`. `block` refuses protected addresses.

### 3.2 Audit trail

Every event (`block`, `unblock`, `expire`, `counters`, `skip_protected`, `error`) is written to:
- `engine-ml/data/mitigations.jsonl`
- SQLite `mitigation_events`, plus `blocked_ips` (current state per IP)
- ClickHouse `sentinel.mitigations` (DDL in `engine-ml/sql/init_clickhouse.sql`; created on demand)

Kernel counters are read every 10 s, and on exit.

### 3.3 Daemon

`daemon.py --mitigate none|dry-run|nftables` (default `none`), plus `--mitigate-netns`, `--block-timeout` (900 s), `--protected-cidr`, `--allow-private-blocks`, `--allowlist`, `--allowlist-file`, `--no-severe-risk-blocks`, `--mitigations-jsonl`. Each scored batch is passed to the mitigator after it's written to storage. On exit, active blocks are **left in place** until their timeout.

---

## 4. Verification on real packets and data

### 4.1 nftables backend in a namespace lab (`engine-ml/tests/lab_nftables_netns.py`)

Namespaces `sf_victim` (`192.168.50.10`) and `sf_remote` (`203.0.113.66` blocked peer, `203.0.113.10` benign peer), joined by a veth pair. The block was placed by `Mitigator.process()` from a synthetic scored record (`ml_anomaly_score 0.97`). Captured output:

```text
[baseline] received at victim: {'203.0.113.66': 50, '203.0.113.10': 50}
[block] events: [('block', '203.0.113.66', 'ml_score')]
[block] nft set: {'203.0.113.66': {'expires_s': 899, 'packets': 0, 'bytes': 0}}
[inbound] sent 50 from each; received at victim: {'203.0.113.10': 50}; nft counter for 203.0.113.66: packets=50 bytes=6400 (expected 50 and 6400)
[outbound] victim->203.0.113.66: send failed=True ['PermissionError: [Errno 1] Operation not permitted']; victim->203.0.113.10: send failed=False; nft counter now packets=51 bytes=6528
[expiry] 3 s block on 203.0.113.10: received during={} after={'203.0.113.10': 50}; set now: ['203.0.113.66']
[unblock] unblock 203.0.113.66 final dropped_pkts=51 bytes=6528; received after unblock: {'203.0.113.66': 50}
[events] block:203.0.113.66, counters:203.0.113.66, expire:203.0.113.10, unblock:203.0.113.66
[cleanup] lab namespaces remaining: []
```

6,400 bytes = 50 × (20 IP + 8 UDP + 100 payload). The outbound send fails on its first packet (`EPERM` from the local nft drop), so one packet was counted. The host's own ruleset was unchanged afterwards (`table ip nat / ip filter / ip6 nat / ip6 filter` only).

### 4.2 Dry run on the 11 Part 3 captures, with Panel 6

Same captures as the Part 3 final run, `sensor -r … -A 0` → `daemon.py --backend both --scorer onnx --mitigate dry-run`:

```text
[daemon] mitigation: backend=dry-run timeout=900s protected=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8 allowlist=none sinks=JsonlEventSink,SqliteEventSink,ClickHouseEventSink
[daemon] mitigation: {'blocks': 24, 'skips_protected': 7, 'errors': 0}; active blocks left in place: 24 (they expire after --block-timeout)
flows: SQLite 3604  ClickHouse 3604
mitigation events: jsonl 31  SQLite 31  ClickHouse 31
SQLite vs ClickHouse: all 6 panels identical
```

Panel 6, "Active Kernel Mitigations & XDP Drop Counters", is in `query_dashboard.py` (SQLite `blocked_ips` / ClickHouse `sentinel.mitigations`, same columns and order) and in Grafana (same SQL as `query_dashboard.py`):

```text
[table] Active Kernel Mitigations & XDP Drop Counters: status=200 rows=24 fields=['ip', 'backend', 'status', 'reason', 'score', 'flow', 'dropped_pkts', 'dropped_bytes', 'first_blocked']
```

Of the 24 dry-run blocks:

| Group | Count |
|---|---|
| Labeled malicious holdout endpoints | 16 (15 via ML score, 1 via severe risk: `49.13.65.235`, suspicious DGA) |
| Endpoints from nDPI's `malware.pcap` | 3 |
| Shared services the malware used (labeled ambiguous) | 3: `psiewdr.org`, `checkip.dyndns.org`, `api.ipify.org` on Cloudflare |
| Microsoft false positives | 2: `13.107.213.57`, `20.190.135.18` |

No private address was selected.

---

## 5. Threshold × risk-policy comparison (read-only, `engine-ml/models/threshold_table.py`)

`BlockPolicy` was replayed over predictions already saved in Part 3; nothing was retrained or rescored. An endpoint is a (capture, remote IP) pair, as the policy would pick it.
- **Caught:** a malicious endpoint (remote IP of a label-1 flow) that gets blocked.
- **False block:** a blocked endpoint seen only in label-0 flows.
- Ambiguous flows are excluded.

**Holdout:** 5 never-trained captures; 3,592 stored flows from the Part 3/4 live run, assigned to captures by capture time and labeled with `mta_holdout_labels.json`.

| Threshold | Risk policy | Malicious endpoints caught | Benign endpoints blocked | Infections with ≥ 1 block |
|---|---|---|---|---|
| 0.70 | none | 16 / 23 (69.6 %) | 2 / 61 (3.3 %) | 5 / 5 |
| 0.70 | severe | 16 / 23 (69.6 %) | 2 / 61 (3.3 %) | 5 / 5 |
| 0.80 | none | 15 / 23 (65.2 %) | 2 / 61 (3.3 %) | 5 / 5 |
| **0.80** | **severe** | **16 / 23 (69.6 %)** | **2 / 61 (3.3 %)** | **5 / 5** |
| 0.90 | none | 14 / 23 (60.9 %) | 2 / 61 (3.3 %) | 5 / 5 |
| 0.90 | severe | 15 / 23 (65.2 %) | 2 / 61 (3.3 %) | 5 / 5 |

**Cross-validation:** seed 42 out-of-fold predictions, 9,597 flows, 28 training captures (23 of them have a non-protected malicious endpoint).

| Threshold | Risk policy | Malicious endpoints caught | Benign endpoints blocked | Captures with ≥ 1 block |
|---|---|---|---|---|
| 0.70 | none | 65 / 91 (71.4 %) | 113 / 2,459 (4.60 %) | 14 / 23 |
| 0.70 | severe | 67 / 91 (73.6 %) | 123 / 2,459 (5.00 %) | 16 / 23 |
| 0.80 | none | 63 / 91 (69.2 %) | 51 / 2,459 (2.07 %) | 14 / 23 |
| **0.80** | **severe** | **65 / 91 (71.4 %)** | **61 / 2,459 (2.48 %)** | **16 / 23** |
| 0.90 | none | 60 / 91 (65.9 %) | 21 / 2,459 (0.85 %) | 13 / 23 |
| 0.90 | severe | 62 / 91 (68.1 %) | 35 / 2,459 (1.42 %) | 15 / 23 |

Readings:
- **On the holdout, the threshold barely matters for false blocks:** both are the Microsoft addresses, which scored ≥ 0.99. The threshold mainly trades away caught endpoints.
- **In CV, the threshold is the main lever on false blocks:** 113 → 51 → 21 from 0.70 to 0.90 (`none`).
- **`severe` adds 2 caught endpoints and 2 captures** at a cost of 10–14 extra false blocks in CV.
- **The default stays at 0.80 + `severe`.** 0.90 + `none` is the more conservative option when false blocks matter more than coverage.
- **These are small samples:** 23 holdout endpoints, and one CV seed. Part 3 §7.1 showed CV metrics varying noticeably across seeds.

---

## 6. XDP: not done

- **Sources:** `mitigation-ebpf/xdp_blocker.bpf.c` and `mitigation-ebpf/xdp_ctl.c` were provided by the project owner and reviewed before use. The program drops IPv4 packets whose source or destination is in the `blocked_ips` map and counts drops per entry. `xdp_ctl` manages a map pinned at `/sys/fs/bpf/sentinel_blocked_ips` (`init`, `add`, `del`, `list`, `teardown`).
- **Build:** `clang -O2 -g -target bpf -c xdp_blocker.bpf.c -o xdp_blocker.bpf.o` and `gcc -O2 -Wall -Wextra -o xdp_ctl xdp_ctl.c` both succeeded with no warnings. The object has the `xdp`, `.maps`, `license`, `.BTF` and `.relxdp` sections.
- **Attach attempt:** in a throwaway namespace, `ip link set dev veth-v xdpgeneric obj xdp_blocker.bpf.o sec xdp` failed:
  ```text
  libbpf: map 'blocked_ips': attr 'type': expected PTR, got int.
  ERROR: opening BPF object file failed
  ```
  Nothing was attached, and the namespace was deleted.
- **What's needed:**
  - libbpf (used by iproute2 1.6.2 here) doesn't accept the map definition in `xdp_blocker.bpf.c`; the program's map definition has to change.
  - Even once it loads, the map the program uses has to be the **same** map `xdp_ctl` pins at `/sys/fs/bpf/sentinel_blocked_ips`. Otherwise entries added with `xdp_ctl` won't affect packets.

  Both are left to the project owner. No `xdp` backend was added to `mitigator.py`, and no XDP result is claimed.

---

## 7. Automatic closed loop with nftables

`tests/verify_closed_loop.sh` (run as root, or it re-runs itself with `sudo`):

1. Creates namespaces `sf_host` (`192.168.50.10`) and `sf_peer` (`flagged_peer` = `45.154.98.21`, `normal_peer` = `203.0.113.10`), joined by a veth pair, and runs a baseline wave.
2. **Wave 1:** starts `daemon.py --scorer onnx --mitigate nftables --mitigate-netns sf_host`, then replays `2023-11-20-DarkGate-infection-traffic.pcap` with `sensor -r … -A 0`. It waits until `flagged_peer` appears in `sf_host`'s nft set. In Part 3 this capture's flows to `45.154.98.21` scored up to 0.998.
3. **Wave 2:** sends 50 UDP packets (100-byte payload) from each peer to a listener in `sf_host`, and reads the nft counter before and after.
4. Waits 11 s for the daemon's counter refresh, stops it, and prints the audit rows for `flagged_peer`.
5. Prints PASS/FAIL for: block present after wave 1; 0/50 delivered from `flagged_peer`; 50/50 delivered from `normal_peer`; counter delta = 50 packets and 6,400 bytes.
6. Deletes both namespaces on exit, even on failure. Outputs stay in `/tmp/sf_closed_loop.*`.

Static check: `bash -n tests/verify_closed_loop.sh` → syntax ok (`shellcheck` not installed).

### 7.1 Run 1 (2026-10-23, run by the project owner): failed, the daemon never started

```text
[verify] namespaces sf_host (192.168.50.10) <-> sf_peer (flagged_peer=45.154.98.21, normal_peer=203.0.113.10)
[verify] baseline (no blocks): received at host: {"45.154.98.21": 50, "203.0.113.10": 50}
[verify] wave 1: sensor -r 2023-11-20-DarkGate-infection-traffic.pcap -A 0
   Packets processed: 9961
   Flows exported: 740
   Flows dropped: 0
[verify] nft set in sf_host after wave 1:
Error: No such file or directory
list set inet sentinel blocked_ipv4
              ^^^^^^^^
[verify] counter for flagged_peer before wave 2: absent
[verify] wave 2: sent 50 from each peer; received at host: {"45.154.98.21": 50, "203.0.113.10": 50}
[verify] counter for flagged_peer after wave 2: absent
tests/verify_closed_loop.sh: line 159: kill: (346768) - No such process
[verify] cleanup: namespaces removed: 0 left; outputs kept in /tmp/sf_closed_loop.7rwCV1
```

`/tmp/sf_closed_loop.7rwCV1/daemon.log`:

```text
  File "/home/joe/cv_work/sentinel-flow/engine-ml/daemon.py", line 202, in __init__
    import onnxruntime as ort
ModuleNotFoundError: No module named 'onnxruntime'
```

**What happened.** Under `sudo`, `/usr/bin/python3` can't import `onnxruntime`. With `--scorer onnx` (fail instead of falling back) the daemon exited at startup, so the nft table was never created and nothing was blocked. Both peers got 50/50 through in wave 2, which is consistent with no block existing. Two script bugs showed up too: it didn't check the daemon was alive, and it aborted at `kill` before printing the verdict.

**Root cause, and a correction to Part 3.** `onnxruntime` and the numpy used in Parts 3–4 are **not installed system-wide**. They come from the site-packages of a pipx virtualenv (`~/.local/share/pipx/venvs/headroom-ai`), which the user's `sys.path` includes through the user site directory:

```text
/usr/bin/python3 (user)  import onnxruntime: ok …/pipx/venvs/headroom-ai/lib/python3.14/site-packages/onnxruntime/__init__.py
/usr/bin/python3 (sudo)  import onnxruntime: ModuleNotFoundError: No module named 'onnxruntime'
```

Part 3 §8 / requirements describe onnxruntime 1.31.0 as "system-wide"; that is wrong. The version (1.31.0) and every Part 3 result are unaffected. Only the description of where the package lives was wrong. The training virtualenv (`engine-ml/.venv-train`, `--system-site-packages`) depends on the same user path.

**Fix.**
- New self-contained interpreter `engine-ml/.venv-runtime` (`make runtime-venv`): numpy 2.5.4 and onnxruntime 1.31.0, no system or user site-packages. Under `sudo` it loads the models with the SHA-256 check (`under sudo, OnnxScorer loads: lgbm+iforest-fv1-6e986f14`).
- It scores identically to the interpreter used in Parts 3–4: `3604 flows scored by both interpreters: max |diff| = 0.0, decisions at 0.80 differing: 0`.
- `verify_closed_loop.sh` now runs the daemon with `PY_DAEMON` (default `.venv-runtime`), stops before creating namespaces if that interpreter can't load the models, stops with the daemon log if the daemon dies after starting, and no longer aborts on `kill`.

### 7.2 Run 2 (2026-10-23T18:08:24Z, run by the project owner): all 5 checks PASS

`sudo bash tests/verify_closed_loop.sh`, after the fix in §7.1:

```text
[verify] namespaces sf_host (192.168.50.10) <-> sf_peer (flagged_peer=45.154.98.21, normal_peer=203.0.113.10)
[verify] baseline (no blocks): received at host: {"45.154.98.21": 50, "203.0.113.10": 50}
  [daemon] scorer: lgbm+iforest-fv1-6e986f14  alert-risk-policy: any
  [daemon] mitigation: backend=nftables netns=sf_host timeout=900s protected=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8 allowlist=none sinks=JsonlEventSink,SqliteEventSink
[verify] wave 1: sensor -r 2023-11-20-DarkGate-infection-traffic.pcap -A 0
   Packets processed: 9961
   Flows exported: 740
   Flows dropped: 0
  [daemon] flushed 740 rows -> sqlite,jsonl (scored in 40.3 ms; alerts=697; total accepted=740 rejected=0)
  [daemon] BLOCK 45.154.98.21 (ml_score: ml_anomaly_score=0.991 (lgbm+iforest-fv1-6e986f14)) flow 10.11.7.120:54179 -> 45.154.98.21:80 HTTP
  [daemon] BLOCK 188.246.224.221 (ml_score: ml_anomaly_score=0.895 (lgbm+iforest-fv1-6e986f14)) flow 10.11.7.120:54197 -> 188.246.224.221:2351 HTTP
[verify] nft set in sf_host after wave 1:
  table inet sentinel {
        set blocked_ipv4 {
                type ipv4_addr
                counter
                timeout 15m
                elements = { 45.154.98.21 counter packets 0 bytes 0 expires 14m59s756ms comment "ml_score: ml_anomaly_score=0.991 (lgbm+iforest-fv1-6e986f14)",
                             188.246.224.221 counter packets 0 bytes 0 expires 14m59s760ms comment "ml_score: ml_anomaly_score=0.895 (lgbm+iforest-fv1-6e986f14)" }
        }
  }
[verify] counter for flagged_peer before wave 2: 0 0
[verify] wave 2: sent 50 from each peer; received at host: {"203.0.113.10": 50}
[verify] counter for flagged_peer after wave 2: 50 6400
[verify] daemon audit for flagged_peer:
  {"ts_us":1792778889754621,"action":"block","ip":"45.154.98.21","backend":"nftables","reason":"ml_score","detail":"ml_anomaly_score=0.991 (lgbm+iforest-fv1-6e986f14)","score":0.99122,"flow":"10.11.7.120:54179 -> 45.154.98.21:80 HTTP","ml_model":"lgbm+iforest-fv1-6e986f14","timeout_s":900,"dropped_pkts":0,"dropped_bytes":0}
  {"ts_us":1792778898976826,"action":"counters","ip":"45.154.98.21","backend":"nftables","reason":"","detail":"","score":-1.0,"flow":"","ml_model":"","timeout_s":890,"dropped_pkts":50,"dropped_bytes":6400}
  blocked_ips row: ('45.154.98.21', 'nftables', 'active', 'ml_score', 0.991, 50, 6400, '10.11.7.120:54179 -> 45.154.98.21:80 HTTP')

=== CLOSED-LOOP RESULT (2026-10-23T18:08:24Z) ===
wave 1  flagged_peer in nft set after replay           : PASS
wave 2  flagged_peer packets delivered   0 / 50 (want 0)  : PASS
wave 2  normal_peer packets delivered    50 / 50 (want 50) : PASS
wave 2  nft counter delta packets        50 (want 50)      : PASS
wave 2  nft counter delta bytes          6400 (want 6400)  : PASS
outputs: /tmp/sf_closed_loop.FrXiss
[verify] cleanup: namespaces removed: 0 left; outputs kept in /tmp/sf_closed_loop.FrXiss
```

Readings:
- **Wave 1 is the full automatic path, with no manual step:**
  - The sensor replayed the holdout DarkGate capture: 9,961 packets, 740 flows, 0 dropped.
  - The daemon scored all 740 flows with the ONNX model in one batch (40.3 ms).
  - The mitigator blocked the capture's two C2 endpoints: `45.154.98.21` (score 0.991, payload host) and `188.246.224.221` (0.895, DarkGate C2). They are the same two endpoints Part 3 §9.1 listed for this capture.
  - Both were inserted into the nft set in `sf_host` with a 15-minute timeout and the reason as the element comment.
  - The victim address `10.11.7.120` was not blocked (protected, RFC 1918).
- **Wave 2:**
  - 0/50 packets from `flagged_peer` were delivered, and its nft element counter went from 0/0 to exactly **50 packets / 6,400 bytes** (50 × (20 + 8 + 100)).
  - 50/50 packets from `normal_peer` were delivered on the same interface.
- **Audit trail:** the daemon's own 10 s counter refresh recorded the kernel counters in `mitigations.jsonl` (`counters`, 50 / 6,400) and in SQLite `blocked_ips` (`active`, 50, 6,400).
- `alerts=697` is the Phase 2 `is_alert` rule (`--alert-risk-policy any`), which only labels flows. Blocking used the Phase 4 policy and produced 2 blocks.
- ClickHouse was not attached in this run (`--backend sqlite`); the ClickHouse audit sink was shown in §4.2.

---

## 8. Files changed in Phase 4

| Area | Files |
|---|---|
| Sensor | `sensor-c/src/main.c` (`-A`, snapshots, live wall-clock housekeeping), `sensor-c/src/flow_table.{c,h}` (`last_export_us`, `flow_table_foreach`), `sensor-c/tests/test_sensor_pcaps.py` (+4 tests) |
| Engine | `engine-ml/mitigator.py` (new), `engine-ml/daemon.py` (`--mitigate*`, `--allowlist-file`), `engine-ml/query_dashboard.py` (panel 6), `engine-ml/sql/init_clickhouse.sql` (`sentinel.mitigations`), `engine-ml/models/build_dataset.py` + `evaluate_holdout.py` (pin `-A 0`), `engine-ml/models/threshold_table.py` + `threshold_table.json` (new), `engine-ml/tests/test_mitigator.py` (new), `engine-ml/tests/lab_nftables_netns.py` (new) |
| Dashboards | `dashboard/grafana/dashboards/sentinelflow.json` (panel 6, version 4) |
| Verification | `tests/verify_closed_loop.sh` (new; `PY_DAEMON` preflight after run 1) |
| Repo | `Makefile` (`test-engine` runs the mitigator tests; new `runtime-venv`, `verify-closed-loop`), `.gitignore` (`engine-ml/.venv-runtime/`, XDP build outputs) |
| Provided by the project owner | `mitigation-ebpf/xdp_blocker.bpf.c`, `mitigation-ebpf/xdp_ctl.c` (built, not attached) |

Nothing has been committed.

---

## 9. What may and may not be said

**May be said (observed in this session):**
- The sensor exports cumulative snapshots of still-active flows every `-A` seconds. `-A 0` reproduces the Part 3 sensor output exactly (byte-identical regression set, identical corpus flow counts).
- The blocking policy never selected a private or special-purpose address in the Part 3/4 data. It blocks on ML score ≥ 0.80 from a trained model, or on 6 severe nDPI risks; other risks never block on their own.
- With nftables in a namespace lab, a block placed by `Mitigator` dropped 50/50 packets from the blocked peer, with an exact per-element counter (50 packets / 6,400 bytes), while 50/50 packets from a benign peer were delivered. Timeout expiry and manual unblock worked.
- Dry-run mitigation over the 11 Part 3 captures produced 24 blocks and 7 protected skips, recorded identically in JSONL, SQLite and ClickHouse, and shown by Panel 6 in both dashboards.
- On the saved holdout predictions, 0.80 + `severe` would block 16/23 malicious endpoints and 2/61 benign endpoints, with at least one block in each of the 5 infections.
- The automatic loop works end to end in a namespace lab (§7.2). A replayed holdout capture was scored by the ONNX model, its two C2 endpoints were blocked in nftables by the daemon without manual steps, and afterwards 0/50 packets from the blocked endpoint were delivered (counter exactly 50 packets / 6,400 bytes) while 50/50 from a normal peer were delivered.

**Must not be said (not shown):**
- **That the loop works on live capture or against a running C2 session.** Wave 1 was an offline replay (`sensor -r`), not live capture (`-i`). Wave 2 traffic was synthetic UDP from the blocked address, not the malware's own protocol. Time from detection to block under live traffic was not measured.
- **Anything about XDP enforcement, XDP drop counters, or XDP performance.** XDP was not attached (§6).
- **Blocking mid-connection with `-A`.** The snapshot logic is tested offline only.
- **That blocks are safe on a production host without an allowlist.** The Part 3 data contained Microsoft and Cloudflare addresses the policy would block (§2.1).
- **That the false-block rates in §5 generalize.** They come from 61 benign holdout endpoints and one CV seed.
