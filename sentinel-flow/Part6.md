# Part 6 — Alert rule and per-IP blocking

Date: 2026-10-24. Model unchanged: `lgbm+iforest-fv1-2005d025`.

## 0. Summary

| Change | Before | After |
|---|---|---|
| `is_alert` default (`daemon.py --alert-risk-policy`) | `any`: any nDPI risk raises an alert (18 % of benign flows) | `severe`: only the risks in `features.SEVERE_MASK`. `any` is still available. |
| Blocking (`mitigator.BlockPolicy`) | Any single flow with score ≥ 0.80 blocks the remote IP | Decided per remote IP: **one flow ≥ 0.95**, or **2 flows ≥ 0.80 to the same IP within 1 h**, or a severe nDPI risk |
| Scan detection | None (per-flow model scores each probe as harmless) | One source hitting **≥ 50 ports on one host**, or **≥ 100 hosts on one port** (flows ≤ 3 packets), within 60 s → the **source** is blocked (or logged, if it is a protected address) |

No retraining was needed. All of this is policy around the model.

## 1. Evidence

Same code (`BlockPolicy`, defaults vs. the old rule) run over three data sets. "Benign IPs blocked" = remote IPs blocked that carried only benign-labeled flows in that capture. "Ambiguous" = shared services abused by malware (IP-lookup sites etc.), which the labels exclude from both classes.

| Data | Rule | Malicious IPs blocked | Benign IPs blocked | Infections with ≥ 1 block |
|---|---|---|---|---|
| Training, out-of-fold scores (9,597 flows, 91 malicious / 2,450 benign IPs) | old | 70 | 44 | 16 / 28 |
| | **new** | 56 | **15** | 15 / 28 |
| Holdout, live replay (3,592 flows, 23 malicious remote IPs) | old | 16 | 2 (+ 2 ambiguous) | 5 / 5 |
| | **new** | 14 | 2 (+ 1 ambiguous) | 5 / 5 |
| | new + `config/default_allowlist.txt` | 14 | 0 | 5 / 5 |
| Lab nmap session (1,137 flows, 1,002 ports in 220 s) | old | — | — | scan not seen (max score 0.32) |
| | **new** | — | — | scan detected after 50 ports |

- On training data the new rule wrongly blocks about a third as many benign IPs (44 → 15) and loses one infection.
- **On the holdout the new rule does not help and costs 2 malicious IPs.** The two benign false blocks are the Microsoft addresses `13.107.213.57` and `20.190.135.18`, which score ≥ 0.95, so per-IP counting cannot remove them. The rule drops one ambiguous block (`193.122.6.168`, checkip.dyndns.org) and loses `193.3.19.230` (one flow, 0.86) and `104.21.24.30` (best flow 0.91), both single-flow endpoints. The training result is the reason for the change; the holdout (5 captures) is a sanity check that infections are still caught.
- **Allowlist:** `config/default_allowlist.txt` removes the remaining holdout false blocks, but its first three entries were taken from the holdout itself, so that row is not an independent result.
- `is_alert` on the nmap session: 1,031 → 1 flow. The remaining one is an RDP flow whose risk mask was corrupted by the pre-fix sensor (Part5.md §4); a current sensor would not produce it.

**Scan thresholds vs. benign traffic** (training set, 60 s windows): the most distinct ports from one source to one host was 9 (a game client). The most distinct hosts on one port with short flows was 40 (Gnutella, UDP). Over all flow lengths it was 56 (Ethereum P2P), which is why the sweep rule counts only flows of ≤ 3 packets. Holdout maximum: 6 ports.

Thresholds (0.95 / 2 flows / 1 h) were chosen on the training out-of-fold scores, then checked on the holdout. The holdout was not used to pick them, but it is only 5 captures.

## 2. Behavior details

- **Time** comes from flow timestamps (`last_seen_us` for ML counting, `first_seen_us` for scans), so PCAP replays behave like live capture.
- **Scan target** is always the source. A scanner inside a protected range (default RFC 1918) is not blocked; the event is written as `skip_protected` with reason `scan` and logged as `SCAN (not blocked) …`.
- **Scan events** fire at most once per (source, target) every 10 minutes, so a 1,000-port scan produces one event, not twenty.
- **Memory**: per-IP trackers are pruned once a table exceeds 100,000 keys.
- **New reason codes**: `ml_repeat` (4) and `scan` (5), next to `ml_score` (1), `severe_risk` (2) and `manual` (3). They appear in `mitigations.jsonl`, `blocked_ips` and `sentinel.mitigations` with no schema change.

## 3. New daemon flags

| Flag | Default | |
|---|---|---|
| `--block-high-score` | 0.95 | One flow at or above this blocks |
| `--block-repeat` | 2 | Flows ≥ 0.80 to one IP that block it |
| `--block-repeat-window` | 3600 | Seconds |
| `--scan-ports` | 50 | 0 = off |
| `--sweep-hosts` | 100 | 0 = off |
| `--scan-window` | 60 | Seconds |

`--block-high-score 0.80 --block-repeat 1 --scan-ports 0 --sweep-hosts 0` restores the previous behavior. `--alert-risk-policy any` restores the Phase 2 `is_alert` rule.

## 4. Tests

- `engine-ml/tests/test_mitigator.py`: 32 tests (18 before), all pass. New: thresholds, per-IP repeat counting, window expiry by flow time, legacy mode, severe + moderate score, port scan, slow scan not firing, host sweep ignoring long flows, protected scanner + cooldown, scans disabled, mitigator audit rows.
- `test_lab_nmap_session` replays the lab session when `SENTINEL_NMAP_FLOWS=<path to its flows.jsonl>` is set; otherwise it is skipped.
- `engine-ml/tests/test_daemon.py`: 15/15 pass (unchanged).
- `daemon.py --from-jsonl <nmap flows> --mitigate dry-run`: logs the scan as not blocked by default; with `--allow-private-blocks` it blocks `192.168.230.1` with reason `scan`.

## 5. Not done / caveats

_(Items 1 and the allowlist note are addressed in §6.)_

- The **dashboard** shows new reasons as plain strings. There is no panel for `skip_protected` scan events yet; they are in `mitigations.jsonl` and SQLite `mitigation_events`.
- **Delay**: the sensor exports a flow only after it ends or idles 30 s, so a scan is detected about 30 s after the 50th port. A repeat-rule block waits for the second suspicious flow.
- `evaluate_holdout.py` now defaults to `--risk-policy severe`, so its `is_alert` columns change. The summary table still prints all policies.
- Thresholds come from lab captures (MTA + nDPI corpus). Busy production networks may need a higher `--sweep-hosts` (e.g. scanners you run yourself, monitoring systems): allowlist them.

## 6. Follow-up (same day)

1. **Dashboard:** `query_dashboard.py` has a new panel **6b "Recent Mitigation & Scan Events"**: the last 50 events from `mitigation_events` (SQLite) or `sentinel.mitigations` (ClickHouse), excluding counter updates. `skip_protected` is shown as **"detected, not blocked"**, so a LAN scanner shows up on the dashboard. Checked on SQLite (nmap replay: the scan row appears), on a database without mitigation tables (falls back to a note), and on ClickHouse with the existing Part 4 data. The Grafana dashboard is unchanged.
2. **Allowlist:** `config/default_allowlist.txt`, 6 entries: the two holdout Microsoft false blocks, `api.ipify.org` (shared Cloudflare IP, ambiguous label), and 1.1.1.1 / 8.8.8.8 / 9.9.9.9. On the holdout replay it removes all non-malicious blocks with the same 14 / 23 malicious IPs. Because the entries came from the holdout, that is not an independent result.
3. **Correction to §1:** the first version of this report counted 2 ambiguous IP-lookup endpoints as benign on the holdout ("4 → 3 benign IPs"). The corrected numbers are in the §1 table: 2 benign blocks before and after.
4. **Tests:** `make test-sensor` (13 + 24 + 11) and `make test-engine` (15 + 32, 1 skipped without the lab session file) pass.
