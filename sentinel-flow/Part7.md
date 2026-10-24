# Part 7 — More training data (23 MTA cases), retrain

Date: 2026-10-24. New model: `lgbm+iforest-fv1-203d33a1` (previous: `2005d025`).
Built, trained and evaluated on the development host, offline, from captures downloaded once.

## 0. Summary

| | Before (`2005d025`) | After (`203d33a1`) |
|---|---|---|
| MTA training cases | 17 | **40** |
| Labeled flows | 9,659 | 12,250 |
| Malicious flows / captures | 1,825 / 28 | **2,846 / 51** |
| CV recall @ 0.80 (5 seeds) | 0.449 ± 0.020 | 0.648 ± 0.035 |
| CV precision / false-alarm rate | 0.922 / 0.9 % | 0.952 / 1.0 % |
| CV ROC-AUC / PR-AUC | 0.980 / 0.901 | 0.984 / 0.945 |
| **Holdout:** infections / malicious endpoints alerted | 5/5, 15/23 | 5/5, **17/23** |
| **Holdout:** flow recall / false alerts | 0.229 / 3 of 498 | 0.268 / **12 of 498** |
| **Holdout, per-IP blocking rule:** malicious IPs / benign IPs blocked | 14/23, 2 | 14/23, 2 (same two Microsoft IPs) |

CV numbers are on different data and are **not** a like-for-like comparison. The holdout (5 fixed captures, never trained on) is: the model alerts on more attacker endpoints and many more malicious flows, raises more flow-level false alerts, and blocks exactly the same under the Part 6 per-IP rule.

## 1. Data choice

Candidates looked at (the `Datasets` notes file in the repo root, plus MTA itself):

| Source | Verdict | Why |
|---|---|---|
| **More malware-traffic-analysis.net cases** | **used** | Same source, format and labeling as the existing 17 cases; recent (2023–2026) Windows infections, each with its own real Windows background traffic; IOC lists give C2 IPs/domains. Fixes the main weakness (most families seen once). |
| Stratosphere CTU-Normal | not now | Reachable, but CTU-Normal-20…32 are 2017 scripted visits to top websites, 12 of 13 from Kali Linux. Old TLS stacks and no Windows background; weak match for the Microsoft false alerts. |
| Stratosphere CTU-Malware | not now | Mostly 2013–2019 families; labels need a new parser. |
| Active Countermeasures "Malware of the Day" | not usable unattended | Site answers HTTP 403 to scripted downloads, so it can't run in a Colab script. |
| DNS-tunnel corpus (ggyggy666/DNS-Tunnel-Datasets) | later | Real captures (dnscat2, iodine, dnspot, …), but a separate goal, and it needs a "DNS-only" labeling rule plus a check that it doesn't add DNS false alerts. |

**Cases added (23):** Rhadamanthys, MetaStealer, Bandook, DanaBot (×2, one with Matanbuchus), IcedID (×2), Lumma (×2, one with Rsockstun), AgentTesla FTP (×2), StealC, UltraVNC, SSLoad, DarkGate, XLoader/Formbook, Snake KeyLogger SMTP, StrelaStealer, a PureLogs-style RAT, Koi Loader, XWorm, njRAT + MassLogger, KongTuke/MintsLoader/GhostWeaver.

**Deliberately not added:** more Pikabot / Gozi (already 75 % of malicious flows before), SectopRAT (so holdout case 2025-08-15 still tests a family absent from training), the 5 holdout dates, macOS/Linux/Android cases, "scans and probes" server logs, multi-infection data dumps, cases without a usable capture or IOC list (Emotet 2023-03-22, Remcos 2026-08-06, GuLoader 2024-08-26, Raspberry Robin 2024-11-14), and WikiLoader (C2 runs through a public MQTT broker, which the labeling rules treat as a shared service).

## 2. Labels

Written from each case's IOC text (or page), same rules as before: attacker C2 / payload / exfil infrastructure = malicious; compromised legitimate sites, file-sharing, IP-lookup services, CDNs = ambiguous (excluded); everything else in the capture = benign background. Each new entry has a `"note"` field.

Checks done on the built dataset (per case: malicious / benign / ambiguous counts and the busiest "benign" remote IPs):

- Every new case has malicious flows (1 to 390 each).
- **Fixed 1:** SSLoad 2024-04-17: 27 flows to the WebDAV host that served the MSI (`krd6.com`, listed under "location of MSI" in the IOC text) were benign → added as malicious (1 → 28 malicious flows).
- **Fixed 2:** njRAT + MassLogger 2026-01-29: the IOC text names `cphost.qhoster.net:587` for SMTP exfil, but the capture's DNS resolves `cphost14.qhoster.net` (78.110.166.82) → labeled by that name and IP. IP-lookup and Telegram traffic → ambiguous.
- **Bug caught:** the first version used a `"source"` key per entry, which overrode `build_dataset.py`'s internal `source="mta"` (benign flows of new cases got the malware family name instead of "background"). Renamed to `"note"` before training; the numbers here are from the fixed build.
- XLoader/Formbook contributes 390 malicious flows, including traffic to decoy domains on shared parking hosts. That is real Formbook C2-pattern traffic; the per-capture weight cap in training limits its influence.

## 3. Holdout detail

```text
                                    before (2005d025)   after (203d33a1)
2023-11-06 404 TDS + Cobalt Strike   67/2227  5/8  1     81/2227  5/8  6
2023-11-20 DarkGate                 614/687   2/2  0    686/687   2/2  0
2024-02-21 SocGholish + AsyncRAT      6/11    3/5  0      9/11    5/5  0
2025-08-15 Lumma + SectopRAT         14/148   3/3  0     45/148   3/3  0
2025-12-29 ClickFix + NetSupport      4/11    2/5  2      4/11    2/5  6
(ML-detected malicious flows / endpoints alerted / false alerts)
```

- **Newly alerted endpoints:** the 404 TDS redirect `201.148.107.213` (best score 0.007 → 0.917), the SocGholish fake-update host `66.135.17.87` (0.048 → 0.810) and `49.13.65.235` (0.381 → 0.972). These HTTPS delivery/redirect servers were the main misses in Part 3. **Lost:** `193.3.19.230` (0.862 → 0.780).
- **Unseen family:** Lumma + SectopRAT flows detected 14 → 45 of 148 (SectopRAT is still absent from training).
- **The 12 false alerts:**
  - 6 are WinRM (5985) from the infected host to the domain controller (Part 3 noted these are probably attacker lateral movement that IP-based labels count as benign); private-to-private, never blocked.
  - 1 is SMB from the domain controller to the client; private, never blocked.
  - 2 are the same Microsoft IPs as before (in `config/default_allowlist.txt`).
  - **3 are new: long TLS sessions to Google** (`142.250.138.132`, `142.250.115.100`, `142.251.186.101`, 31–43 s, scores 0.89–0.95). They show up as `is_alert`, but the per-IP rule doesn't block them (single flow < 0.95).
- **Per-IP blocking (Part 6 rule):** identical for both models: 14/23 malicious IPs, 5/5 infections, 2 benign IPs (Microsoft), 0 with the allowlist.

Out-of-fold per-IP blocking on the new training set: 106 of 171 malicious IPs, 36 of 51 infections, 31 benign IPs blocked (old model on the old set: 56/91, 15/28, 15). Different data, so only the rates are indicative.

## 4. Other changes

- `engine-ml/models/compare_holdout.py`: before/after table from two `evaluation_holdout.json` files.
- `scripts/colab_train.sh`: scores the current model on the holdout first, fetches the 40 cases, prints a per-case label check (warns on any case without malicious flows), trains, re-runs the holdout, prints the comparison, and adds `holdout_before.json`, `holdout_compare.txt`, `dataset_summary.json` to the zip.
- `scripts/colab_holdout.sh`: no longer cuts off the first capture and model line.
- Tests: daemon 15/15, mitigator 32 (1 skipped without the lab session file). The daemon loads `203d33a1` after the SHA-256 check. ONNX parity: 0 / 12,127 alert decisions differ.

## 5. Not done / caveats

- `models/threshold_table.json` and the README threshold table still describe older models.
- The holdout is 5 captures; "more endpoints, more false alerts" is one sample.
- The 3 Google false alerts suggest long TLS sessions now look more C2-like; worth watching on live traffic.
- Rolling back: `git checkout ddcbd03 -- sentinel-flow/engine-ml/models/{c2_detector.onnx,anomaly_iforest.onnx,model_meta.json}` (or revert the commit).
