# SentinelFlow — Next Steps

Proposed work after Part 7 (2026-10-24), most useful first. Big downloads belong on **Google Colab**, not the development machine, which is on mobile data. Small things (IOC text files, git push) are fine locally.

Words you may not know are explained in [GUIDE.md](GUIDE.md). The evidence behind every number is in [REPORT.md](REPORT.md).

---

## 1. Datasets

### Where we are

- **Training:** 40 malware-traffic-analysis.net (MTA) cases plus the nDPI test corpus. 12,250 flows; 2,846 malicious flows from 51 infected captures.
- **Holdout (the fair test):** 5 MTA infections the model never trains on.
- **Main weakness now: measurement.** With only 5 holdout captures, a change like "17 vs 15 servers detected" is a small sample.

### Ranked options

| # | Dataset | Why | Effort | What I need from you |
|---|---|---|---|---|
| **1** | **Bigger holdout: ~5 more recent MTA cases (2026)** | The test grows from 5 to about 10 infections. Choosing cases **newer** than all training data gives a realistic "future malware" test. | Small: same tools; I write labels from the IOC text files (a few KB each) **before** any model sees them. | Run `colab_train.sh` once I've added them; paste the output. |
| **2** | **~20 more MTA training cases** | Many families still have only 1–2 captures. More variety is what improved Part 7. Same format and labeling, nothing new to build. | Small to medium (reading IOC files). | Same as above. |
| 3 | **DNS-tunnel corpus** ([ggyggy666/DNS-Tunnel-Datasets](https://github.com/ggyggy666/DNS-Tunnel-Datasets)) | Real captures of dnscat2, iodine, dnspot, DNS-shell and others. Training today has only one DNS-tunnel capture. | Medium: needs a "DNS flows only" labeling rule, plus a check that it doesn't add DNS false alerts. | Output of the inspection commands below. |
| 4 | Stratosphere CTU-Normal-20 (Windows) and CTU-Normal-33 (real user, 1.1 h) | More normal traffic. | Small. | Nothing; plain PCAPs, all benign. |
| 5 | Stratosphere CTU-Malware botnet captures | Long C2 sessions. | Medium: mostly 2013–2019 families, and labels need a new parser. | Later. |
| – | Active Countermeasures "Malware of the Day" | Realistic C2 frameworks with jitter. | **Can't be scripted**: the site returns HTTP 403 to automated downloads. Manual download + upload only. | Only if you download by hand. |
| – | CIC-IDS2017 / CSE-CIC-IDS2018 | Big and well known. | Mostly attacks (DoS, brute force, web) rather than C2; huge files; labels from separate CSVs. | Not recommended for this goal. |

**Recommendation: do 1 and 2 together**, then 3 if you want DNS-tunnel detection.

### Notes on the earlier `Datasets` notes file (now removed)

- **Stratosphere "real benign HTTPS" (CTU-Normal-20…32):** 12 of these 13 captures are a 2017 *script* visiting top websites from **Kali Linux**. Only #20 is Windows. They aren't real Windows background traffic, and 2017 TLS looks different from today's, so they wouldn't teach the model much about the Microsoft false alerts.
- **"2 false blocks on Microsoft (azureedge.net, login.live.com)":** the holdout false blocks are the addresses `13.107.213.57` and `20.190.135.18`. Their host names weren't checked in this project.
- **"Only 1 DNS-tunnel capture":** roughly right. The nDPI corpus has a few tunnel/exfiltration captures, and each is one capture group.

### Candidate cases (to check before use)

All Windows infections with a single capture file and an IOC list or page (check each before adding):

- **Holdout candidates (newest; never used for training):** 2026-01-09 VIP Recovery, 2026-01-14 Lumma + follow-up, 2026-01-15 XLoader, 2026-01-22 SmartApeSG ClickFix → Remcos, 2026-02-03 GuLoader → AgentTesla FTP, 2026-05-22 SmartApeSG → unidentified RAT → NetSupport, 2026-08-21 SmartApeSG → two RATs.
- **Training candidates:** 2023-01-31 Qakbot + Cobalt Strike, 2023-03-24 IcedID + BackConnect, 2023-05-02 Qakbot + VNC, 2023-08-09 IcedID + BackConnect + VNC, 2023-10-16 IcedID, 2023-11-30 and 2023-12-07 DarkGate, 2023-12-11 Astaroth, 2024-01-25 DarkGate, 2024-02-14 DanaBot, 2024-03-26 Matanbuchus + DanaBot, 2024-06-10 OriginLogger, 2024-09-17 Snake KeyLogger FTP, 2025-01-30 XLoader, 2025-03-26 SmartApeSG → NetSupport + StealC, 2025-05-22 StealC v2, 2025-06-21 Koi, 2025-09-05 XLoader, 2025-12-22 StealC.
- **Still excluded:** more Pikabot / Gozi (already over-represented), SectopRAT (keeps holdout case 2025-08-15 an unseen family), macOS / Linux / Android cases, "scans and probes" server logs, multi-infection data dumps.

### Colab commands

**Retrain with whatever cases are in the repo** (downloads ~700 MB on Google's network, not yours):

```
!git clone -q https://github.com/AbdeldjallilZennir/sentinel-flow.git /root/cv_work
!bash /root/cv_work/sentinel-flow/scripts/colab_train.sh
from google.colab import files; files.download("/root/sentinel_model.zip")
```

Paste back the **label check** table and the **before / after** table it prints.

**Inspect the DNS-tunnel corpus** (option 3):

```
!git clone -q --depth 1 https://github.com/ggyggy666/DNS-Tunnel-Datasets /content/dnst
!apt-get -qq install -y tshark > /dev/null
!find /content/dnst -name "*.pcap*" -printf "%s %p\n" | sort -k2
!for f in /content/dnst/tunnel/*.pcap; do echo "== $f"; tshark -n -r "$f" -q -z conv,ip | sed -n 6,10p; tshark -n -r "$f" -T fields -e _ws.col.Protocol | sort | uniq -c | sort -rn | head -4; done
```

Paste back the output. It shows which addresses and protocols each capture contains, so the labeling rule can be written correctly.

---

## 2. Model and evaluation

- **Watch the new Google false alerts.** Model `203d33a1` flags some long TLS sessions to Google (31–43 s) as suspicious: 3 flows on the holdout. The per-IP rule doesn't block them, but they appear on the dashboard. Check on live traffic.
- **Labels for internal attacker traffic.** Labels are by IP address, so attacker activity between internal machines (e.g. WinRM to the domain controller) counts as "benign" and shows up as false alerts. A rule for traffic *from the infected host to internal servers on admin ports* would make the numbers more honest.
- **IsolationForest** (the second model) adds noise and isn't used for alerts. Either drop it or replace it with something better defined.
- **Recalibrate** after the dataset grows: the 0.80 threshold is set so that about 1 % of benign training flows score above it.

## 3. Engineering

| Item | State | What's needed |
|---|---|---|
| XDP blocking (faster kernel drop) | Sources compile, attaching fails (REPORT Part 4 §6) | Fix the BPF map definition for libbpf, and make the program use the same pinned map as `xdp_ctl` |
| Grafana panel for scan / "detected, not blocked" events | Only in the built-in dashboard (`query_dashboard.py` panel 6b) | Add a Grafana panel on `sentinel.mitigations` |
| Live-capture throughput | Only offline speed measured (~0.40 Mpps) | Measure on a real interface under load |
| `pyzmq` transport | Untested; the C `zmq_sink` path is used | Test or remove |
| Offline idle expiry checked every 1,000 packets | Documented, kept for reproducibility (REPORT Part 4 §1.3) | Optional change |
| Unfinished attack-family dataset code | In `git stash` ("unfinished: attack families + lab sessions") | Decide: finish or drop (`git stash drop`) |
| Phase 5 demo | Not started | Plan a demo scenario (lab VM + dashboard) |

## 4. Housekeeping

- **Revoke the GitHub tokens** that were pasted into chat sessions (GitHub → Settings → Developer settings → Personal access tokens). Make a new one when needed and don't paste it into chats; use `git push` from your own terminal or a credential manager.
- After any retrain: `make test-engine`, then update the README numbers from the new `evaluation.json` / `evaluation_holdout.json`.
