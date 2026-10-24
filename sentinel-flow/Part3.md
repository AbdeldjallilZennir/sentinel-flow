# SentinelFlow — Part 3: Phases 1–3 Status, Audit, and the Encrypted-Traffic ML Pipeline

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Tree:** `/home/joe/cv_work/sentinel-flow/`
**Date:** 2026-10-23
**Host:** Kali Linux 6.16.8, Intel i7-1165G7 (8 threads), Python 3.14.7, nDPI 6.1.0-5906, libzmq 4.3.5, ClickHouse 24.8.14.39, Grafana 13.0.1
**Status:**
- **Phase 1 (C sensor)** and **Phase 2 (ingestion & analytics)** were re-checked against the README. The open Phase 1 items are now verified: memory safety, live capture, 30 s expiry, signal flush and throughput. The audit also found and fixed **seven sensor bugs** and **one consumer bug**, each with a regression test.
- **Phase 3 (ML pipeline)** is built end to end, from labeled PCAPs to ONNX models scored live in `daemon.py`. It was evaluated with grouped cross-validation and on 5 malware captures that were never used for training.

> [!info] How to read this document
> Same claim discipline as `part1.md` §12 and `part2.md` §10: every statement here is backed by output captured in this session. §11 lists what was **not** shown. `part1.md`, `part1_2.md` and `part2.md` stay valid for what they cover; this file records what changed since and adds Phase 3.

---

## 0. Summary

| Area | Result |
|---|---|
| Phase 1 vs README | All "Phase 1" checklist items done. Three README claims that had not been demonstrated before ("no memory leaks", live `-i`, "30 s idle expiration") are now demonstrated (§3). One README claim is wrong: the JSON has **23** fields, not 24. |
| Sensor bugs found & fixed | (1) undefined-behavior misaligned header reads, (2) garbage `ja4_client` on non-TLS flows (nDPI union read), (3) unsigned underflow of duration/IAT on out-of-order packets, (4) every non-Ethernet capture silently ignored, (5) flows lost silently when the consumer is slow (fixed in the sink), (6) dropped flows counted as "exported", (7) µs precision lost on flows > ~17 min. |
| Phase 2 vs README | Done, with the stdlib substitutes agreed in Part 2 (no `pyzmq` / `clickhouse-connect`). The default batch size is now **1,000 rows** (README "1,000 records / 1 sec"; it was 100). A 5th panel shows ML detections. |
| Phase 3 dataset | **9,659 flows** from **601 PCAPs** (22 malware-traffic-analysis.net cases + nDPI corpus + repo PCAPs), all produced by the production path `sensor → ZMQ → zmq_sink`. 0 dropped, 0 rejected. 1,825 malicious flows in 28 captures / 25 families. Also loaded into ClickHouse `sentinel.training_flows`. |
| Phase 3 models | LightGBM classifier + IsolationForest (benign-only), exported to ONNX. Parity with the native models on all 9,597 labeled rows: max \|Δp\| = 3.7e-4, 0 alert decisions differ. |
| Cross-validation (grouped by capture, 5 seeds) | Calibrated LightGBM at the 0.80 alert threshold: **recall 0.45 ± 0.04, precision 0.91 ± 0.03, FPR 1.1 % ± 0.4 %, ROC-AUC 0.980, PR-AUC 0.905 ± 0.007**. |
| Holdout (5 never-seen infections, full live pipeline) | **5/5 infections detected**, **15/23 malicious endpoints** alerted, **precision 99.6 %, FPR 0.6 %** (3 false alerts / 498 benign flows). Flow-level recall 23 %. |
| Live scoring | `daemon.py` loads the ONNX models (SHA-256-checked), scores each batch (1,000 flows in 36–47 ms), and falls back to the Phase 2 heuristic when `onnxruntime` is missing. Verified with `python3 -S`. |
| Key finding for Phase 4 | The Phase 2 alert rule `ndpi_risk_mask > 0 OR score ≥ 0.80` fires on **18 % of real Windows background flows** (CV) and **18.3 %** on the holdout. Blocking on it would block a large share of normal traffic. It is kept as the default because it is your rule; `--alert-risk-policy` offers the alternatives (§8.4). |

---

## 1. README requirements check

### 1.1 Phase 1 — "The C Sensor & IPC Spine"

| README item | State | Evidence |
|---|---|---|
| libpcap from live interface or offline `.pcap` | Done | Offline: every run in this file. Live: `sensor -i lo` as root captured the 3 test HTTP requests (§3.8). |
| libndpi + 5-tuple hash table (uthash) | Done | `flow_table.c`; `test_flow` 13/13. |
| protocol name, JA4, `ndpi_flow_risk_bitmap` | Done; JA4 bug fixed | §3.3. JA4 of `test_tls_full.pcap` still matches ndpiReader (`t12d6707h2_2955a3196ffa_c83f907a73d3`, regression test). |
| Welford `iat_*`, `pkt_len_*` | Done; underflow fixed | `test_stats` 24/24; §3.4. |
| JSON over `ZMQ_PUSH` on `ipc:///tmp/ndpi_flows.sock` | Done; loss fixed | §3.6. |
| README "24-field JSON schema" | **Incorrect claim** | The sensor emits 23 fields (`daemon.SENSOR_FIELDS`, validated on 9,659 + 3,604 records). |
| README "uthash … 30s idle expiration" | Now demonstrated | §3.7. |
| README "Clean shutdown (SIGINT/SIGTERM), no memory leaks" | Now demonstrated | LeakSanitizer §3.1; SIGINT flush on live capture §3.8. |

### 1.2 Phase 2 — "ClickHouse Ingestion & Instant Visibility"

| README item | State | Evidence |
|---|---|---|
| ClickHouse + Grafana via `docker-compose.yml` | Done (Part 2) | Still running: `sentinel-clickhouse` healthy, Grafana datasource `OK`. |
| `daemon.py` with `pyzmq` + `clickhouse-connect` | Done with stdlib substitutes (Part 2 constraint) | `zmq_sink` child process + `urllib` JSONEachRow. The `pyzmq` path exists but is untested (not installed). |
| Flush every 1 s **or 1,000 rows** | **Fixed this session** | Default `--batch-size` was 100, now 1,000. Final run: batches of `1000, 1000, 1000, 591` rows (§9). |
| MergeTree `network_flows` | Done | `ENGINE = MergeTree`, `ORDER BY (first_seen_us, app_protocol, src_ip)`; 3 Phase 3 columns added with an idempotent migration (§8.3). |
| 4 Grafana panels (protocols, JA4 anomalies, traffic volume, high-risk) | Done; JA4 panel upgraded | The JA4 panel now shows per-fingerprint `max_ml_score` / `ml_alerts`, closer to "JA4 Fingerprint anomalies". 5th panel "ML Detections". All 5 queries return HTTP 200 through Grafana (§9.3). |

### 1.3 Phase 3 — "The Encrypted Traffic ML Pipeline"

| README item | State | Evidence |
|---|---|---|
| Download benign + malicious C2/exfil PCAPs (Malware-Traffic-Analysis.net / CIC) | Done (MTA + nDPI corpus) | 22 MTA cases (17 training, 5 holdout), 281 MB; only PCAP + IOC text archives (§4.1). CIC datasets not used. |
| Run them through the sensor to make labeled rows in ClickHouse ("zero feature mismatch") | Done | `build_dataset.py` uses `sensor -r → ZMQ → zmq_sink`; 9,659 rows in SQLite, JSONL and ClickHouse `sentinel.training_flows` (§5). |
| Train LightGBM (benign vs C2/exfil) + IsolationForest, export `.onnx` | Done | `train_pipeline.py` → `models/c2_detector.onnx`, `models/anomaly_iforest.onnx`, `models/model_meta.json` (§6–§7). |
| Load the `.onnx` in `daemon.py` with `onnxruntime`, score batches in real time | Done | `OnnxScorer` in `daemon.py`; live run of 3,604 flows (§9). |

---

## 2. System as built

```
 PCAP / NIC ──► sensor (C, libpcap + nDPI 6.1)                    sensor-c/
                 │  Ethernet/VLAN, Linux cooked v1/v2, BSD loopback, raw IP
                 │  5-tuple flows, JA4, risk mask, Welford IAT/len stats
                 │  JSON (23 fields) ──► ZMQ PUSH (connect)
                 ▼
            ipc:///tmp/ndpi_flows.sock
                 ▼
 zmq_sink (C, ZMQ PULL bind, RCVHWM=0) ──stdout JSONL──► daemon.py      engine-ml/
   (or pyzmq PULL if installed)          validate 23 fields
                                         stamp ingested_at_us
                                         batch (1,000 rows / 1 s)
                                         features.py ─► ONNX LightGBM + IsolationForest
                                           (fallback: heuristic_v1, stdlib)
                                         is_alert = risk-policy OR score ≥ 0.80
                       ┌─────────────────────┼────────────────────────┐
                       ▼                     ▼                        ▼
             SQLite (WAL)             flows.jsonl           ClickHouse sentinel.network_flows
         query_dashboard.py                                    Grafana (5 panels)

 Training path (offline, same sensor bytes):
 datasets/fetch_mta.py ─► PCAP + IOC ─► models/build_dataset.py (sensor→ZMQ→zmq_sink, labels)
   ─► data/training/flows_labeled.jsonl + training.db + ClickHouse sentinel.training_flows
   ─► models/train_pipeline.py (grouped CV, calibration, ONNX export, parity check)
   ─► models/evaluate_holdout.py (5 unseen captures through the live daemon)
```

---

## 3. Phase 1 audit (sensor)

The audit used three kinds of check:

- **Sanitizer build:** AddressSanitizer + LeakSanitizer + UndefinedBehaviorSanitizer, built in the scratchpad with `-fsanitize=address,undefined -g` (valgrind is not installed).
- **Corpus sweeps:** the whole nDPI test corpus, 631 captures.
- **Byte-for-byte regression:** a fixed 9-PCAP set (`test_dns`, `test_http`, `test_tls_full`, `tls_invalid_reads`, `http_invalid_server`, `malware`, `emotet`, `tor`, `quic`), 38 flows. After each fix its JSON had to stay byte-identical, unless the fix was meant to change it (§3.7).

### 3.1 Memory safety (ASan / LSan / UBSan)

First run, 12 PCAPs: **0 AddressSanitizer and 0 LeakSanitizer reports, but 8–12 UBSan `runtime error` lines per run**, all of one kind:

```text
sensor-c/src/main.c:223:19: runtime error: member access within misaligned address 0x7dc06cbe008e
for type 'const struct ip', which requires 4 byte alignment
```

To show LeakSanitizer was really active, a 3-line program that leaks 4,242 bytes was built with the same flags:

```text
==170614==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 4242 byte(s) in 1 object(s) allocated from:
```

**Fix 1 — misaligned header reads.** `main.c` cast `pkt + 14` to `struct ip *`. Offset 14 isn't 4-byte aligned, so this is undefined behavior: harmless on x86, a fault on strict-alignment CPUs. The IPv4, TCP and UDP headers (and the VLAN ethertype) are now `memcpy`'d into aligned locals. After the fix the 9-PCAP JSON was byte-identical and UBSan reported 0.

**Final sweep with the final binaries:** 16 PCAPs, including a 1,105-flow MTA capture, the non-Ethernet captures and the JA4-bug captures. 1,890 flows exported, 1,890 received by the ASan-built `zmq_sink`, **0 sanitizer errors** in sensor or sink.

### 3.2 Throughput (was "no packets-per-second number")

All 577 Ethernet captures in the nDPI corpus were converted to classic pcap (`editcap`; 1 failed) and concatenated (`mergecap`): **124,070 packets, 45 MB**. They were run through the final sensor with `zmq_sink` consuming:

```text
run 1: exit=0 dropped=0 packets=124070 flows_exported=9694 sink_received=9694 wall=0.29s pps=433,768 sensor_maxRSS=25.6MB
run 2: exit=0 dropped=0 packets=124070 flows_exported=9694 sink_received=9694 wall=0.31s pps=403,090 sensor_maxRSS=25.8MB
run 3: exit=0 dropped=0 packets=124070 flows_exported=9694 sink_received=9694 wall=0.29s pps=435,273 sensor_maxRSS=25.8MB
```

That's **~0.40–0.44 Mpps offline, single-threaded, 25.8 MB peak RSS**. This measures reading a file as fast as possible. It is not a live-capture line-rate number.

### 3.3 Fix 2 — garbage `ja4_client` on non-TLS flows

The first throughput run crashed my checker with `UnicodeDecodeError`: the sink output contained invalid UTF-8, and the bad byte changed from run to run (`0xe8`, `0xc8`, `0xf7`):

```text
"app_protocol":"SSDP","ja4_client":"\xf7\xb2\\u0004\x90U"
```

**Root cause:** `ndpi_wrapper_get_ja4()` read `flow->metadata.protos.tls_quic.ja4_client` for every flow. `metadata.protos` is a **union** shared by all dissectors, so on an SSDP, DHCP or TiVo flow those bytes belong to another protocol. A scan of the 577 Ethernet corpus files with the HEAD binary:

```text
  1kxun.pcap: 3 non-TLS flows with ja4 e.g. ('Mikrotik', '50G', False)
  gnutella.pcap: 1 non-TLS flows with ja4 e.g. ('DHCP', '2', False)
  mikrotik_mndp.pcap: 1 non-TLS flows with ja4 e.g. ('Mikrotik', 'UiG+5HPaxD2HPaxD', False)
  ssdp.pcapng: 1 non-TLS flows with ja4 e.g. ('SSDP', 'oe��U', True)
  teams.pcap: 1 non-TLS flows with ja4 e.g. ('DHCP', '19', False)
  telegram.pcap: 1 non-TLS flows with ja4 e.g. ('DHCP', '19', False)
  TivoDVR.pcap: 1 non-TLS flows with ja4 e.g. ('TiVoConnect', 'inidlna', False)
files_affected=7 flows_affected=9
--- fixed:
files_affected=0 flows_affected=0
```

**Fix:** read the field only when the master or app protocol is TLS-family (TLS, DTLS, QUIC, DoH/DoT, IMAPS, POPS, SMTPS, FTPS), **and** require a well-formed 36-character JA4 (`is_valid_ja4`). On the merged corpus: 886 flows carry a JA4, all of them TLS-family (TLS 742, QUIC 131, DTLS 9, IMAPS 2, POPS 1, SMTPS 1); 198 distinct fingerprints. Two flows carry `t13i0311/0_…`, where nDPI writes `/0` for a libp2p ALPN (the JA4 spec would use hex). That is nDPI's output and is passed through.

### 3.4 Fix 3 — unsigned underflow on out-of-order packets

The Phase 2 validator rejected 16 merged-corpus flows with `last_seen_us < first_seen_us`. Their records showed the bug:

```text
{'app_protocol': 'IPSec', 'pkt_count': 90, 'flow_duration_ms': 1.8446744e+16,
 'iat_mean': 2.07266787e+17, 'iat_max': 1.8446744e+19, ...}
```

`last_seen_us` was overwritten by every packet, and `pkt_time_us - last_pkt_us` underflowed as `uint64` when a packet's timestamp went backwards. Single (unmerged) captures trigger it too:

```text
  ipsec_isakmp_esp.pcap: 10/24 flows with underflowed duration/IAT
  geforcenow.pcapng / heuristic_tcp_ack_payload.pcap / mudfish.pcap / resp.pcap /
  sites3.pcapng / tls-appdata.pcap / yandex.pcapng: 1 each
files=577 flows=9738 affected_files=8 affected_flows=17        (HEAD)
files=577 flows=9738 affected_files=0 affected_flows=0         (fixed)
```

**Fix:** `first_seen_us` / `last_seen_us` are kept as min/max of packet times. A backwards step counts as IAT 0, and `last_pkt_us` never moves backwards. The 9-PCAP set was byte-identical afterwards.

### 3.5 Fix 4 — non-Ethernet link types were silently dropped

`main.c` assumed Ethernet framing and only printed a warning otherwise. **53 of the 631 corpus files** (Linux cooked capture, raw IP, BSD loopback, …) produced 0 flows, including two malicious samples (`Emotet_infection_url_dga_*` is raw IPv4, `dns2tcp_tunnel` is Linux cooked). Live capture on `-i any` or on a tun/VPN interface would have failed the same way.

**Fix:** `ipv4_offset()` decodes Ethernet (+ one 802.1Q tag), `DLT_LINUX_SLL`, `DLT_LINUX_SLL2`, `DLT_NULL` / `DLT_LOOP` (AF_INET in either byte order) and `DLT_RAW` / `DLT_IPV4`. The link type is logged at start. Result on the 53 files, with the ASan build, 0 sanitizer errors:

```text
rawip4     files=6   decoded=6   flows=15
linux-sll  files=17  decoded=16  flows=132
null       files=10  decoded=7   flows=11
rawip      files=16  decoded=16  flows=56
ppp        files=2   decoded=0   flows=0      (unsupported)
ppi        files=1   decoded=0   flows=0      (unsupported)
chdlc      files=1   decoded=0   flows=0      (unsupported)
```

The 4 remaining files of supported types that decode nothing contain no IPv4; the sensor is IPv4-only (known, see `part1_2.md` §5.2).

### 3.6 Fixes 5–6 — silent flow loss over ZeroMQ

The first full dataset build stopped with a 30 s read timeout on the second MTA capture. Reproduced:

```text
2023-07-12-Gozi-infection-with-Cobalt-St exported 1105 queued 1001
```

The sensor reported 1,105 flows exported but the consumer only ever received **1,001**, with no error anywhere.

**Diagnosis.** The trigger was my builder reading the sink's pipe unbuffered, which made it a slow consumer. Three hypotheses were tested in turn:

1. *Sender send-timeout drops.* Adding a drop counter showed `dropped=0`: not the cause.
2. *Sender linger expiring at close.* Socket monitoring showed the sender's queue had drained and `zmq_close` returned in 0.2 s: not the cause.
3. *Receiver high-water mark.* `zmq_sink` used the default `ZMQ_RCVHWM = 1000`. While its stdout is blocked, about 1,000 messages queue on the receiving side, and the in-flight rest is discarded when the sensor disconnects. Setting `ZMQ_RCVHWM = 0` in `zmq_sink`:

```text
before fix: exit=0 exported=1105 dropped=n/a (not reported) consumer_received=1001
sink RCVHWM=0, new sensor: exit=0 exported=1105 dropped=0 consumer_received=1105
sink RCVHWM=0, old sensor: exit=0 exported=1105 dropped=0 consumer_received=1105
```

**Fix 5 (root cause):** `ZMQ_RCVHWM = 0` in `zmq_sink.c` and in the daemon's `pyzmq` transport. Receive memory stays bounded by the sender's own queue (`ZMQ_SNDHWM = 10000`).

**Fix 6 (making loss visible), kept because it closes real gaps:**
- `export_flow` used to count a flow as exported even when `zmq_send` failed. Now the summary prints `Flows exported` (accepted by the ZMQ queue) and `Flows dropped` separately. An offline run with any drop exits with status **3**, and `build_dataset.py` aborts on it.
- Offline `-r` waits up to 10 s per flow for a full queue; live capture keeps the 200 ms bound so capture never stalls. After one drop a breaker limits retries until a send succeeds again, so a run with no consumer can't hang.
- At close, a libzmq socket monitor tells whether a consumer is connected. If so the sensor waits up to 60 s for the queue to drain, otherwise 500 ms. The old fixed 2 s linger could discard the tail of a large final flush, e.g. after SIGINT on a busy live capture.

```text
[zmq] closing: 1 consumer(s) connected, linger 60000 ms     (consumer present)
[zmq] closing: 0 consumer(s) connected, linger 500 ms       (no consumer; run took 0.64 s)
```

**Regression test** `test_stalled_consumer_loses_nothing`: 1,500 one-packet flows, and the consumer doesn't read until the sensor has exited. It passes with the new sink and fails with the HEAD sink, which receives about 1,001 and times out waiting for the rest.

### 3.7 Fix 7 — µs precision of long flows, and the 30 s expiry test

The final live run (§9) showed `timestamp mismatches: 15` on the holdout captures, which are 20–60 minutes long:

```text
HTTP|5003499711|5003499.71|5003499710      (delta_us | flow_duration_ms | round(ms*1000))
shortest_mismatch_us = 1058470424
```

`cJSON.c` printed non-integers with `%.9g`, so any duration over ~1,058 s lost microseconds. **Fix:** `%.15g`. On the 9-PCAP set this is the one intended output change: 729 fields identical, 145 gained digits (largest relative change 4.4e-9), and no string, IP, port or JA4 changed. Final live run: **timestamp mismatches 0**. Regression test `test_long_flow_duration_keeps_microseconds` fails on the old binary (`5003499710 != 5003499711`).

**30 s idle expiry (previously not tested).** A synthetic PCAP: flow A at t = 0–0.4 s, then 1,000 filler packets at t = 40 s (the sensor checks expiry every 1,000 packets), then A again at t = 42 s. Expected: A exported **twice**.

```text
10.0.0.1 40000 -> 10.0.0.2 9999 pkts 5 first 1700000000000000 last 1700000000400000
10.0.0.3 40001 -> 10.0.0.4 9998 pkts 1000 first 1700000040000000 last 1700000040999000
10.0.0.1 40000 -> 10.0.0.2 9999 pkts 5 first 1700000042000000 last 1700000042400000
║  Flows tracked:     3               ║
```

### 3.8 Live capture and SIGINT flush (previously not tested)

Final binary: `sudo sensor -i lo` against a local `python3 -m http.server`, 3 × `curl`, then SIGINT:

```text
curl 1 -> 200 / curl 2 -> 200 / curl 3 -> 200
sensor exited 1.63 s after SIGINT
[sensor] capturing live on: lo
[sensor] link type: EN10MB
║  Packets processed: 80   Flows tracked: 12   Flows exported: 12   Flows dropped: 0 ║
[zmq] closing: 1 consumer(s) connected, linger 60000 ms
sink received 12 flows; 3 to :18080: [('HTTP', 12), ('HTTP', 12), ('HTTP', 12)]
```

The other 9 flows are other local services' loopback traffic on this host (ports 6789 and 9200). The 1.63 s exit time is the 1 s `pcap_open_live` timeout plus the flush.

### 3.9 Sensor test suite

| Test | Result |
|---|---|
| `sensor-c/build/test_flow` (direction / byte accounting) | 13 passed, 0 failed |
| `sensor-c/build/test_stats` (Welford) | 24 passed, 0 failed |
| `sensor-c/tests/test_sensor_pcaps.py` (new; runs the real binary on synthetic + corpus PCAPs) | 7/7 OK: idle expiry, out-of-order timestamps, no JA4 on non-TLS (4 real corpus captures), JA4 still exact on TLS, 6 link-type framings, stalled consumer, long-flow precision |

Each new test was also run against the pre-fix binary and fails there, except the expiry test (expiry already worked) and the "JA4 still on TLS" test (a guard against over-fixing).

---

## 4. Phase 3 data

### 4.1 Malware-traffic-analysis.net (MTA)

`engine-ml/datasets/fetch_mta.py` downloads **only** `*.pcap.zip` and IOC/notes `*.txt.zip` archives. "malware"/"artifacts" archives (actual samples) are never fetched, and an archive containing any file other than `.pcap` / `.pcapng` / `.txt` would be dropped. Archives use the site's `infected_YYYYMMDD` password scheme, published as an image on the site's "about" page; extraction is done with `7z` into a temporary directory, and every extracted file's SHA-256 is recorded in `SOURCE.json`. The PCAPs are untrusted data, parsed only by the sensor and `tshark`.

**Training cases (17; 178 MB):**

| Case | Family | Flows | Malicious | Benign | Ambiguous |
|---|---|---|---|---|---|
| 2023-05-10 | Qakbot + Cobalt Strike + VNC | 543 | 91 | 452 | 0 |
| 2023-07-12 | Gozi/ISFB + Cobalt Strike | 1105 | 903 | 202 | 0 |
| 2023-10-03 | Pikabot + Cobalt Strike | 412 | 277 | 135 | 0 |
| 2023-10-31 | IcedID | 87 | 17 | 70 | 0 |
| 2023-12-18 | Pikabot + Cobalt Strike | 289 | 188 | 99 | 2 |
| 2024-01-09 | AsyncRAT | 4 | 3 | 1 | 0 |
| 2024-03-14 | AsyncRAT + XWorm | 37 | 12 | 15 | 10 |
| 2024-03-19 | DarkGate | 71 | 68 | 3 | 0 |
| 2024-04-18 | SSLoad + Cobalt Strike | 179 | 12 | 148 | 19 |
| 2024-06-12 | KoiLoader/KoiStealer | 297 | 30 | 260 | 7 |
| 2024-06-25 | Latrodectus + BackConnect + Keyhole VNC | 485 | 165 | 320 | 0 |
| 2024-09-19 | Lumma Stealer | 66 | 29 | 24 | 13 |
| 2024-10-23 | Redline Stealer | 3 | 1 | 1 | 1 |
| 2024-12-17 | NetSupport RAT | 19 | 1 | 14 | 4 |
| 2025-01-31 | AgentTesla-style FTP exfil / VIP Recovery SMTP exfil (2 PCAPs) | 10 | 4 | 3 | 3 |
| 2025-03-10 | Remcos RAT | 182 | 3 | 179 | 0 |
| 2025-11-19 | XWorm | 5 | 1 | 3 | 1 |

`2025-03-10/vmnet8a.pcap` was excluded: it's a near-duplicate raw capture of the same Remcos run (11 k packets, same ~19 minutes).

**Holdout cases (5; 103 MB), in a separate directory that the dataset builder never reads:** 2023-11-06 (404 TDS → Cobalt Strike), 2023-11-20 (DarkGate), 2024-02-21 (SocGholish → AsyncRAT), 2025-08-15 (Lumma Stealer → SectopRAT, a family absent from training) and 2025-12-29 (ClickFix → NetSupport RAT). Their labels (`datasets/mta_holdout_labels.json`) were written from the IOC texts **before** any model was run on them.

### 4.2 Labeling rules

MTA labels are curated by hand in `datasets/mta_labels.json`, written from each case's IOC text. Two cases needed other sources: 2025-03-10 came from the Unit 42 IOC file linked on the MTA page, and 2025-01-31 has no IOC file, so it was labeled from its flows.

- **malicious (1):** either endpoint is an IOC IP, or an IP that the capture's own DNS answers / TLS SNI / HTTP Host (via `tshark`, labeling only) map to an IOC domain. Classes: C2, payload delivery, exfiltration.
- **ambiguous (−1, excluded from training and evaluation):** shared or legitimate services the malware used: Dropbox, trycloudflare, Telegram, `t.me`, `sites.google.com`, Firebase, IP-lookup sites (`api.ipify.org`, `ip-api.com`, `api.ip.sb`, …), and compromised legitimate sites. Sections the IOC files mark "NOT MALICIOUS" / "LEGITIMATE DOMAINS" are never used as malicious.
- **benign (0):** every other flow in the capture ("background": Windows updates, telemetry, AD traffic). Benign traffic from the same lab environment keeps the model from learning "which dataset is this" instead of "is this C2".

**nDPI corpus rules** (`NDPI_RULES` / `NDPI_EXCLUDE` in `build_dataset.py`):
- **malicious:** `trickbot`, `websocket-chisel-ssh`, `tls_malicious_sha1`, DNS tunnels/exfil (`dns_exfiltration`, `dns-exf`, `dns-tunnel-iodine`, `dns2tcp_tunnel`) and `icmp-tunnel` (all flows); `malware`, `emotet`, `Emotet_infection_url_dga_*` ("non-infra" rule: their DNS/ICMP/NetBIOS/… flows are ambiguous).
- **excluded:** web attacks, scans, DoS, executable downloads, mining, anonymizers (Tor, Psiphon, Ultrasurf, Shadowsocks, `tls_heur__*`) and fuzzed/malformed captures. They aren't C2 and would blur the labels.
- **benign:** everything else, plus the 4 repo PCAPs.
- **`bot.pcap` is benign.** nDPI's own result file shows it is the Bing crawler (`[cat: Bots/124][Breed: Acceptable]`). Labeling it by filename would have been wrong.

### 4.3 Label audit

Every malicious MTA flow was grouped by destination and checked against the IOC text. Examples:

```text
Gozi/ISFB + CS: 803 → 170.130.55.162:443 TLS (Cobalt Strike C2), 74 → 151.248.117.244:80 (Gozi C2)
DarkGate:        67 → 103.124.105.78:80 HTTP (badbutperfect.com, resolved in-capture)
Remcos RAT:       3 → 206.123.152.51:3980 (nDPI labels this "Blizzard")
AsyncRAT+XWorm:   2 → 91.134.150.150:7000 (nDPI labels this "Cassandra")
```

Two side observations. nDPI sometimes names C2 channels by port guess ("Blizzard", "Cassandra"). And domain-based labels on Cloudflare IPs (Lumma, IcedID) label every flow to that IP within the capture, a known source of label noise.

---

## 5. Building the training set

```bash
LD_LIBRARY_PATH=~/nDPI/src/lib python3 engine-ml/models/build_dataset.py    # or: make dataset
```

`SensorRunner` keeps one `zmq_sink` alive and runs one `sensor -r` per PCAP. After the sensor exits with `Flows exported: N`, the next N sink lines belong to that PCAP: a single PUSH→PULL pipe preserves order, and the sensor drains before exit. Every record goes through `daemon.validate()`.

```json
{
  "pcaps": 601, "pcaps_with_flows": 562, "flows": 9659, "rejected_by_validation": 0,
  "by_source_label": {"mta/ambiguous": 60, "mta/benign": 1929, "mta/malicious": 1805,
                      "ndpi/ambiguous": 2, "ndpi/benign": 5839, "ndpi/malicious": 20, "repo/benign": 4},
  "groups": {"benign": 550, "malicious": 28}
}
[clickhouse] sentinel.training_flows: 9659 rows
```

Outputs: `engine-ml/data/training/flows_labeled.jsonl` (SHA-256 `f4af2732…`), `training.db`, `summary.json` (per-PCAP counts and link types), and ClickHouse `sentinel.training_flows`.

---

## 6. Features and models

### 6.1 Feature vector (`engine-ml/features.py`, 61 features, `FEATURE_VERSION = 1`)

`features.py` is used by both training and `daemon.py`, so the transformation is identical offline and online.

| Group | Features |
|---|---|
| Transport | `protocol`, `service_port` (min of the two ports), `service_port_wellknown` |
| Volume | log `pkt_count`, `bytes_up`, `bytes_down`, total; `bytes_per_pkt` |
| Timing | log `duration_ms`, log `iat_mean/stddev/min/max`, `iat_cv` |
| Sizes / shape | `pkt_len_mean`, `pkt_len_stddev`, `pkt_len_cv`, `log_up_down_ratio`, `small_pkt_ratio`, `unidirectional_bytes` |
| nDPI risk | `risk_count`, `has_risk`, 26 individual risk bits (from `ndpi_risk_enum`) |
| Classification | `app_tls`, `app_quic`, `app_http`, `app_dns`, `app_unknown`, `app_has_subprotocol` |
| JA4_a (parsed) | present, QUIC, TLS version, SNI-is-domain, #ciphers, #extensions, ALPN class |

IP addresses and timestamps are **deliberately not features**: they identify specific hosts and captures, and a model could memorize them.

### 6.2 Training (`engine-ml/models/train_pipeline.py`)

- **LightGBM:** 300 trees, learning rate 0.05, 31 leaves, `min_child_samples` 10, row/column subsampling 0.8, λ = 1.
- **Per-capture weight cap of 50.** One capture can't dominate: Gozi's 803-flow beacon counts as at most 50 flows.
- **IsolationForest:** 200 trees on **benign flows only**. Its raw anomaly is mapped so the benign median → 0 and the benign 99.5th percentile → 0.80.
- **Evaluation:** `StratifiedGroupKFold(k=5)`, grouped by capture (each MTA case or nDPI file), so near-duplicate flows from one capture never span train and test. Repeated with **5 seeds**: different fold assignment and model seed each time.
- **Baselines on the same data:** the Phase 2 heuristic, and "nDPI risk mask > 0".

### 6.3 Calibrating the score to the alert threshold

The Phase 2 rule alerts at `ml_anomaly_score ≥ 0.80`. Raw LightGBM probabilities rank C2 well but rarely reach 0.80 on unseen families. So `ml_anomaly_score` is a monotone, piecewise-linear map of the probability: raw threshold *t* → 0.80, with *t* the probability at which **1 % of held-out benign flows** would alert. *t* is the median over the 5 seeds of the per-seed 1 %-FPR thresholds `[0.376, 0.451, 0.330, 0.267, 0.319]`, so **t = 0.3298**. The map is monotone, so ROC-AUC and PR-AUC are unchanged. The raw probability is stored too, as `ml_c2_proba`.

---

## 7. Cross-validation results

### 7.1 Main result: spread over 5 seeds (calibrated LightGBM, threshold 0.80)

```text
[cv] calibrated LightGBM at 0.80 over 5 seeds (raw thresholds 0.376, 0.451, 0.330, 0.267, 0.319; median used):
  recall    mean=0.452 std=0.042 min=0.389 max=0.512
  precision mean=0.907 std=0.031 min=0.863 max=0.934
  fpr       mean=0.011 std=0.004 min=0.007 max=0.017
  roc_auc   mean=0.980 std=0.001 min=0.979 max=0.982
  pr_auc    mean=0.905 std=0.007 min=0.893 max=0.914
```

**Why a spread and not one number.** The first training runs (on data from the sensor before the §3.7 precision fix) gave a single-seed calibrated recall of 0.655. After the fix, where the inputs differed by under 1e-8 relative, the same seed gave 0.423: values that close can still fall into different LightGBM histogram bins. With only 28 malicious captures, one CV run is a noisy estimate, so the 5-seed spread above is the number to quote, and 0.655 is not.

### 7.2 Seed 42 in detail, with baselines (all 9,597 labeled flows, out-of-fold)

```text
  score                   recall precision      FPR  ROC-AUC  PR-AUC
  lgbm_raw                 0.254     0.951   0.0031    0.979   0.893
  lgbm_calibrated          0.438     0.863   0.0163    0.979   0.893
  iforest                  0.003     0.039   0.0157    0.846   0.423
  max(lgbm_cal, iforest)   0.439     0.764   0.0319    0.924   0.664
  phase2_heuristic         0.000     0.000   0.0012    0.697   0.284
  ndpi_risk_only           0.920     0.306   0.4910    0.715   0.296
```

Raw-probability recall at fixed FPR budgets (seed 42): **0.1 % → 0.094, 0.5 % → 0.312, 1 % → 0.423, 2 % → 0.724, 5 % → 0.929**.

Readings:
- **The Phase 2 heuristic detects nothing** at 0.80 (recall 0). It was a placeholder, and the data confirms it.
- **"Any nDPI risk" fires on 49 % of benign flows**: 59.5 % of the nDPI corpus (3,474/5,839, which is dissector test material full of edge cases) and **17.7 % of real Windows background** in the MTA captures (341/1,929).
- **IsolationForest is weak** (recall 0.003, PR-AUC 0.42). Adding it to the alert score (`max`) doubles the FPR for +0.001 recall. **Decision: it's stored as `ml_iforest_score` for analysts but not used for alerting.**

### 7.3 Where it fails (seed 42, calibrated)

Malicious captures with ≥ 1 alert: **14/28**. Benign FPR by source: MTA background 37/1,929 (1.9 %), nDPI corpus 90/5,839 (1.5 %).

| Family (flows) | Detected |
|---|---|
| Qakbot + CS (91) | 86 |
| Latrodectus (165) | 134 |
| IcedID (17) | 14 |
| Pikabot + CS (465) | 250 |
| Gozi + CS (903) | 276 |
| SSLoad + CS (12) | 7 |
| Lumma (29) / Koi (30) | 12 / 12 |
| AsyncRAT (3) / XWorm (1) | 2 / 1 |
| DarkGate (68) | 3 |
| AsyncRAT + XWorm (12) | 1 |
| Emotet (7) | 2 |
| Remcos, Redline, NetSupport, FTP/SMTP exfil, TrickBot, chisel, all DNS/ICMP tunnels | 0 |

The misses are mostly **families that appear in exactly one capture**: each tunnel type, several RATs, the exfil pair. When that capture is held out, nothing similar is left to learn from. More model tuning won't fix that; more captures per family will (§10).

### 7.4 One variant tested (selection rule fixed in advance: higher out-of-fold PR-AUC)

| Variant | PR-AUC (5 seeds) | Recall @0.80 |
|---|---|---|
| Group-capped weights (**chosen**) | 0.905 ± 0.007 | 0.452 ± 0.042 |
| + class-balanced weights | 0.899 ± 0.007 | 0.414 ± 0.053 |

The difference is within the seed noise, so it's not evidence that one is better, only that class balancing didn't help.

### 7.5 `is_alert` policies (out-of-fold, seed 42)

```text
  any_risk OR ml (Phase 2 spec)    recall=0.929 precision=0.307 fpr=0.4927 fpr_on_real_background=0.1799
  severe_risk OR ml                recall=0.475 precision=0.827 fpr=0.0233 fpr_on_real_background=0.0353
  ml only                          recall=0.438 precision=0.863 fpr=0.0163 fpr_on_real_background=0.0192
```

"Severe" = risks that point at known-bad infrastructure or content: suspicious DGA domain, risky domain, malicious JA4/fingerprint, malicious SHA-1 certificate, possible exploit, malware host contacted (`features.SEVERE_MASK`).

---

## 8. ONNX export and live scoring

### 8.1 Export and parity

```text
[onnx] parity: lgbm max|diff|=3.69e-04, iforest max|diff|=3.08e-07, alert decisions differing: 0/9597
[onnx] latency (both models): batch_1_ms=2.004, batch_100_ms=5.463, batch_1000_ms=30.511
```

| File | Size | SHA-256 (prefix) |
|---|---|---|
| `models/c2_detector.onnx` (LightGBM; outputs `label`, `probabilities`) | 672 KB | `6e986f14` |
| `models/anomaly_iforest.onnx` (IsolationForest; outputs `label`, `scores`) | 1.5 MB | `66b3f164` |
| `models/model_meta.json` | — | feature list, calibrations, metrics, library versions, file hashes |

Model version string: **`lgbm+iforest-fv1-6e986f14`**. Exported with onnxmltools 1.16.0 / skl2onnx 1.20.0 (opset 15, `ai.onnx.ml` 3), trained with LightGBM 4.7.0 / scikit-learn 1.9.1, and run with onnxruntime 1.31.0.

### 8.2 `daemon.py` integration

- `--scorer auto|onnx|heuristic` (default `auto`). `OnnxScorer` checks both files' SHA-256 and the feature list against `model_meta.json` before loading. `auto` falls back to `HeuristicScorer` (`heuristic_v1`) on any problem (missing numpy/onnxruntime, missing or tampered file, feature mismatch) and logs the reason. `onnx` fails hard instead.
- Records are validated and timestamped on arrival. **Scoring happens per batch at flush** (default 1,000 rows or 1 s). In the live run, a 1,000-row batch took 36.5–47.1 ms for feature extraction + both models on one onnxruntime thread.
- New columns: `ml_c2_proba` (raw LightGBM probability), `ml_iforest_score` (calibrated IsolationForest) and `ml_model` (scorer version). `−1` means not computed, i.e. the heuristic scorer.
- `--alert-risk-policy any|severe|none`. Default `any` keeps the Phase 2 rule exactly as specified.

### 8.3 Schema migration

- **SQLite:** on open, missing Phase 3 columns are added with `ALTER TABLE … ADD COLUMN … NOT NULL DEFAULT …` (unit test `test_sqlite_migrates_phase2_table` builds a Phase 2 table and checks the final column list).
- **ClickHouse:** `init_clickhouse.sql` creates the columns and also contains idempotent `ALTER TABLE … ADD COLUMN IF NOT EXISTS`. The daemon runs the same `ALTER`s when ClickHouse is reachable. Applied to the running server: 26 → 29 columns; new defaults `-1`, `-1`, `''`.

### 8.4 Recommendation for the alert rule (not applied)

For Phase 4, where alerts turn into blocks, use `--alert-risk-policy severe` or `none`. The evidence:

| Policy | False alarms, real Windows background (CV) | False alarms, holdout |
|---|---|---|
| `any` (current default) | 18.0 % | 18.3 % (91/498) |
| `severe` | 3.5 % | 1.8 % |
| `none` | 1.9 % | 0.6 % |

I left the default unchanged because the rule is your Phase 2 specification.

### 8.5 Unit tests (`engine-ml/tests/test_daemon.py`)

```text
15 tests OK: validation (good record, extra fields, 11 rejection cases, IPv6), heuristic alert rule (4),
alert policies, calibration monotone & maps t→0.80, ONNX scores a real record, missing models → heuristic,
tampered model (1 extra byte) rejected and auto falls back, Phase 2 SQLite table migration
python3 -S (no site-packages): Ran 15 tests, OK (skipped=3) — the 3 ONNX tests skip, everything else passes
```

---

## 9. End-to-end verification

### 9.1 Holdout: 5 never-seen infections through the full live pipeline

`python3 engine-ml/models/evaluate_holdout.py` (or `make holdout`). For each capture it:
1. starts `daemon.py` (`--scorer onnx`, real ZeroMQ via `zmq_sink`, private SQLite);
2. replays the capture with `sensor -r`;
3. sends SIGTERM to flush, reads the stored rows;
4. labels them with the same `label_flow()` used for the training set.

```text
[model] lgbm+iforest-fv1-6e986f14  alert-risk-policy=any
[2023-11-06] 404 TDS + Cobalt Strike: stored 2327/2327 flows, 2227 malicious -> ML detected 76, is_alert 2223; benign 100 -> ML false alerts 1, is_alert 30
[2023-11-20] DarkGate: stored 740/740 flows, 687 malicious -> ML detected 612, is_alert 687; benign 50 -> ML false alerts 0, is_alert 10
[2024-02-21] SocGholish + AsyncRAT: stored 28/28 flows, 11 malicious -> ML detected 5, is_alert 9; benign 12 -> ML false alerts 0, is_alert 4
[2025-08-15] Lumma Stealer + SectopRAT: stored 152/152 flows, 148 malicious -> ML detected 15, is_alert 48; benign 4 -> ML false alerts 0, is_alert 3
[2025-12-29] ClickFix + NetSupport RAT: stored 345/345 flows, 11 malicious -> ML detected 4, is_alert 5; benign 332 -> ML false alerts 2, is_alert 44

[holdout] 3582 labeled flows (3084 malicious) from 5 captures
  ml (ml_anomaly_score >= 0.80)    recall=0.231 precision=0.996 fpr=0.006 captures_detected=5/5
  severe_risk OR ml                recall=0.231 precision=0.988 fpr=0.018 captures_detected=5/5
  any_risk OR ml (Phase 2 rule)    recall=0.964 precision=0.970 fpr=0.183 captures_detected=5/5
  phase2_heuristic >= 0.80         recall=0.000 precision=n/a fpr=0.000 captures_detected=0/5
  malicious endpoints with >= 1 ML alert: 15/23
```

**Per malicious endpoint** (what an IP blocker acts on):

```text
2023-11-06 404 TDS + Cobalt Strike
   170.130.55.150   flows= 2212 alerted=  65 max=0.978 80/HTTP        (Cobalt Strike, IOC)
   170.130.55.117   flows=    8 alerted=   8 max=0.984 443/TLS,8080/TLS (follow-up C2)
   201.148.107.213  flows=    2 alerted=   0 max=0.012 443/TLS        (404 TDS redirect)
   193.3.19.230     flows=    1 alerted=   1 max=0.859 80/HTTP
   65.108.196.140   flows=    1 alerted=   0 max=0.014 443/TLS        (404 TDS redirect)
   170.130.165.37   flows=    1 alerted=   1 max=0.977 80/HTTP        (RClient.dll download)
   170.130.165.107  flows=    1 alerted=   0 max=0.018 1444/Unknown   (remote-access TCP)
   170.130.55.46    flows=    1 alerted=   1 max=0.997 80/HTTP        (initial C2)
2023-11-20 DarkGate
   188.246.224.221  flows=  684 alerted= 609 max=0.971 2351/HTTP,8080/HTTP_Proxy (DarkGate C2)
   45.154.98.21     flows=    3 alerted=   3 max=0.998 80/HTTP        (AutoIt payload)
2024-02-21 SocGholish + AsyncRAT
   5.161.113.150    flows=    6 alerted=   3 max=0.970 25658/TLS      (AsyncRAT C2)
   66.135.17.87     flows=    2 alerted=   0 max=0.071 443/TLS        (SocGholish fake update)
   45.59.170.106    flows=    1 alerted=   1 max=0.998 443/TLS
   49.13.65.235     flows=    1 alerted=   0 max=0.747 80/HTTP
   167.71.107.109   flows=    1 alerted=   1 max=0.951 80/HTTP
2025-08-15 Lumma Stealer + SectopRAT
   5.10.250.239     flows=  136 alerted=   4 max=0.961 443/TLS,9000/HTTP (SectopRAT C2)
   185.95.159.55    flows=   10 alerted=  10 max=0.994 443/TLS        (Lumma C2)
   104.21.24.30     flows=    2 alerted=   1 max=0.941 443/TLS
2025-12-29 ClickFix + NetSupport RAT
   45.93.20.50      flows=    4 alerted=   0 max=0.403 443/TLS
   65.181.111.158   flows=    2 alerted=   0 max=0.037 443/TLS
   80.253.249.145   flows=    2 alerted=   2 max=0.998 80/HTTP        (ClickFix payload)
   185.39.19.96     flows=    2 alerted=   2 max=0.985 443/HTTP       (NetSupport C2)
   104.21.96.46     flows=    1 alerted=   0 max=0.127 443/HTTP
```

Readings:
- **Every C2 server named in the five IOC write-ups got at least one alert**, including SectopRAT, a family absent from training.
- **The misses are mostly delivery and redirect infrastructure over HTTPS** (404 TDS redirectors, the SocGholish fake-update host, ClickFix lure pages), plus one raw-TCP remote-access channel on port 1444.
- **Flow-level recall (23 %) understates detection.** It is dominated by repetitive beacons, e.g. 65 of the 2,212 Cobalt Strike HTTP flows. For blocking, one alert per C2 IP is enough.
- **Of the 3 false alerts,** 2 go to Microsoft (`13.107.213.57`, `20.190.135.18`) and 1 is `10.11.7.120 → 10.11.7.17:5985` (WinRM to the domain controller). The MTA write-up lists that last one under traffic from the infected host, so it is probably lateral movement that my IP-based labels count as benign.

### 9.2 Final live run into the main stores

Fresh SQLite, ClickHouse `network_flows` truncated, `daemon.py --backend both --scorer onnx` running in the background, then the 6 Phase 2 PCAPs + the 5 holdout PCAPs via `sensor -r`:

```text
sensor -r test_dns.pcap: exit=0 exported=1 dropped=0
... (11 PCAPs, all exit=0 dropped=0)
sensor -r 2025-12-29-ClickFix-page-sends-NetSupportRAT.pcap: exit=0 exported=345 dropped=0
daemon exit: 0 ; sensor total exported: 3604
[daemon] scorer: lgbm+iforest-fv1-6e986f14  alert-risk-policy: any
[daemon] transport=zmq_sink endpoint=ipc:///tmp/ndpi_flows.sock backends=sqlite,jsonl,clickhouse ready
[daemon] flushed 13 rows -> sqlite,jsonl,clickhouse (scored in 24.4 ms; alerts=8; total accepted=13 rejected=0)
[daemon] flushed 1000 rows -> sqlite,jsonl,clickhouse (scored in 47.1 ms; alerts=939; total accepted=1013 rejected=0)
[daemon] flushed 1000 rows -> sqlite,jsonl,clickhouse (scored in 36.5 ms; alerts=991; total accepted=2013 rejected=0)
[daemon] flushed 1000 rows -> sqlite,jsonl,clickhouse (scored in 41.3 ms; alerts=954; total accepted=3013 rejected=0)
[daemon] flushed 591 rows -> sqlite,jsonl,clickhouse (scored in 45.9 ms; alerts=184; total accepted=3604 rejected=0)
[daemon] stopped: accepted=3604 rejected=0 clickhouse_failed=0
SQLite rows: 3604  JSONL lines: 3604  ClickHouse rows: 3604
```

`query_dashboard.py` (5 panels) on both stores:

```text
SentinelFlow Phase 2/3 — SQLite engine-ml/data/sentinel_flows.db
flows=3604  is_alert=1: 3076  ndpi_risk_mask>0: 3061  timestamp mismatches: 0  ml_score>=0.80: 722  scorer: lgbm+iforest-fv1-6e986f14
SQLite vs ClickHouse: all 5 panel tables identical (6834 table lines)
```

Panel 5 (top 15 by `ml_anomaly_score`; SQL shown with `--show-sql`):

```text
| flow                              | app_protocol | ja4_client                           | score | c2_proba | iforest | is_alert |
| 10.2.21.101 -> 45.59.170.106:443  | TLS          | t12d190800_d83cc789557e_7af1ed941c26 | 0.998 | 0.993    | 0.239   | 1        |
| 10.11.7.120 -> 45.154.98.21:80    | HTTP         | N/A                                  | 0.998 | 0.993    | 0.534   | 1        |
| 10.12.29.101 -> 80.253.249.145:80 | HTTP         | N/A                                  | 0.998 | 0.992    | 0.613   | 1        |
| 10.11.7.120 -> 170.130.55.46:80   | HTTP         | N/A                                  | 0.997 | 0.989    | 0.454   | 1        |
| 10.8.15.176 -> 185.95.159.55:443  | TLS          | t13d201200_2b729b4bf6f3_e24568c0d440 | 0.994 | 0.979    | 0.739   | 1        |
| ...                                                                                                                      |
| 10.11.7.120 -> 10.11.7.17:5985    | Unknown      | N/A                                  | 0.992 | 0.975    | 0.08    | 1        |
| 10.12.29.101 -> 13.107.213.57:443 | TLS          | N/A                                  | 0.992 | 0.973    | 0.0     | 1        |
```

`is_alert = 3076 / 3604` reflects the default `any` risk policy (3,061 flows carry some nDPI risk); `ml_score ≥ 0.80` is 722.

### 9.3 Grafana

All 5 provisioned panel queries were sent through `POST /api/ds/query`:

```text
[piechart] Protocol Distribution: status=200 rows=29
[timeseries] Traffic Volume (bytes per capture second): status=200 rows=2785
[table] JA4 TLS Fingerprints (with ML score): status=200 rows=16
[table] High-Risk Flows (alerts): status=200 rows=500
[table] ML Detections (ml_anomaly_score >= 0.80): status=200 rows=27
```

![Grafana dashboard after Phase 3](docs/part3_grafana.png)

The screenshot (headless Chromium) shows the known C2 endpoints at the top of the JA4, alert and ML-detection tables.

### 9.4 Zero-dependency path still works

```text
$ python3 -S engine-ml/daemon.py -e ipc://…/z.sock --backend sqlite …     (no numpy/onnxruntime visible)
[daemon] scorer: ONNX unavailable (ModuleNotFoundError: No module named 'numpy'); using heuristic_v1
[daemon] flushed 8 rows -> sqlite,jsonl (scored in 0.1 ms; alerts=2; total accepted=8 rejected=0)
sqlite: 8 | heuristic_v1 | ml_c2_proba min/max -1.0/-1.0
```

---

## 10. Findings and next steps

1. **The alert rule matters more than the model for Phase 4.** "Any nDPI risk" flags 18 % of real host traffic. Use `severe` or `none` before connecting alerts to nftables/XDP (§8.4).
2. **Data diversity is the limiting factor.** 28 malicious captures with a heavy tail (Gozi + Pikabot = 75 % of malicious flows); most families appear once. The next gain comes from more captures per family: more MTA cases, Stratosphere CTU captures, CIC-IDS. The pipeline handles that with `fetch_mta.py` + `make phase3`.
3. **The model detects C2 servers, not every flow** (holdout 15/23 endpoints, 5/5 infections, 23 % flow recall). An endpoint-level aggregation, e.g. "alert on an IP after k scored flows", would suit Phase 4 better than per-flow decisions.
4. **IsolationForest adds noise.** Keep it informational, or replace it with a better-specified anomaly model.
5. **No active timeout in the sensor.** A flow is exported only when it ends or idles 30 s, so a long-lived C2 session is scored only when it closes. An active timeout (e.g. export a snapshot every 60 s) would let Phase 4 react during the session.
6. **Labels are IP-level.** Domains on shared Cloudflare IPs over-label; attacker activity to internal hosts (the WinRM case) under-labels.

---

## 11. What may and may not be said

**May be said (observed in this session):**
- The sensor builds clean under `-Wall -Wextra -Wpedantic`. With ASan + LSan + UBSan it produced 0 reports over 16 PCAPs (1,890 flows), and LSan was shown to be active.
- The sensor exports flows after 30 s idle (synthetic test), captures live on `lo`, flushes all flows on SIGINT, and runs at ~0.40–0.44 Mpps offline on 124,070 packets with 25.8 MB peak RSS.
- The seven sensor fixes and the sink fix in §3 each have before/after evidence, and each fix that changes behavior has a regression test that fails on the old binary.
- 9,659 labeled flows were produced through the production sensor → ZMQ path, with 0 drops and 0 validation rejects, and are stored in SQLite, JSONL and ClickHouse.
- With grouped 5-fold CV over 5 seeds, calibrated LightGBM at 0.80 reaches recall 0.45 ± 0.04, precision 0.91 ± 0.03 and FPR 1.1 % ± 0.4 % (ROC-AUC 0.980).
- ONNX outputs match the native models on all 9,597 labeled flows (0 differing alert decisions).
- On 5 held-out infections replayed through the live pipeline, the model alerted on all 5 captures and 15 of 23 malicious endpoints, with 3 false alerts out of 498 benign flows.
- The daemon scores 1,000-flow batches in 36–47 ms and falls back to the heuristic without numpy/onnxruntime.

**Must not be said (not shown):**
- **Detection rates outside this data.** That it detects "Cobalt Strike" or "C2" in general, or on real enterprise networks. All malicious traffic and most benign background comes from MTA lab captures and the nDPI test corpus, and the holdout is only 5 captures from the same source.
- **Robustness on rare families.** The per-family results in §7.3 show 0 detections for most single-capture families.
- **That the 1 % FPR operating point holds on new traffic.** It was set on out-of-fold predictions; the holdout's 0.6 % is one more sample, not a guarantee.
- **That `pyzmq` ingestion works.** It is still untested; pyzmq isn't installed.
- **Live-capture throughput, or behavior at line rate.** Only offline throughput was measured.
- **Mid-run ClickHouse failover or re-attach.** Still not tested (as in Part 2).
- **That the models are reproducible bit-for-bit.** Two early training runs on identical data gave identical metrics but different `c2_detector.onnx` hashes (`8b51f326` vs `384d2ee4`). Bit-for-bit reproducibility was not shown; only the metric spread in §7.1 was.
- **Anything about Phase 4 (mitigation) or Phase 5 (demo).** Not started.

---

## 12. Reproduce

```bash
cd /home/joe/cv_work/sentinel-flow
make sensor && make test-sensor && make test-engine            # Phase 1 + daemon tests
docker compose up -d                                            # ClickHouse + Grafana (optional)
python3 -m venv --system-site-packages engine-ml/.venv-train
engine-ml/.venv-train/bin/pip install -r engine-ml/requirements-train.txt
make fetch-data          # 17 training + 5 holdout MTA cases (PCAP + IOC text only)
make dataset             # sensor -> ZMQ -> labeled rows (JSONL, SQLite, ClickHouse)
make train               # grouped CV (5 seeds), calibration, ONNX export, parity
make holdout             # 5 unseen captures through the live daemon
python3 engine-ml/daemon.py --backend both &                    # live scoring
LD_LIBRARY_PATH=~/nDPI/src/lib ./sensor-c/build/sensor -r capture.pcap
python3 engine-ml/query_dashboard.py --backend clickhouse        # or open http://127.0.0.1:3000
```

## 13. Files changed in this session

| Area | Files |
|---|---|
| Sensor (modified) | `sensor-c/src/main.c` (alignment, timestamps, link types, drop counting, drain), `ndpi_wrapper.{c,h}` (JA4 gate + validation), `zmq_publisher.{c,h}` (patience, monitor-based linger), `zmq_sink.c` (`RCVHWM=0`), `zmq.h` (monitor declarations), `cJSON.c` (`%.15g`) |
| Sensor (new) | `sensor-c/tests/test_sensor_pcaps.py` |
| Engine (modified) | `engine-ml/daemon.py` (ONNX scorer, fallback, batching, new columns, migrations, alert policy, pyzmq `RCVHWM`), `engine-ml/query_dashboard.py` (panel 5, summary), `engine-ml/sql/init_clickhouse.sql`, `engine-ml/requirements.txt` |
| Engine (new) | `engine-ml/features.py`, `engine-ml/models/{build_dataset,train_pipeline,evaluate_holdout}.py`, `engine-ml/models/{c2_detector,anomaly_iforest}.onnx`, `model_meta.json`, `evaluation.json`, `evaluation_holdout.json`, `evaluation_variant_class_balance.json`, `engine-ml/datasets/{fetch_mta.py,mta_labels.json,mta_holdout_labels.json}`, `engine-ml/requirements-train.txt`, tests in `engine-ml/tests/test_daemon.py` |
| Dashboards | `dashboard/grafana/dashboards/sentinelflow.json` (JA4 panel with ML score, alert columns, panel 5), `docker-compose.yml` (unchanged since Part 2), `docs/part3_grafana.png` |
| Repo | `Makefile` (`test-sensor`, `fetch-data`, `dataset`, `train`, `holdout`, `phase3`), `.gitignore` (downloaded malware PCAPs, training venv), `README.md` (status line) |

Downloaded captures (`engine-ml/datasets/mta*/`) and the training virtualenv are git-ignored. Nothing has been committed.
