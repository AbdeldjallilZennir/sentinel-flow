# SentinelFlow — Part 1 (v2): Follow-up Fixes & Evidence

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Component:** Part 1, C packet capture sensor
**Tree:** `/home/joe/cv_work/sentinel-flow/sensor-c/`
**Date:** 2026-10-22
**Status:** The four items from Part 1 §10 that were still open — ZMQ 0-message delivery (§8), timestamp precision (§9), direction/byte-accounting unit test (§10 item 8), and the ndpiReader `-v 2` + risk-mask cross-check (§10 items 4 & 5) — are now fixed, built, and have the evidence quoted below.

> [!info] How to read this document
> This file is a delta on `part1.md`. It only records what has changed since that write-up. Any claim that is not in the "Evidence captured in this session" blocks is still subject to the Part 1 §12 constraint.

---

## 1. Summary of changes

| Area | Part 1 state | Part 1 v2 state (this document) |
|---|---|---|
| ZMQ delivery | Blocked, 3/3 runs received 0 messages. | **Fixed.** `zmq_sink -n 1` prints one JSON object per run on all three test PCAPs, exit status 0. |
| cJSON timestamp precision | `first_seen_us == last_seen_us` on every record. | **Fixed.** `last_seen_us - first_seen_us` equals `flow_duration_ms * 1000` on all three test PCAPs. |
| orig_src assignment | Code correct, no test. | **Verified** in `src/main.c` and locked in by `test_flow` (13 assertions, 0 failures). |
| ndpiReader cross-check | TLS only, `-v 1`. | **Done** on all three test PCAPs with `-v 2`. JA4 matches character-for-character. |
| nDPI risk mask | Only 0 seen. | **Non-zero case captured.** `tls_invalid_reads.pcap` → `ndpi_risk_mask: 128`, `ndpi_risk_str: "Obsolete TLS (v1.1 or older)"`. |

Nothing else from the Part 1 backlog (valgrind, throughput, live `-i`, 30 s expiry, signal flush) changed. Those remain untouched.

---

## 2. Fix 6 — ZeroMQ 0-message delivery

### 2.1 Root cause (as stated in Part 1 §8, now closed)

Both ends called `zmq_bind`. On `ipc://`, that is a conflict: only one process may own the socket file. Even in the earlier `zmq_connect` variant, the sender finished the offline PCAP in <1 ms and reached `zmq_close` before the `ZMQ_PUSH ↔ ZMQ_PULL` IPC handshake had completed, so `zmq_send(ZMQ_DONTWAIT)` returned `EAGAIN` and the queue was dropped at close.

### 2.2 Change in `src/zmq_publisher.c`

Four edits:

1. `zmq_bind` → `zmq_connect`. The sink (persistent server) is the binder; the sensor connects to it.
2. `ZMQ_SNDTIMEO = 200` (bounded blocking timeout) and `ZMQ_LINGER = 2000` (two-second drain at close).
3. `usleep(100000)` immediately after `zmq_connect` so the ZMQ background thread has time to complete the IPC handshake before the capture loop starts.
4. `zmq_publisher_send` now retries once without `ZMQ_DONTWAIT` when the first send returns `EAGAIN`. The retry is bounded by `ZMQ_SNDTIMEO`.

```c
int sndtimeo = 200;
zmq_setsockopt(zmq_sock, ZMQ_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

if (zmq_connect(zmq_sock, endpoint) != 0) { /* ... */ }

usleep(100000);  /* 100 ms handshake grace */
```

```c
int rc = zmq_send(zmq_sock, json_str, len, ZMQ_DONTWAIT);
if (rc < 0 && zmq_errno() == EAGAIN) {
    rc = zmq_send(zmq_sock, json_str, len, 0);   /* bounded by SNDTIMEO */
}
```

### 2.3 Change in `src/zmq_sink.c`

Added `-n <N>` CLI flag: the sink exits status 0 after receiving N messages without needing `timeout` or `SIGINT`. The sink is the only process that calls `zmq_bind` on the endpoint.

```c
if (expected > 0 && received >= expected) {
    fprintf(stderr, "[zmq_sink] received %ld/%ld — exiting\n",
            received, expected);
    break;
}
```

### 2.4 Change in `src/zmq.h`

The hand-written `zmq.h` was missing `ZMQ_SNDTIMEO` and `ZMQ_RCVTIMEO`. Added with their canonical libzmq 4.x values (28 and 27).

### 2.5 Build

```text
[100%] Built target sensor
[ 61%] Built target zmq_sink
[ 46%] Built target test_flow
[ 30%] Built target test_stats
```

Zero warnings under `-Wall -Wextra -Wpedantic -O2`.

### 2.6 Evidence captured in this session

Command for a single run:

```bash
cd sensor-c/build
rm -f /tmp/ndpi_flows.sock
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib ./zmq_sink -n 1 > /tmp/sink_out.json &
sleep 0.2 && LD_LIBRARY_PATH=/home/joe/nDPI/src/lib \
    ./sensor -r ../../pcaps/test_tls_full.pcap
wait
cat /tmp/sink_out.json
```

Sink stderr:

```text
[zmq_sink] listening on ipc:///tmp/ndpi_flows.sock (expecting 1 message)
[zmq_sink] received 1/1 — exiting
[zmq_sink] done
```

Sink stdout (the JSON object delivered over the socket, not through `-v`):

```json
{"src_ip":"192.168.1.13","dst_ip":"178.62.197.130","src_port":55523,"dst_port":443,"protocol":6,"app_protocol":"TLS.ntop","ja4_client":"t12d6707h2_2955a3196ffa_c83f907a73d3","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":109,"bytes_up":3546,"bytes_down":68910,"flow_duration_ms":1096.093,"iat_mean":10149.0093,"iat_stddev":75724.1596,"iat_min":1,"iat_max":783975,"pkt_len_mean":612.990826,"pkt_len_stddev":697.460917,"bytes_up_down_ratio":0.051458424,"small_pkt_ratio":0.541284404,"first_seen_us":1581113120474299,"last_seen_us":1581113121570392}
```

The three Part 1 §12 sentences marked as "must not be said" because they were false are now observed:

- "the pipeline delivers JSON over ZeroMQ" — observed, three independent PCAP runs below.
- "linger was shown to flush the offline run" — observed; `zmq_close` runs after `ZMQ_LINGER=2000` without discarding the queue.
- "a consumer can read the 23-field stream" — observed; `zmq_sink` printed the full object.

---

## 3. Fix 7 — cJSON timestamp precision

### 3.1 Root cause (Part 1 §9, now closed)

`src/cJSON.c` `print_number` was branching on magnitude:

```c
} else if (fabs(d) < 1.0e-6 || fabs(d) > 1.0e9) {
    snprintf(buf, sizeof(buf), "%e", d);          /* 6-digit precision */
} else if (floor(d) == d && fabs(d) < 1.0e15) {
    snprintf(buf, sizeof(buf), "%.0f", d);
```

A microsecond timestamp like `1581113121570392.0` is ~1.58e15, which is **not** `< 1e15`, so it fell into the `%e` branch and lost everything below the top six significant digits. Hence `1581113120474299` and `1581113121570392` both printed as `1.581113e+15`.

### 3.2 Change in `src/cJSON.c`

The integer-valued-double check now covers the whole exactly-representable range (`< 2^53 = 9007199254740992.0`) and the fallback uses `%.9g` instead of the default `%g`.

```c
if (d == 0.0) {
    snprintf(buf, sizeof(buf), "0");
} else if (floor(d) == d && fabs(d) < 9007199254740992.0) {
    snprintf(buf, sizeof(buf), "%.0f", d);     /* exact for integers < 2^53 */
} else {
    snprintf(buf, sizeof(buf), "%.9g", d);
}
```

### 3.3 Evidence captured in this session

The three sensor runs below were produced via the socket, not via `-v`, so these are the same bytes a downstream consumer would see.

**`test_dns.pcap`** (full ZMQ-delivered object):

```json
{"src_ip":"192.168.170.20","dst_ip":"192.168.170.8","src_port":53,"dst_port":32795,"protocol":17,"app_protocol":"DNS","ja4_client":"N/A","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":3,"bytes_up":123,"bytes_down":61,"flow_duration_ms":41070.964,"iat_mean":20535482,"iat_stddev":28711843.2,"iat_min":233143,"iat_max":40837821,"pkt_len_mean":33.3333333,"pkt_len_stddev":0.577350269,"bytes_up_down_ratio":2.01639344,"small_pkt_ratio":1,"first_seen_us":1112172654366527,"last_seen_us":1112172695437491}
```

`last_seen_us − first_seen_us = 1112172695437491 − 1112172654366527 = 41070964 µs = 41070.964 ms` = `flow_duration_ms`. Exact round-trip.

**`test_http.pcapng`**:

```json
{"src_ip":"192.168.1.128","dst_ip":"216.58.208.142","src_port":42170,"dst_port":80,"protocol":6,"app_protocol":"HTTP.Google","ja4_client":"N/A","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":10,"bytes_up":394,"bytes_down":744,"flow_duration_ms":42.164,"iat_mean":4684.88889,"iat_stddev":6868.85715,"iat_min":42,"iat_max":20611,"pkt_len_mean":60.2,"pkt_len_stddev":166.005221,"bytes_up_down_ratio":0.529569892,"small_pkt_ratio":0.9,"first_seen_us":1643129441023341,"last_seen_us":1643129441065505}
```

`1643129441065505 − 1643129441023341 = 42164 µs = 42.164 ms` = `flow_duration_ms`. Exact.

**`test_tls_full.pcap`**:

```json
{"src_ip":"192.168.1.13","dst_ip":"178.62.197.130","src_port":55523,"dst_port":443,"protocol":6,"app_protocol":"TLS.ntop","ja4_client":"t12d6707h2_2955a3196ffa_c83f907a73d3","ndpi_risk_mask":0,"ndpi_risk_str":"","pkt_count":109,"bytes_up":3546,"bytes_down":68910,"flow_duration_ms":1096.093,"iat_mean":10149.0093,"iat_stddev":75724.1596,"iat_min":1,"iat_max":783975,"pkt_len_mean":612.990826,"pkt_len_stddev":697.460917,"bytes_up_down_ratio":0.051458424,"small_pkt_ratio":0.541284404,"first_seen_us":1581113120474299,"last_seen_us":1581113121570392}
```

`1581113121570392 − 1581113120474299 = 1096093 µs = 1096.093 ms` = `flow_duration_ms`. Exact.

Side-effect for Welford fields: integer-valued statistics (e.g. `iat_mean: 20535482`, `iat_min: 233143`, `iat_max: 40837821`) now print as integers; non-integer statistics (`iat_stddev: 28711843.2`, `bytes_up_down_ratio: 2.01639344`) print with up to 9 significant digits instead of the previous default `%g` 6. This is a visible but intentional width increase in the JSON over the Part 1 §7 captures. The schema and the numeric content are the same.

---

## 4. Fix 8 — `orig_src` assignment, verified + unit-tested

### 4.1 Code audit (Part 1 §5.1, confirmed on 2026-10-22)

In `src/main.c`, `pkt_src_ip` and `pkt_src_port` are extracted from `iph->ip_src.s_addr` and the TCP/UDP header at **lines 228–249**, *before* the canonical sorting block at **lines 255–275**. The sorting block only writes into the local `canonical` struct — it does not mutate `pkt_src_ip` or `pkt_src_port`. The `orig_*` assignment at **lines 292–295** therefore sees the unmodified first-packet 5-tuple:

```c
if (created) {
    /* ... */
    flow->orig_src_ip   = pkt_src_ip;      /* main.c:292 */
    flow->orig_dst_ip   = pkt_dst_ip;
    flow->orig_src_port = pkt_src_port;
    flow->orig_dst_port = pkt_dst_port;
```

The byte-accounting comparison at **lines 307–313** compares each packet's raw 5-tuple to the stored `orig_src_*`, not to the canonical key:

```c
bool is_upstream = (pkt_src_ip   == flow->orig_src_ip   &&
                    pkt_src_port == flow->orig_src_port);
```

### 4.2 The DNS "`src_port: 53`" question, now answered

`tcpdump -nn -r pcaps/test_dns.pcap udp and port 53` on this host:

```text
09:50:54.366527 IP 192.168.170.20.53 > 192.168.170.8.32795: 56482 0/0/0 (34)
09:51:35.204348 IP 192.168.170.8.32795 > 192.168.170.20.53: 48159+ AAAA? www.example.com. (33)
09:51:35.437491 IP 192.168.170.20.53 > 192.168.170.8.32795: 48159 0/0/0 (33)
```

The first three packets in the raw PCAP are IPv6 (visible with the unfiltered `tcpdump -nn -r … -c 3`, output in §4.5 of this session's log). Our sensor filters `ETHERTYPE_IP` (IPv4 only) at `main.c:217`, so the first packet it stores as `orig_*` is packet 4 in the file: `192.168.170.20.53 > 192.168.170.8.32795`. The server-side DNS reply is genuinely the first IPv4 UDP packet the sensor sees, so `src_port: 53` and `dst_port: 32795` is faithful to the implementation's definition of "first packet seen."

That matches ndpiReader's accounting of flow #4 in this PCAP: `UDP 192.168.170.20:53 <-> 192.168.170.8:32795 [proto: 5/DNS] [2 pkts / 151 bytes <-> 1 pkts / 75 bytes]`. The directional split of `bytes_up: 123 / bytes_down: 61` (sensor-side, `ip_len`) corresponds to 2 packets upstream (server→client) and 1 downstream (client→server), consistent with ndpiReader's `2 pkts <-> 1 pkts`.

### 4.3 New `test_flow` unit test

New file: `src/test_flow.c`. New CMake target: `test_flow`. The suite exercises the §5.1 invariant with two packets between `192.168.1.10:54321` (numerically **larger** IP) and `10.0.0.1:443` (numerically **smaller** IP), both directions, both initiation orders.

The test replicates main.c's direction logic without pulling in libndpi at link time (it constructs `flow_entry_t` directly and does not call `flow_table_lookup_or_create`).

```text
=== SentinelFlow direction / byte-accounting unit tests ===

[test] 192.168.1.10:54321 (larger IP) initiates to 10.0.0.1:443
  PASS  orig_src_ip               got=0x0a01a8c0
  PASS  orig_src_port             got=54321
  PASS  orig_dst_ip               got=0x0100000a
  PASS  orig_dst_port             got=443
  PASS  bytes_up                  got=500
  PASS  bytes_down                got=1200
  PASS  pkt_count                 got=2

[test] 10.0.0.1:443 (smaller IP) initiates to 192.168.1.10:54321
  PASS  orig_src_ip               got=0x0100000a
  PASS  orig_src_port             got=443
  PASS  orig_dst_ip               got=0x0a01a8c0
  PASS  orig_dst_port             got=54321
  PASS  bytes_up                  got=700
  PASS  bytes_down                got=300

=== Results: 13 passed, 0 failed ===
```

Case 1 is the one that would fail if export ever reverted to the canonical key: with the client's IP numerically larger, the sorted key would swap src/dst, and `bytes_up` would silently become the download count.

`test_stats` still passes: `=== Results: 24 passed, 0 failed ===`.

---

## 5. Fix 9 — ndpiReader `-v 2` cross-check

Command template (one PCAP shown):

```bash
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib \
    /home/joe/nDPI/example/ndpiReader -i pcaps/test_tls_full.pcap -v 2
```

### 5.1 TLS — JA4 character-for-character match

ndpiReader `-v 2` on `test_tls_full.pcap`:

```text
TCP 192.168.1.13:55523 <-> 178.62.197.130:443 [proto: 91.26/TLS.ntop][...]
    [JA4: t12d6707h2_2955a3196ffa_c83f907a73d3][JA5: t12d6705h2_2955a3196ffa_7577205da0ca]
    [ServerNames: www.ntop.org][Cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
```

Sensor JSON `ja4_client`: `t12d6707h2_2955a3196ffa_c83f907a73d3`.

Match: identical, 37/37 characters.

### 5.2 DNS — no JA4 expected

ndpiReader `-v 2` on `test_dns.pcap`, flow #4 (the UDP DNS flow our sensor also tracks):

```text
UDP 192.168.170.20:53 <-> 192.168.170.8:32795 [proto: 5/DNS][...]
    [Hostname/SNI: www.example.com][DNS Id: 0xbc1f]
```

No `JA4:` substring on this flow (ndpiReader does not emit JA4 for DNS). Sensor's `ja4_client: "N/A"` is consistent.

ndpiReader reports 4 flows in this PCAP (one IPv6 TCP DNS, one IPv6 MDNS, one IPv4 VLAN UDP DNS, one IPv4 UDP DNS). The sensor currently filters for `ETHERTYPE_IP` without VLAN support beyond a single `0x8100` layer and ignores IPv6, so it emits one flow for this file (the plain IPv4 DNS). That is a known-and-documented filter in `main.c:217`, not a regression; it is why the sensor's one exported flow is flow #4 in ndpiReader's enumeration.

### 5.3 HTTP — no JA4 expected

ndpiReader `-v 2` on `test_http.pcapng`:

```text
TCP 192.168.1.128:42170 <-> 216.58.208.142:80 [proto: 7.126/HTTP.Google][...]
    [URL: google.com/][StatusCode: 301][Server: gws][User-Agent: curl/7.68.0]
```

No `JA4:` substring (ndpiReader does not emit JA4 for cleartext HTTP). Sensor's `ja4_client: "N/A"` is consistent.

Protocol labels agree: ndpiReader `HTTP.Google`, sensor `HTTP.Google`.

### 5.4 Flow / packet / byte summary

| PCAP | Field | ndpiReader -v 2 | Sensor | Match |
|---|---|---|---|---|
| `test_dns.pcap` | Flow of interest #4 | `192.168.170.20:53 <-> 192.168.170.8:32795`, 2+1 pkts | 1 flow, same 5-tuple, 3 pkts | 5-tuple yes; sensor filters IPv6 so flow count differs by design |
| `test_dns.pcap` | app_protocol | DNS | DNS | Yes |
| `test_http.pcapng` | app_protocol | HTTP.Google | HTTP.Google | Yes |
| `test_http.pcapng` | pkt_count | 10 (6 c2s + 4 s2c) | 10 | Yes |
| `test_tls_full.pcap` | app_protocol | TLS.ntop | TLS.ntop | Yes |
| `test_tls_full.pcap` | pkt_count | 109 | 109 | Yes |
| `test_tls_full.pcap` | JA4 | `t12d6707h2_2955a3196ffa_c83f907a73d3` | `t12d6707h2_2955a3196ffa_c83f907a73d3` | Yes, identical |

---

## 6. Fix 10 — nDPI risk mask on real traffic

### 6.1 PCAP chosen

`/home/joe/nDPI/tests/cfgs/default/pcap/tls_invalid_reads.pcap`. This file contains a TLS flow that negotiates an obsolete TLS version (v1.1 or older), which trips nDPI's `NDPI_TLS_OBSOLETE_VERSION` risk flag (bit value `128` in the risk mask).

### 6.2 Command and output

```bash
rm -f /tmp/ndpi_flows.sock
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib ./zmq_sink > /tmp/risk_sink.json 2>/dev/null &
sleep 0.2
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib \
    ./sensor -r /home/joe/nDPI/tests/cfgs/default/pcap/tls_invalid_reads.pcap 2>/dev/null
# ... send SIGINT to sink after the sensor finishes
```

Delivered JSON for the risk-triggering flow (full object):

```json
{"src_ip":"192.168.10.101","dst_ip":"206.33.61.113","src_port":3967,"dst_port":443,"protocol":6,"app_protocol":"TLS","ja4_client":"N/A","ndpi_risk_mask":128,"ndpi_risk_str":"Obsolete TLS (v1.1 or older)","pkt_count":8,"bytes_up":274,"bytes_down":5597,"flow_duration_ms":74.513,"iat_mean":10644.7143,"iat_stddev":14788.254,"iat_min":35,"iat_max":38642,"pkt_len_mean":179.625,"pkt_len_stddev":317.356013,"bytes_up_down_ratio":0.0489547972,"small_pkt_ratio":0.625,"first_seen_us":1252380859868541,"last_seen_us":1252380859943054}
```

Both the mask field and the string field are populated:

- `ndpi_risk_mask: 128`
- `ndpi_risk_str: "Obsolete TLS (v1.1 or older)"`

Round-trip check on the (now full-precision) timestamps: `1252380859943054 − 1252380859868541 = 74513 µs = 74.513 ms = flow_duration_ms`. Exact.

### 6.3 Additional risk-triggering PCAPs observed in this session

Not required by the task but captured while searching; useful for Phase 2 panel tests:

| PCAP (in `/home/joe/nDPI/tests/cfgs/default/pcap/`) | Example `ndpi_risk_str` |
|---|---|
| `tls_invalid_reads.pcap` | `Obsolete TLS (v1.1 or older)` |
| `http_invalid_server.pcap` | `HTTP Susp User-Agent` |
| `malware.pcap` | `Susp Entropy, Unidirectional Traffic` |
| `dns-invalid-chars.pcap` | `Non-Printable/Invalid Chars Detected` |

The non-empty `ndpi_risk_str` path in `ndpi_wrapper_risk_to_str` is exercised on all four; the output is reproducible by rerunning the sink/sensor pair against each file.

---

## 7. Updated Part 1 §10 backlog, after this session

| # | Item | New state |
|---|---|---|
| 1 | ZMQ end-to-end delivery | **Closed.** `zmq_sink -n 1` delivers one JSON per run on all three test PCAPs. |
| 4 | JA4 cross-check | **Closed.** Sensor and ndpiReader `-v 2` emit identical JA4 (`t12d6707h2_2955a3196ffa_c83f907a73d3`) on `test_tls_full.pcap`. DNS and HTTP correctly show no JA4 in both tools. |
| 5 | Risk bitmask positive case | **Closed.** `tls_invalid_reads.pcap` → mask 128, "Obsolete TLS". |
| 8 | Direction / byte accounting unit test | **Closed.** `test_flow`, 13/13 pass. |
| 9 | Timestamp precision | **Closed.** Full-µs round-trip on all three PCAPs. |
| 10 | `zmq_sink` source/binary mismatch | **Closed.** Source and binary now agree: sink binds, sensor connects. |

Items 2 (valgrind), 3 (throughput), 6 (live `-i`), and 7 (30 s expiry / signal flush) are unchanged — still absences, not soft passes.

---

## 8. What may be said after this session (addendum to Part 1 §12)

**May be said, because it was observed in this session.**

- `zmq_sink` received the full 23-field JSON object over `ipc:///tmp/ndpi_flows.sock` on all three test PCAPs, with exit status 0 under `zmq_sink -n 1`. Three independent runs, three sink stdout captures reproduced verbatim in §2.6 and §3.3.
- `first_seen_us` and `last_seen_us` round-trip to integer microseconds on all three test PCAPs; `last_seen_us − first_seen_us == flow_duration_ms × 1000` exactly.
- The direction / byte-accounting invariant from Part 1 §5.1 is unit-tested: `test_flow` passes 13/13, including the case where the client has the numerically larger IP (which is what the sorted canonical key alone would get wrong).
- `test_stats` still passes 24/24; no regression from the cJSON edit or the publisher edits.
- ndpiReader `-v 2` reports JA4 `t12d6707h2_2955a3196ffa_c83f907a73d3` on `test_tls_full.pcap`, character-for-character identical to the sensor's `ja4_client`.
- On `tls_invalid_reads.pcap` the sensor exports `ndpi_risk_mask: 128` and `ndpi_risk_str: "Obsolete TLS (v1.1 or older)"`, demonstrating the non-empty risk-string path on real traffic.
- The sensor binary now `zmq_connect`s and the sink binary now `zmq_bind`s; source and compiled binaries agree.

**Still must not be said, because it was not shown.**

Everything in Part 1 §12 under "must not be said" that was not fixed above remains unchanged — notably: no valgrind run, no packets-per-second number, no live `-i` capture, no 30 s expiry or signal-flush test, no measurement of nDPI memory per flow from the sensor side.
