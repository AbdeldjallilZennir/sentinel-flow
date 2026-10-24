# SentinelFlow — Part 2: Ingestion & Analytics Pipeline (`engine-ml/`)

**Project:** SentinelFlow — zero-decrypt encrypted traffic analyzer
**Component:** Phase 2, flow ingestion, storage and query
**Tree:** `/home/joe/cv_work/sentinel-flow/`
**Date:** 2026-10-23
**Status:** Built and verified end to end on this host. All 12 flows that `sensor` exported from the 6 test PCAPs arrived over `ipc:///tmp/ndpi_flows.sock`. All 12 were validated, enriched and stored in SQLite and JSONL (run A, ClickHouse down) and also in ClickHouse (run B). The four query panels give identical results from SQLite and ClickHouse, and the Grafana dashboard renders them from ClickHouse.

> [!info] Claim discipline
> Same rule as `part1.md` §12: a statement is only made here if the output that supports it is quoted in this document and was captured in this session. §10 lists what was **not** shown.

---

## 1. Summary

| Requirement | Result |
|---|---|
| Stdlib-only ZMQ ingestion | **Done.** `pyzmq` is absent on this host, so the daemon spawned `sensor-c/build/zmq_sink` and read its stdout. 12/12 flows received in both runs. |
| Validate 23 fields + 3 enrichment columns | **Done.** 9/9 unit tests pass. 0 differences across 552 field comparisons between the sensor's `-v` output and what was stored (§6.3). |
| SQLite (WAL) + JSONL backend | **Done.** `PRAGMA journal_mode` → `wal`. 12 rows / 12 lines. |
| ClickHouse HTTP backend (`urllib`) | **Done.** 12 rows inserted via `INSERT … FORMAT JSONEachRow` into ClickHouse 24.8.14.39. |
| `init_clickhouse.sql` with exact types | **Done.** Types and `ORDER BY` confirmed from `system.columns` / `system.tables` (§5.2). |
| `docker-compose.yml` + Grafana, 4 panels | **Done.** Datasource health `OK`. All 4 panel queries return HTTP 200 through Grafana's `/api/ds/query`. Screenshot in `docs/part2_grafana.png`. |
| `query_dashboard.py` (CLI + `--serve`) | **Done.** 4 tables on SQLite and on ClickHouse, byte-identical table rows (§7.3). `--serve` returns HTTP 200 for `/` and `/api/panels.json`. |
| 6-PCAP end-to-end run | **Done**, twice (run A without ClickHouse, run B with it). |

---

## 2. Host environment check (before writing code)

```text
$ python3 --version                      → Python 3.14.7
$ python3 -c "import zmq"                → ModuleNotFoundError: No module named 'zmq'
$ sqlite3 --version                      → 3.46.1 2024-08-13
$ clickhouse-client --version            → command not found
$ curl http://localhost:8123/ping        → exit 7 (connection refused)
$ docker info                            → Server Version: 27.5.1+dfsg4, Running: 1
$ docker images | grep -E 'clickhouse|grafana'
grafana/grafana   latest   da9910ab9d4c   (grafana --version → 13.0.1)
                                         (no ClickHouse image)
```

Docker Hub turned out to be reachable in this session: `docker pull clickhouse/clickhouse-server:24.8` finished with `Status: Downloaded newer image`. So both the offline path (run A) and the full stack (run B) could be tested.

---

## 3. What was built

| File | Purpose |
|---|---|
| `engine-ml/daemon.py` | Ingestion daemon: transport selection, validation, enrichment, batched writes to SQLite + JSONL + ClickHouse. Stdlib only. |
| `engine-ml/query_dashboard.py` | Four panel queries against SQLite (default) or ClickHouse; text tables, `--json`, or `--serve` (HTML + JSON on 127.0.0.1:8080). |
| `engine-ml/sql/init_clickhouse.sql` | `sentinel` database + `sentinel.network_flows` MergeTree table. |
| `engine-ml/tests/test_daemon.py` | 9 `unittest` cases for validation, enrichment and the alert rule. |
| `docker-compose.yml` | ClickHouse 24.8 + Grafana 13.0.1, both bound to 127.0.0.1. |
| `dashboard/grafana/provisioning/…` | ClickHouse datasource + dashboard provider. |
| `dashboard/grafana/dashboards/sentinelflow.json` | The 4-panel dashboard. |
| `docs/part2_grafana.png` | Headless-Chromium screenshot of the dashboard, taken in this session. |
| `Makefile` | New targets: `daemon`, `dashboard`, `dashboard-web`, `test-engine`, `stack-up`, `stack-down`. |
| `engine-ml/requirements.txt` | States that nothing is required; `pyzmq` is listed as optional. |
| `.gitignore` | Ignores `sentinel-flow/engine-ml/data/`. |

### 3.1 Transport selection (`daemon.py`)

1. `import zmq` succeeds → bind a `PULL` socket directly.
2. Otherwise → `subprocess.Popen([zmq_sink, endpoint], stdout=PIPE, text=True, bufsize=1)` and read one JSON object per line. A reader thread feeds a `queue.Queue`, so the main loop can flush partial batches on a timer (`--flush-interval`, default 1 s).
3. `--from-jsonl FILE|-` → replay records from a file (for backfill and tests).

**Deviation from the brief:** the brief has `zmq_sink -e <endpoint>`. The compiled `zmq_sink` (`src/zmq_sink.c`) only accepts `[-n N] [endpoint]` and has no `-e` option. The daemon therefore passes the endpoint as a positional argument and leaves the Part 1-verified C code unchanged. The daemon's own flag is `-e/--endpoint`.

Before binding, the daemon removes a stale socket file at the IPC path (only if it is a socket). On SIGINT/SIGTERM it drains the queue, flushes, and terminates `zmq_sink`.

### 3.2 Validation

Each of the 23 fields must be present with the right type. The checks:

| Kind | Fields | Check |
|---|---|---|
| IP | `src_ip`, `dst_ip` | `ipaddress.ip_address()` parses (IPv4 or IPv6) |
| string | `app_protocol`, `ja4_client`, `ndpi_risk_str` | `str` |
| UInt8/16/64 | `protocol`; ports; `ndpi_risk_mask`, `pkt_count`, `bytes_*`, `*_seen_us` | integer (bool rejected, integral floats accepted), in range |
| Float64 | the 10 timing/shape statistics | finite number |
| cross-field | — | `last_seen_us >= first_seen_us`, `pkt_count > 0` |

Extra fields are dropped. Rejected records go to `data/rejected.jsonl` with the error message and the raw line.

### 3.3 Enrichment

| Column | Type | Value |
|---|---|---|
| `ingested_at_us` | UInt64 | `time.time_ns() // 1000` when the record is accepted |
| `ml_anomaly_score` | Float64 | Phase 2 baseline heuristic (below), rounded to 4 d.p. |
| `is_alert` | UInt8 | `1` if `ndpi_risk_mask > 0` **or** `ml_anomaly_score >= 0.80`, else `0` |

The baseline score is a noisy-OR, `1 − Π(1 − wᵢ)`, over these behavioral signals. **It is a placeholder heuristic, not a trained model.** Phase 3 replaces `heuristic_score()` with ONNX inference; the column and the alert rule stay the same.

| Signal | Condition | wᵢ |
|---|---|---|
| `ndpi_risk` | `ndpi_risk_mask > 0` | 0.40 |
| `unknown_protocol` | master protocol is `Unknown` | 0.40 |
| `unidirectional` | `pkt_count >= 3` and one direction has 0 bytes | 0.35 |
| `periodic_iat` | `pkt_count >= 6` and `iat_stddev / iat_mean < 0.20` | 0.50 |
| `upload_heavy` | `bytes_up_down_ratio > 10` | 0.25 |
| `nonstandard_port` | TLS/HTTP with neither port in the usual set | 0.20 |

**Change made during this session:** the first weights (0.30 / 0.30 / 0.35) could never reach 0.80 without a risk mask, so the `score >= 0.80` half of the alert rule could never fire. The unit test `test_score_threshold_alert_without_risk` caught this (`AssertionError: 0.6815 not greater than or equal to 0.8`). With the weights above, the beacon-like combination (unknown protocol + unidirectional + periodic) scores 0.805 and alerts. Two signals alone (best case 0.70) do not.

### 3.4 Storage

* **SQLite** `engine-ml/data/sentinel_flows.db`: `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`. All 26 columns are `NOT NULL`. Indexes on `(first_seen_us, app_protocol, src_ip)` (the ClickHouse sort key) and on `is_alert`. Each batch is one transaction.
* **JSONL** `engine-ml/data/flows.jsonl`: one enriched record per line, `fsync`'d after each batch.
* **ClickHouse** over `urllib.request`: `POST {url}/?query=INSERT INTO sentinel.network_flows FORMAT JSONEachRow`. Credentials go in the `X-ClickHouse-User` / `X-ClickHouse-Key` headers.
* `--backend auto` (the default): SQLite + JSONL always; ClickHouse only if `/ping` and `EXISTS TABLE` succeed at startup. If not, ClickHouse is re-probed every 30 s. If a ClickHouse insert fails, ClickHouse is detached and the batch stays in SQLite/JSONL. `--backend both` exits with status 2 if ClickHouse is unreachable at startup.

---

## 4. Unit tests

```bash
python3 engine-ml/tests/test_daemon.py      # or: make test-engine
```

```text
test_clean_tls_not_alert (__main__.Enrich.test_clean_tls_not_alert) ... ok
test_risk_mask_forces_alert (__main__.Enrich.test_risk_mask_forces_alert) ... ok
test_score_bounded (__main__.Enrich.test_score_bounded) ... ok
test_score_threshold_alert_without_risk (__main__.Enrich.test_score_threshold_alert_without_risk) ... ok
test_two_signals_below_threshold (__main__.Enrich.test_two_signals_below_threshold) ... ok
test_extra_fields_dropped (__main__.Validate.test_extra_fields_dropped) ... ok
test_good_record (__main__.Validate.test_good_record) ... ok
test_ipv6_accepted (__main__.Validate.test_ipv6_accepted) ... ok
test_rejections (__main__.Validate.test_rejections) ... ok
----------------------------------------------------------------------
Ran 9 tests in 0.001s

OK
```

`test_rejections` has 11 sub-cases, each of which must raise `ValidationError`: missing field, invalid IP, port 70000, negative u64, `true` as protocol, `"109"` as a string number, fractional timestamp, NaN, `last_seen_us < first_seen_us`, `pkt_count = 0`, non-object JSON.

---

## 5. ClickHouse schema and stack

### 5.1 `engine-ml/sql/init_clickhouse.sql` (excerpt)

```sql
CREATE DATABASE IF NOT EXISTS sentinel;

CREATE TABLE IF NOT EXISTS sentinel.network_flows
(
    src_ip String, dst_ip String, src_port UInt16, dst_port UInt16, protocol UInt8,
    app_protocol LowCardinality(String), ja4_client String,
    ndpi_risk_mask UInt64, ndpi_risk_str String,
    pkt_count UInt64, bytes_up UInt64, bytes_down UInt64,
    flow_duration_ms Float64, iat_mean Float64, iat_stddev Float64,
    iat_min Float64, iat_max Float64, pkt_len_mean Float64, pkt_len_stddev Float64,
    bytes_up_down_ratio Float64, small_pkt_ratio Float64,
    first_seen_us UInt64, last_seen_us UInt64,
    ingested_at_us UInt64, ml_anomaly_score Float64, is_alert UInt8
)
ENGINE = MergeTree()
ORDER BY (first_seen_us, app_protocol, src_ip);
```

### 5.2 Evidence: schema as loaded by the server

`docker compose up -d` mounts the file into `/docker-entrypoint-initdb.d/`. After the container reported `healthy`:

```text
$ curl -s http://localhost:8123/?query=SELECT+version()      → 24.8.14.39
$ ... SELECT name, type FROM system.columns WHERE database='sentinel' AND table='network_flows' AND name IN (...)
ndpi_risk_mask    UInt64
bytes_up          UInt64
bytes_down        UInt64
first_seen_us     UInt64
last_seen_us      UInt64
ingested_at_us    UInt64
ml_anomaly_score  Float64
is_alert          UInt8
$ ... SELECT count() FROM system.columns WHERE database='sentinel' AND table='network_flows'
26
$ ... SELECT engine, sorting_key, total_rows FROM system.tables WHERE database='sentinel'
MergeTree    first_seen_us, app_protocol, src_ip    12
```

### 5.3 `docker-compose.yml` notes

* `clickhouse/clickhouse-server:24.8`, user `sentinel` / password `sentinel`, port `127.0.0.1:8123`, named volume, `wget /ping` healthcheck.
* `grafana/grafana:13.0.1`, `depends_on: clickhouse (service_healthy)`, port `127.0.0.1:3000`, admin password `sentinel`.
* `GF_PLUGINS_PREINSTALL=grafana-clickhouse-datasource`. The plugin is **downloaded on first start**, so first start needs internet access (cached in the `grafana-data` volume afterwards). Observed in this session: `Downloaded and extracted grafana-clickhouse-datasource v4.23.2 zip successfully` … `Plugin successfully installed`. In the same log, Grafana's default app plugins failed with `dial tcp [2a00:…]:443: connect: network is unreachable` (IPv6). That doesn't affect this dashboard.
* Anonymous **Viewer** access is enabled (`GF_AUTH_ANONYMOUS_ENABLED`) so the dashboard opens without a login. I added this so the headless screenshot could load the dashboard. Checked: an anonymous `GET` of the dashboard returns `200`, and an anonymous `PUT` on the datasource returns `403`. Both ports bind to 127.0.0.1 only. The credentials are dev defaults; change them before exposing the stack.
* The local Grafana image was `grafana/grafana:latest`, and `grafana --version` inside it printed `13.0.1`. I tagged it locally as `13.0.1` instead of pulling. On a fresh host, compose will pull `13.0.1` from Docker Hub.

---

## 6. End-to-end runs

### 6.1 Harness

Both runs use the same script; only the daemon arguments differ:

```bash
cd /home/joe/cv_work/sentinel-flow
export LD_LIBRARY_PATH=/home/joe/nDPI/src/lib
rm -rf engine-ml/data                                    # fresh store
python3 engine-ml/daemon.py [ARGS] 2> daemon.stderr &    # background
DPID=$!
# wait until daemon.stderr contains " ready"
for p in pcaps/test_dns.pcap pcaps/test_http.pcapng pcaps/test_tls_full.pcap \
         /home/joe/nDPI/tests/cfgs/default/pcap/tls_invalid_reads.pcap \
         /home/joe/nDPI/tests/cfgs/default/pcap/http_invalid_server.pcap \
         /home/joe/nDPI/tests/cfgs/default/pcap/malware.pcap; do
    ./sensor-c/build/sensor -r "$p"
done
sleep 2                                                  # > flush interval
kill -TERM $DPID; wait $DPID
```

### 6.2 Run A — ClickHouse **down**, default `--backend auto` (zero-dependency path)

```text
sensor -r pcaps/test_dns.pcap -> exit 0 ; Flows exported: 1
sensor -r pcaps/test_http.pcapng -> exit 0 ; Flows exported: 1
sensor -r pcaps/test_tls_full.pcap -> exit 0 ; Flows exported: 1
sensor -r .../tls_invalid_reads.pcap -> exit 0 ; Flows exported: 2
sensor -r .../http_invalid_server.pcap -> exit 0 ; Flows exported: 1
sensor -r .../malware.pcap -> exit 0 ; Flows exported: 6
daemon exit status: 0
```

Daemon stderr (complete):

```text
[daemon] clickhouse: http://localhost:8123 not reachable — SQLite/JSONL only (re-probed every 30 s)
[daemon] transport=zmq_sink endpoint=ipc:///tmp/ndpi_flows.sock backends=sqlite,jsonl ready
[zmq_sink] listening on ipc:///tmp/ndpi_flows.sock
[daemon] flushed 12 rows -> sqlite,jsonl (total accepted=12 rejected=0)
[daemon] signal 15 — flushing and stopping
[zmq_sink] done
[daemon] stopped: accepted=12 rejected=0 clickhouse_failed=0
```

```text
$ wc -l engine-ml/data/flows.jsonl                         → 12
$ sqlite3 engine-ml/data/sentinel_flows.db "PRAGMA journal_mode; SELECT COUNT(*) FROM network_flows;"
wal
12
```

The sensors exported 1+1+1+2+1+6 = 12 flows. The daemon accepted 12 and rejected 0, and SQLite and JSONL each hold 12.

### 6.3 Lossless check: stored values vs. the sensor's own output

Each PCAP was replayed with `sensor -v` to collect the 12 JSON objects the sensor emits. Each object was matched to its stored row by `(src_ip, dst_ip, src_port, dst_port, protocol, first_seen_us)`. All 23 fields were compared in both SQLite and JSONL, and the `is_alert` rule was re-checked on every row:

```text
sensor -v records: 12  jsonl: 12  sqlite: 12
fields compared: 552  differences: 0
```

The same check after run B also reported `differences: 0`.

### 6.4 Rejection path

Input: one valid record, the line `not json`, and the valid record with `dst_port` changed to `99999`. Run with `--from-jsonl … --backend sqlite` into a separate scratch DB:

```text
[daemon] rejected: Expecting value: line 1 column 1 (char 0)
[daemon] rejected: dst_port: 99999 out of range for u16
[daemon] flushed 1 rows -> sqlite,jsonl (total accepted=1 rejected=2)
[daemon] stopped: accepted=1 rejected=2 clickhouse_failed=0
```

`rejected.jsonl` held both lines, each with its `error` and `raw` fields.

### 6.5 Run B — full stack up, `--backend both`

```text
[daemon] clickhouse: http://localhost:8123 table sentinel.network_flows reachable
[daemon] transport=zmq_sink endpoint=ipc:///tmp/ndpi_flows.sock backends=sqlite,jsonl,clickhouse ready
[zmq_sink] listening on ipc:///tmp/ndpi_flows.sock
[daemon] flushed 12 rows -> sqlite,jsonl,clickhouse (total accepted=12 rejected=0)
[daemon] signal 15 — flushing and stopping
[zmq_sink] done
[daemon] stopped: accepted=12 rejected=0 clickhouse_failed=0
```

The sensor lines and exit statuses were the same as in run A. The ClickHouse row count is in §5.2 (`total_rows = 12`), and:

```text
SELECT count() AS flows, sum(is_alert) AS alerts, countIf(ml_anomaly_score >= 0.8) AS score_ge_080,
       min(ingested_at_us) > max(last_seen_us) AS ingest_after_capture
FROM sentinel.network_flows
flows  alerts  score_ge_080  ingest_after_capture
12     5       0             1
```

---

## 7. `query_dashboard.py` output

### 7.1 Command

```bash
python3 engine-ml/query_dashboard.py --show-sql                        # SQLite
python3 engine-ml/query_dashboard.py --backend clickhouse --show-sql   # ClickHouse
```

### 7.2 Captured output (SQLite, after run B; exact SQL shown above each table)

```text
SentinelFlow Phase 2 — SQLite engine-ml/data/sentinel_flows.db
flows=12  is_alert=1: 5  ndpi_risk_mask>0: 5  timestamp mismatches: 0

1. Protocol Breakdown
    SELECT app_protocol,
           COUNT(*)        AS flows,
           SUM(pkt_count)  AS packets,
           SUM(bytes_up)   AS bytes_up,
           SUM(bytes_down) AS bytes_down
    FROM network_flows
    GROUP BY app_protocol
    ORDER BY flows DESC, app_protocol
+--------------+-------+---------+----------+------------+
| app_protocol | flows | packets | bytes_up | bytes_down |
+==============+=======+=========+==========+============+
| TLS          | 4     | 103     | 5148     | 59537      |
| HTTP         | 3     | 15      | 879      | 759        |
| DNS          | 2     | 5       | 215      | 157        |
| HTTP.Google  | 1     | 10      | 394      | 744        |
| ICMP         | 1     | 1       | 84       | 0          |
| TLS.ntop     | 1     | 109     | 3546     | 68910      |
+--------------+-------+---------+----------+------------+
(6 rows)

2. JA4 TLS Fingerprints
    SELECT ja4_client,
           src_ip || ':' || src_port || ' -> ' || dst_ip || ':' || dst_port AS flow,
           app_protocol
    FROM network_flows
    WHERE ja4_client NOT IN ('', 'N/A')
    ORDER BY ja4_client, first_seen_us
+--------------------------------------+------------------------------------------+--------------+
| ja4_client                           | flow                                     | app_protocol |
+======================================+==========================================+==============+
| t12d6707h2_2955a3196ffa_c83f907a73d3 | 192.168.1.13:55523 -> 178.62.197.130:443 | TLS.ntop     |
| t13d1515h2_8daaf6152771_6a09c78d0dc2 | 192.168.0.20:41240 -> 193.109.85.123:443 | TLS          |
| t13d1814h2_29a2cd9e9f10_d267a5f792d4 | 192.168.7.7:35236 -> 67.215.92.210:443   | TLS          |
+--------------------------------------+------------------------------------------+--------------+
(3 rows)

3. High-Risk Security Alerts (ndpi_risk_mask > 0)
    SELECT ndpi_risk_mask, ndpi_risk_str, src_ip, dst_ip, app_protocol,
           ml_anomaly_score, is_alert
    FROM network_flows
    WHERE ndpi_risk_mask > 0
    ORDER BY ml_anomaly_score DESC, first_seen_us
+----------------+--------------------------------------+----------------+-----------------+--------------+------------------+----------+
| ndpi_risk_mask | ndpi_risk_str                        | src_ip         | dst_ip          | app_protocol | ml_anomaly_score | is_alert |
+================+======================================+================+=================+==============+==================+==========+
| 128            | Obsolete TLS (v1.1 or older)         | 192.168.10.101 | 206.33.61.113   | TLS          | 0.4              | 1        |
| 70368744177664 | Unidirectional Traffic               | 74.80.160.99   | 67.217.77.28    | TLS          | 0.4              | 1        |
| 70403103916032 | Susp Entropy, Unidirectional Traffic | 192.168.7.7    | 144.139.247.220 | ICMP         | 0.4              | 1        |
| 70368744177664 | Unidirectional Traffic               | 192.168.7.7    | 144.139.247.220 | HTTP         | 0.4              | 1        |
| 2048           | HTTP Susp User-Agent                 | 192.168.1.29   | 143.204.14.183  | HTTP         | 0.4              | 1        |
+----------------+--------------------------------------+----------------+-----------------+--------------+------------------+----------+
(5 rows)

4. Flow Telemetry & Timestamp Verification
    SELECT src_ip, dst_ip, app_protocol, pkt_count,
           first_seen_us, last_seen_us,
           last_seen_us - first_seen_us                    AS delta_us,
           flow_duration_ms,
           CAST(ROUND(flow_duration_ms * 1000) AS INTEGER) AS duration_us,
           CASE WHEN last_seen_us - first_seen_us
                     = CAST(ROUND(flow_duration_ms * 1000) AS INTEGER)
                THEN 'OK' ELSE 'MISMATCH' END              AS verdict
    FROM network_flows
    ORDER BY first_seen_us
+----------------+-----------------+--------------+-----------+------------------+------------------+----------+------------------+-------------+---------+
| src_ip         | dst_ip          | app_protocol | pkt_count | first_seen_us    | last_seen_us     | delta_us | flow_duration_ms | duration_us | verdict |
+================+=================+==============+===========+==================+==================+==========+==================+=============+=========+
| 192.168.170.20 | 192.168.170.8   | DNS          | 3         | 1112172654366527 | 1112172695437491 | 41070964 | 41070.964        | 41070964    | OK      |
| 192.168.10.101 | 206.33.61.113   | TLS          | 8         | 1252380859868541 | 1252380859943054 | 74513    | 74.513           | 74513       | OK      |
| 74.80.160.99   | 67.217.77.28    | TLS          | 1         | 1421985541772794 | 1421985541772794 | 0        | 0.0              | 0           | OK      |
| 192.168.7.7    | 1.1.1.1         | DNS          | 2         | 1569571466977364 | 1569571467001085 | 23721    | 23.721           | 23721       | OK      |
| 192.168.7.7    | 144.139.247.220 | ICMP         | 1         | 1569571470672893 | 1569571470672893 | 0        | 0.0              | 0           | OK      |
| 192.168.7.7    | 144.139.247.220 | HTTP         | 1         | 1569571476362891 | 1569571476362891 | 0        | 0.0              | 0           | OK      |
| 192.168.7.7    | 67.215.92.210   | HTTP         | 2         | 1569579408876326 | 1569579409087861 | 211535   | 211.535          | 211535      | OK      |
| 192.168.7.7    | 67.215.92.210   | TLS          | 20        | 1569579416636584 | 1569579417280185 | 643601   | 643.601          | 643601      | OK      |
| 192.168.1.13   | 178.62.197.130  | TLS.ntop     | 109       | 1581113120474299 | 1581113121570392 | 1096093  | 1096.093         | 1096093     | OK      |
| 192.168.1.128  | 216.58.208.142  | HTTP.Google  | 10        | 1643129441023341 | 1643129441065505 | 42164    | 42.164           | 42164       | OK      |
| 192.168.1.29   | 143.204.14.183  | HTTP         | 12        | 1689351610492040 | 1689351610530140 | 38100    | 38.1             | 38100       | OK      |
| 192.168.0.20   | 193.109.85.123  | TLS          | 74        | 1698873191201916 | 1698873192090406 | 888490   | 888.49           | 888490      | OK      |
+----------------+-----------------+--------------+-----------+------------------+------------------+----------+------------------+-------------+---------+
(12 rows)
```

### 7.3 ClickHouse gives the same result

The ClickHouse version of each query differs only in dialect: `count()`/`sum()`, `concat(... toString(port))` in panel 2, and `toInt64(round(...))` / `if(...)` in panel 4. The full text is in `PANELS[*]["clickhouse"]` in `query_dashboard.py`. Captured output header:

```text
SentinelFlow Phase 2 — ClickHouse http://localhost:8123
flows=12  is_alert=1: 5  ndpi_risk_mask>0: 5  timestamp mismatches: 0
```

```text
$ diff <(grep '^[|+]' dashboard_sqlite.txt) <(grep '^[|+]' dashboard_ch.txt) && echo IDENTICAL
SQLite vs ClickHouse: all 4 panel tables IDENTICAL (30 table lines)
$ diff <(grep '^[|+]' runA/dashboard_sqlite.txt) <(grep '^[|+]' runB/dashboard_sqlite.txt)
run A vs run B SQLite panels: IDENTICAL
```

The first diff run was **not** identical: on the 3 zero-duration rows, ClickHouse printed `flow_duration_ms` as `0` and SQLite as `0.0`. ClickHouse's JSON output writes an integral Float64 without a decimal point. `ClickHouseBackend.run` now casts columns to `float` using the `Float*` types in the response's `meta`, and the re-run diff above is empty.

### 7.4 Reading the panels

* **Panel 1:** 6 `app_protocol` values. nDPI's `master.app` labels (`TLS.ntop`, `HTTP.Google`) are kept as distinct rows, not folded into `TLS`/`HTTP`.
* **Panel 2:** 3 flows carry a JA4. `t12d6707h2_2955a3196ffa_c83f907a73d3` is the same string cross-checked against ndpiReader in `part1_2.md` §5.1. The other two both come from `malware.pcap` (`192.168.7.7 → 67.215.92.210` and `192.168.0.20 → 193.109.85.123`) and were **not** cross-checked against ndpiReader in this session. The `tls_invalid_reads.pcap` TLS flow has `ja4_client = N/A`, matching `part1_2.md` §6.2.
* **Panel 3:** 5 flows have `ndpi_risk_mask > 0`, and all 5 have `is_alert = 1`. The two nDPI risk strings from `part1_2.md` §6.3 appear: `Obsolete TLS (v1.1 or older)` (mask 128) and `HTTP Susp User-Agent` (mask 2048). All 5 score `0.4`. That is the `ndpi_risk` weight alone: the `Unidirectional Traffic` flows have `pkt_count = 1`, below the heuristic's 3-packet floor. **No flow in this data reached `ml_anomaly_score >= 0.80`.** All 5 alerts come from the risk-mask half of the rule. The score half is covered only by the unit test (§4).
* **Panel 4:** `last_seen_us − first_seen_us == ROUND(flow_duration_ms × 1000)` on 12/12 rows (`timestamp mismatches: 0`). The `ROUND` is needed because `flow_duration_ms` is stored as a double (e.g. `1096.093 × 1000 = 1096092.9999…`). The two integer timestamp columns are compared exactly. The DNS, TLS.ntop, HTTP.Google and obsolete-TLS rows reproduce the deltas quoted in `part1_2.md` §3.3 and §6.2 (41070964, 1096093, 42164, 74513 µs).

### 7.5 `--serve`

```text
$ python3 engine-ml/query_dashboard.py --serve --port 8080 &
[dashboard] serving SQLite engine-ml/data/sentinel_flows.db on http://127.0.0.1:8080/
GET / -> 200 7091B
GET /api/panels.json -> {'flows': 12, 'alerts': 5, 'risk_flows': 5, 'timestamp_mismatches': 0}
   [('1. Protocol Breakdown', 6), ('2. JA4 TLS Fingerprints', 3),
    ('3. High-Risk Security Alerts (ndpi_risk_mask > 0)', 5),
    ('4. Flow Telemetry & Timestamp Verification', 12)]
```

The HTML contains the 4 panel headings. Each read opens a fresh read-only `file:…?mode=ro` connection, so a running daemon writing in WAL mode doesn't block it. The page was fetched with `curl` only; it was not opened in a browser.

---

## 8. Grafana

### 8.1 Panel queries (ClickHouse SQL)

| Panel | Type | Query |
|---|---|---|
| Protocol Distribution | piechart (donut) | `SELECT app_protocol, count() AS flows FROM sentinel.network_flows GROUP BY app_protocol ORDER BY flows DESC` |
| Traffic Volume | timeseries (bars) | `SELECT toDateTime(intDiv(first_seen_us, 1000000)) AS time, sum(bytes_up) AS bytes_up, sum(bytes_down) AS bytes_down FROM sentinel.network_flows GROUP BY time ORDER BY time` |
| JA4 TLS Fingerprints | table | `SELECT ja4_client, src_ip, dst_ip, dst_port, app_protocol, count() AS flows, sum(pkt_count) AS packets FROM sentinel.network_flows WHERE ja4_client != 'N/A' AND ja4_client != '' GROUP BY … ORDER BY flows DESC` |
| High-Risk Flows (alerts) | table | `SELECT fromUnixTimestamp64Micro(toInt64(first_seen_us)) AS first_seen, src_ip, src_port, dst_ip, dst_port, app_protocol, ndpi_risk_mask, ndpi_risk_str, ml_anomaly_score FROM sentinel.network_flows WHERE is_alert = 1 ORDER BY ml_anomaly_score DESC, first_seen_us` |

Traffic Volume is plotted against **capture time** (`first_seen_us`), not ingest time, and has no `$__timeFilter`. Because the test PCAPs date from 2005 to 2023, the dashboard's default range is `now-25y`.

### 8.2 Evidence

```text
$ curl -u admin:sentinel http://127.0.0.1:3000/api/health
{"database": "ok", "version": "13.0.1", "commit": "a100054f"}
$ curl -u admin:sentinel http://127.0.0.1:3000/api/datasources/uid/sentinel-clickhouse/health
{"message":"Data source is working","status":"OK"}
```

Each panel's `targets` sent unchanged from the provisioned JSON to `POST /api/ds/query`:

```text
[piechart] Protocol Distribution: status=200 rows=6 fields=['app_protocol', 'flows']
      ('TLS', 4)
      ('HTTP', 3)
      ('DNS', 2)
      ('ICMP', 1)
      ('HTTP.Google', 1)
      ('TLS.ntop', 1)
[timeseries] Traffic Volume (bytes per capture second): status=200 rows=12 fields=['time', 'bytes_up', 'bytes_down']
[table] JA4 TLS Fingerprints: status=200 rows=3 fields=['ja4_client', 'src_ip', 'dst_ip', 'dst_port', 'app_protocol', 'flows', 'packets']
[table] High-Risk Flows (alerts): status=200 rows=5 fields=['first_seen', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'app_protocol', 'ndpi_risk_mask', 'ndpi_risk_str', 'ml_anomaly_score']
      (1252380859868, '192.168.10.101', 3967, '206.33.61.113', 443, 'TLS', 128, 'Obsolete TLS (v1.1 or older)', 0.4)
      (1421985541772, '74.80.160.99', 3258, '67.217.77.28', 443, 'TLS', 70368744177664, 'Unidirectional Traffic', 0.4)
      (1569571470672, '192.168.7.7', 0, '144.139.247.220', 0, 'ICMP', 70403103916032, 'Susp Entropy, Unidirectional Traffic', 0.4)
      (1569571476362, '192.168.7.7', 33706, '144.139.247.220', 80, 'HTTP', 70368744177664, 'Unidirectional Traffic', 0.4)
      (1689351610492, '192.168.1.29', 51536, '143.204.14.183', 80, 'HTTP', 2048, 'HTTP Susp User-Agent', 0.4)
```

Rendered with `chromium --headless=new --screenshot` against `http://127.0.0.1:3000/d/sentinelflow-phase2?kiosk`:

![Grafana dashboard](docs/part2_grafana.png)

The screenshot shows the donut (TLS 4 / HTTP 3 / DNS 2 / ICMP, HTTP.Google, TLS.ntop 1 each), 12 bar points spread across 2005–2023, 3 JA4 rows and 5 alert rows. It was taken after one cosmetic dashboard change (wider `ja4_client`/`ndpi_risk_str` columns; the score color scale now starts at yellow so alert rows aren't green).

---

## 9. How to run

```bash
# zero-dependency path (no Docker needed)
make sensor
python3 engine-ml/daemon.py &                 # or: make daemon
LD_LIBRARY_PATH=/home/joe/nDPI/src/lib ./sensor-c/build/sensor -r pcaps/test_tls_full.pcap
python3 engine-ml/query_dashboard.py          # or: make dashboard / make dashboard-web

# full stack
docker compose up -d                          # first start needs internet for the Grafana plugin
python3 engine-ml/daemon.py                   # auto-attaches ClickHouse on :8123
python3 engine-ml/query_dashboard.py --backend clickhouse
# Grafana: http://127.0.0.1:3000  (anonymous viewer; admin/sentinel)

# backfill ClickHouse from the JSONL written while it was down
python3 engine-ml/daemon.py --from-jsonl engine-ml/data/flows.jsonl --backend clickhouse
```

---

## 10. What may and may not be said

**May be said (observed in this session):**

* On a host without `pyzmq`, `daemon.py` received the sensor's flows over `ipc:///tmp/ndpi_flows.sock` through the spawned C `zmq_sink`, using only the Python standard library: 12/12 flows from 6 PCAPs, in two independent runs.
* Every stored record is equal, on all 23 sensor fields, to what `sensor -v` printed for the same PCAPs (552 comparisons, 0 differences, in both SQLite and JSONL).
* SQLite runs in WAL mode; JSONL and SQLite hold the same 12 records.
* ClickHouse 24.8 accepted the same 12 rows through the stdlib `urllib` JSONEachRow client. The column types and MergeTree sort key match the brief.
* The four dashboard queries return identical tables from SQLite and from ClickHouse.
* `last_seen_us − first_seen_us` equals `flow_duration_ms × 1000` (rounded to the µs) on all 12 stored rows, in both databases.
* Every flow with `ndpi_risk_mask > 0` has `is_alert = 1` (5/5), and no flow without a risk mask is flagged (7 rows with score 0.0, `is_alert = 0`).
* The Grafana ClickHouse datasource reports `OK`, all 4 provisioned panel queries return data through Grafana, and the dashboard renders (screenshot).
* Malformed JSON and out-of-range values are rejected and logged without stopping the daemon.

**Must not be said (not shown):**

* That the `pyzmq` transport works. It is implemented but `pyzmq` is not installed here, so it never ran.
* That `ml_anomaly_score` detects anything. It is a fixed heuristic, not a model. No flow in this data reached 0.80; that alert path is tested only by a synthetic unit test.
* That the ClickHouse failover works mid-run. Not tested: losing ClickHouse during a run (the detach path), the 30 s re-probe/re-attach in `auto` mode, and the `--from-jsonl` backfill into ClickHouse.
* That ingestion is deduplicated. It is not: replaying a PCAP or re-running a backfill inserts duplicate rows in all three stores. MergeTree was kept as specified rather than `ReplacingMergeTree`.
* Anything about throughput, latency or memory. Only 12 flows were ingested, all in one batch. No load test, no live `-i` capture, no long-running soak.
* That `ndpi_risk_mask` values ≥ 2⁶³ are handled. SQLite stores INTEGER as signed 64-bit and would raise `OverflowError`. The largest mask seen here is 70403103916032 (< 2⁴⁷).
* That the two JA4 strings from `malware.pcap` match ndpiReader. Only the `test_tls_full.pcap` JA4 was cross-checked (Part 1 v2).
* That the `--serve` HTML page renders correctly in a browser. It was fetched with `curl` only.
* That the Grafana stack starts offline from scratch. The plugin download needs network access on first start.
