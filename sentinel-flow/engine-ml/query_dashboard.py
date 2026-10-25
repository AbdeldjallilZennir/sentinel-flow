#!/usr/bin/env python3
"""
SentinelFlow Phase 2/3 — query dashboard (standard library only).

Runs seven panel queries against the ingested flows and prints them as
tables, or serves them as a web page that updates itself every 10 s.

  ./query_dashboard.py                         # SQLite (engine-ml/data/...)
  ./query_dashboard.py --backend clickhouse    # same panels from ClickHouse
  ./query_dashboard.py --show-sql              # print each SQL query too
  ./query_dashboard.py --serve [--port 8080]   # http://127.0.0.1:8080/
  ./query_dashboard.py --new-test "nmap scan"  # start a test (also a button on the page)
  ./query_dashboard.py --test all              # every flow, not only the latest test

Tests: starting one hides flows and blocking events stored before it, so each
test starts empty. Nothing is deleted; tests are saved beside the database
(sentinel_flows.tests.json) and any earlier test or "all" can be shown.
"""

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "data", "sentinel_flows.db")

# Each panel: title + SQL per backend. SQLite table is `network_flows`,
# ClickHouse table is `sentinel.network_flows`; columns are identical.
#
# Flow panels read `flows`: one row per connection. The sensor's active
# timeout (-A, default 60 s) stores a snapshot of a long connection every
# interval, each with counters since first_seen_us, so counting rows of
# network_flows counts long connections several times. `flows` keeps the
# latest record of each connection (same 5-tuple and first_seen_us).
#
# {start} / {end} (µs) limit every panel to one test (see TestLog): flows by
# the time the daemon stored them, blocking events by their own time.
FLOWS = {
    "sqlite": """\
SELECT * FROM (
  SELECT *, ROW_NUMBER() OVER (
           PARTITION BY src_ip, src_port, dst_ip, dst_port, protocol, first_seen_us
           ORDER BY last_seen_us DESC, pkt_count DESC, ingested_at_us DESC) AS snapshot_rank
  FROM network_flows
  WHERE ingested_at_us >= {start} AND ingested_at_us < {end})
WHERE snapshot_rank = 1""",
    "clickhouse": """\
SELECT * FROM sentinel.network_flows
WHERE ingested_at_us >= {start} AND ingested_at_us < {end}
ORDER BY last_seen_us DESC, pkt_count DESC, ingested_at_us DESC
LIMIT 1 BY src_ip, src_port, dst_ip, dst_port, protocol, first_seen_us""",
}
ALL_TIME = (0, 2**63 - 1)


def bind(sql, window):
    """Fill in the {start} / {end} window (integers, so no quoting issues)."""
    start, end = window
    return sql.replace("{start}", str(int(start))).replace("{end}", str(int(end)))


def full_sql(sql, key, window=ALL_TIME):
    """The query with the `flows` definition in front, if it reads `flows`."""
    if "FROM flows" in sql:
        body = "\n".join("  " + line for line in FLOWS[key].splitlines())
        sql = f"WITH flows AS (\n{body})\n{sql}"
    return bind(sql, window)


PANELS = [
    {
        "title": "1. Protocol Breakdown",
        "sqlite": """\
SELECT app_protocol,
       COUNT(*)        AS flows,
       SUM(pkt_count)  AS packets,
       SUM(bytes_up)   AS bytes_up,
       SUM(bytes_down) AS bytes_down
FROM flows
GROUP BY app_protocol
ORDER BY flows DESC, app_protocol""",
        "clickhouse": """\
SELECT app_protocol,
       count()         AS flows,
       sum(pkt_count)  AS packets,
       sum(bytes_up)   AS bytes_up,
       sum(bytes_down) AS bytes_down
FROM flows
GROUP BY app_protocol
ORDER BY flows DESC, app_protocol""",
    },
    # Panels 2-4 are capped at 100 rows: without a limit they list every flow,
    # and the web page (reloaded every 10 s) keeps growing during a live run.
    {
        "title": "2. JA4 TLS Fingerprints (newest 100 TLS flows)",
        "sqlite": """\
SELECT ja4_client, flow, app_protocol
FROM (SELECT ja4_client, first_seen_us, app_protocol,
             src_ip || ':' || src_port || ' -> ' || dst_ip || ':' || dst_port AS flow
      FROM flows
      WHERE ja4_client NOT IN ('', 'N/A')
      ORDER BY first_seen_us DESC
      LIMIT 100)
ORDER BY ja4_client, first_seen_us""",
        "clickhouse": """\
SELECT ja4_client, flow, app_protocol
FROM (SELECT ja4_client, first_seen_us, app_protocol,
             concat(src_ip, ':', toString(src_port), ' -> ',
                    dst_ip, ':', toString(dst_port)) AS flow
      FROM flows
      WHERE ja4_client NOT IN ('', 'N/A')
      ORDER BY first_seen_us DESC
      LIMIT 100)
ORDER BY ja4_client, first_seen_us""",
    },
    {
        # Same rule as the summary's is_alert count and the Grafana alerts
        # panel. Since Part 6 most nDPI risks no longer raise an alert.
        "title": "3. High-Risk Security Alerts (is_alert = 1, top 100 by ml_anomaly_score)",
        "sqlite": """\
SELECT ndpi_risk_mask, ndpi_risk_str, src_ip, dst_ip, app_protocol,
       ml_anomaly_score, is_alert
FROM flows
WHERE is_alert = 1
ORDER BY ml_anomaly_score DESC, first_seen_us
LIMIT 100""",
        "clickhouse": """\
SELECT ndpi_risk_mask, ndpi_risk_str, src_ip, dst_ip, app_protocol,
       ml_anomaly_score, is_alert
FROM flows
WHERE is_alert = 1
ORDER BY ml_anomaly_score DESC, first_seen_us
LIMIT 100""",
    },
    {
        "title": "4. Flow Telemetry & Timestamp Verification (mismatches first, then newest 100)",
        "sqlite": """\
SELECT src_ip, dst_ip, app_protocol, pkt_count,
       first_seen_us, last_seen_us,
       last_seen_us - first_seen_us                    AS delta_us,
       flow_duration_ms,
       CAST(ROUND(flow_duration_ms * 1000) AS INTEGER) AS duration_us,
       CASE WHEN last_seen_us - first_seen_us
                 = CAST(ROUND(flow_duration_ms * 1000) AS INTEGER)
            THEN 'OK' ELSE 'MISMATCH' END              AS verdict
FROM flows
ORDER BY verdict = 'OK', first_seen_us DESC
LIMIT 100""",
        "clickhouse": """\
SELECT src_ip, dst_ip, app_protocol, pkt_count,
       first_seen_us, last_seen_us,
       toInt64(last_seen_us) - toInt64(first_seen_us)  AS delta_us,
       flow_duration_ms,
       toInt64(round(flow_duration_ms * 1000))         AS duration_us,
       if(toInt64(last_seen_us) - toInt64(first_seen_us)
            = toInt64(round(flow_duration_ms * 1000)),
          'OK', 'MISMATCH')                            AS verdict
FROM flows
ORDER BY verdict = 'OK', first_seen_us DESC
LIMIT 100""",
    },
]

PANELS.append({
    "title": "5. ML Detections (Phase 3, top 15 by ml_anomaly_score)",
    "sqlite": """\
SELECT src_ip || ' -> ' || dst_ip || ':' || dst_port AS flow,
       app_protocol, ja4_client,
       ROUND(ml_anomaly_score, 3) AS score, ROUND(ml_c2_proba, 3) AS c2_proba,
       ROUND(ml_iforest_score, 3) AS iforest, is_alert, ml_model
FROM flows
ORDER BY ml_anomaly_score DESC, first_seen_us
LIMIT 15""",
    "clickhouse": """\
SELECT concat(src_ip, ' -> ', dst_ip, ':', toString(dst_port)) AS flow,
       app_protocol, ja4_client,
       round(ml_anomaly_score, 3) AS score, round(ml_c2_proba, 3) AS c2_proba,
       round(ml_iforest_score, 3) AS iforest, is_alert, ml_model
FROM flows
ORDER BY ml_anomaly_score DESC, first_seen_us
LIMIT 15""",
})

PANELS.append({
    "title": "6. Active Kernel Mitigations & XDP Drop Counters (Phase 4)",
    "optional_table": "blocked_ips / sentinel.mitigations (daemon --mitigate ...)",
    # The daemon writes "expired" only while it is running. A block whose
    # timeout has passed (daemon stopped or restarted) is shown as expired
    # using the latest expiry time from its block / counters events.
    "sqlite": """\
SELECT ip, backend, status, reason, ROUND(score, 3) AS score, flow,
       dropped_pkts, dropped_bytes,
       datetime(last_block_us / 1000000, 'unixepoch') AS last_blocked
FROM (SELECT b.ip, b.backend, b.reason, b.score, b.flow, b.dropped_pkts,
             b.dropped_bytes, COALESCE(e.last_block_us, b.first_blocked_us) AS last_block_us,
             CASE WHEN b.status = 'active'
                       AND e.until_us < CAST(strftime('%s', 'now') AS INTEGER) * 1000000
                  THEN 'expired' ELSE b.status END AS status
      FROM blocked_ips b
      LEFT JOIN (SELECT ip, MAX(ts_us + timeout_s * 1000000) AS until_us,
                        MAX(CASE WHEN action = 'block' THEN ts_us END) AS last_block_us
                 FROM mitigation_events
                 WHERE action IN ('block', 'counters')
                 GROUP BY ip) e ON e.ip = b.ip
      WHERE b.ip IN (SELECT ip FROM mitigation_events
                     WHERE ts_us >= {start} AND ts_us < {end}))
ORDER BY (status = 'active') DESC, dropped_pkts DESC, last_block_us DESC, ip""",
    "clickhouse": """\
SELECT ip,
       argMax(backend, ts_us) AS backend,
       multiIf(argMax(action, ts_us) = 'expire', 'expired',
               argMax(action, ts_us) = 'unblock', 'unblocked',
               maxIf(toInt64(ts_us) + timeout_s * 1000000, action IN ('block', 'counters'))
                 < toUnixTimestamp64Micro(now64(6)), 'expired',
               'active') AS status,
       argMaxIf(reason, ts_us, action = 'block') AS reason,
       round(argMaxIf(score, ts_us, action = 'block'), 3) AS score,
       argMaxIf(flow, ts_us, action = 'block') AS flow,
       max(dropped_pkts) AS dropped_pkts, max(dropped_bytes) AS dropped_bytes,
       formatDateTime(toDateTime(intDiv(maxIf(ts_us, action = 'block'), 1000000), 'UTC'),
                      '%Y-%m-%d %H:%i:%S') AS last_blocked
FROM sentinel.mitigations
WHERE ip != '' AND action IN ('block', 'counters', 'expire', 'unblock')
GROUP BY ip
HAVING countIf(ts_us >= {start} AND ts_us < {end}) > 0
ORDER BY (status = 'active') DESC, dropped_pkts DESC, maxIf(ts_us, action = 'block') DESC, ip""",
})

PANELS.append({
    "title": "6b. Recent Mitigation & Scan Events (incl. detections not blocked)",
    "optional_table": "mitigation_events / sentinel.mitigations (daemon --mitigate ...)",
    # skip_protected = a trigger fired but the address is protected (e.g. a
    # LAN host running a port scan); it is never blocked, only reported here.
    "sqlite": """\
SELECT datetime(ts_us / 1000000, 'unixepoch') AS time,
       CASE action WHEN 'skip_protected' THEN 'detected, not blocked' ELSE action END AS action,
       reason, ip, detail, flow, ROUND(score, 3) AS score
FROM mitigation_events
WHERE action != 'counters' AND ts_us >= {start} AND ts_us < {end}
ORDER BY ts_us DESC
LIMIT 50""",
    "clickhouse": """\
SELECT formatDateTime(toDateTime(intDiv(ts_us, 1000000), 'UTC'), '%Y-%m-%d %H:%i:%S') AS time,
       if(action = 'skip_protected', 'detected, not blocked', action) AS action,
       reason, ip, detail, flow, round(score, 3) AS score
FROM sentinel.mitigations
WHERE action != 'counters' AND ts_us >= {start} AND ts_us < {end}
ORDER BY ts_us DESC
LIMIT 50""",
})

SUMMARY = {
    "sqlite": """\
SELECT COUNT(*), SUM(is_alert), SUM(ndpi_risk_mask > 0),
       SUM(last_seen_us - first_seen_us
           != CAST(ROUND(flow_duration_ms * 1000) AS INTEGER)),
       SUM(ml_anomaly_score >= 0.8), GROUP_CONCAT(DISTINCT ml_model)
FROM flows""",
    "clickhouse": """\
SELECT count(), sum(is_alert), countIf(ndpi_risk_mask > 0),
       countIf(toInt64(last_seen_us) - toInt64(first_seen_us)
               != toInt64(round(flow_duration_ms * 1000))),
       countIf(ml_anomaly_score >= 0.8), arrayStringConcat(groupUniqArray(ml_model), ',')
FROM flows""",
}


# ── Backends: run_all([sql, ...]) -> [(column_names, rows) or exception] ──
class SQLiteBackend:
    key = "sqlite"

    def __init__(self, path):
        if not os.path.exists(path):
            sys.exit(f"database not found: {path} (run daemon.py first)")
        self.path = path
        self.label = f"SQLite {os.path.relpath(path)}"

    def _connect(self):
        # Read-only connection per refresh: safe under a live WAL writer.
        uri = f"file:{urllib.parse.quote(self.path)}?mode=ro"
        db = sqlite3.connect(uri, uri=True)
        try:
            db.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            return db
        except sqlite3.OperationalError as e:
            db.close()
            # A WAL database needs a -shm file beside it. When the daemon has
            # stopped (it removes that file) and this user can't create it,
            # e.g. the daemon ran as root and owns the folder, read the file as
            # a fixed snapshot instead. Nothing is writing to it at that point.
            if "readonly" not in str(e) and "unable to open" not in str(e):
                raise
            return sqlite3.connect(uri + "&immutable=1", uri=True)

    def run_all(self, queries, window=ALL_TIME):
        # `flows` is built once per refresh as a temporary table (private to
        # this connection), not once per query: the window function is the
        # slow part.
        db = self._connect()
        try:
            if any("FROM flows" in q for q in queries):
                db.execute("CREATE TEMP TABLE flows AS " + bind(FLOWS["sqlite"], window))
            out = []
            for sql in queries:
                try:
                    cur = db.execute(bind(sql, window))
                    out.append(([d[0] for d in cur.description], cur.fetchall()))
                except sqlite3.Error as e:
                    out.append(e)
            return out
        finally:
            db.close()


class ClickHouseBackend:
    key = "clickhouse"

    def __init__(self, url, user, password):
        self.url = url.rstrip("/")
        self.headers = {"X-ClickHouse-User": user, "X-ClickHouse-Key": password}
        self.label = f"ClickHouse {self.url}"

    def run(self, sql):
        qs = urllib.parse.urlencode({
            "query": sql + "\nFORMAT JSONCompact",
            "output_format_json_quote_64bit_integers": 0,
        })
        req = urllib.request.Request(f"{self.url}/?{qs}", headers=self.headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            res = json.loads(r.read())
        # JSON drops the type of integral floats (0.0 -> 0); restore it.
        is_f = [m["type"].startswith(("Float", "Nullable(Float")) for m in res["meta"]]
        rows = [tuple(float(v) if f and v is not None else v
                      for v, f in zip(r, is_f)) for r in res["data"]]
        return [m["name"] for m in res["meta"]], rows

    def run_all(self, queries, window=ALL_TIME):
        out = []
        for sql in queries:
            try:
                out.append(self.run(full_sql(sql, self.key, window)))
            except Exception as e:
                out.append(e)
        return out


# ── Tests: named time windows, so one test's flows can be told apart ───────
class TestLog:
    """Each test starts when it is created and ends when the next one starts.
    Starting a test hides older flows and events; nothing is deleted. Kept as
    JSON beside the database, so the web page, the terminal view and later
    runs agree. The database stays read-only (it may belong to root)."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def load(self):
        try:
            with open(self.path) as fh:
                raw = json.load(fh).get("tests", [])
        except FileNotFoundError:
            return []
        except (OSError, ValueError, AttributeError) as e:
            print(f"[dashboard] ignoring unreadable {self.path}: {e}", file=sys.stderr)
            return []
        tests = []
        for t in raw:
            try:
                tests.append({"id": len(tests) + 1, "name": str(t["name"])[:80],
                              "start_us": int(t["start_us"])})
            except (KeyError, TypeError, ValueError):
                continue
        return tests

    def add(self, name):
        with self.lock:
            tests = self.load()
            name = " ".join(str(name or "").split())[:80] or f"Test {len(tests) + 1}"
            tests.append({"id": len(tests) + 1, "name": name,
                          "start_us": time.time_ns() // 1000})
            tmp = f"{self.path}.{os.getpid()}.tmp"
            try:
                with open(tmp, "w") as fh:
                    json.dump({"tests": [{"name": t["name"], "start_us": t["start_us"]}
                                         for t in tests]}, fh, indent=1)
                os.replace(tmp, self.path)
            except OSError as e:
                raise OSError(f"cannot save {self.path}: {e.strerror}") from None
            return tests[-1]

    @staticmethod
    def view(tests, selection):
        """The test to show ('latest', 'all' or an id) -> (view dict, window)."""
        chosen = None
        if selection not in (None, "", "all") and tests:
            if selection == "latest":
                chosen = tests[-1]
            else:
                try:
                    chosen = tests[int(selection) - 1]
                except (ValueError, IndexError):
                    chosen = tests[-1]
        if chosen is None:
            return {"selected": "all", "name": "All flows"}, ALL_TIME
        nxt = tests[chosen["id"]] if chosen["id"] < len(tests) else None
        end = nxt["start_us"] if nxt else ALL_TIME[1]
        return ({"selected": chosen["id"], "name": chosen["name"],
                 "start_us": chosen["start_us"],
                 "end_us": nxt["start_us"] if nxt else None}, (chosen["start_us"], end))


# ── Rendering ─────────────────────────────────────────────────────────────
def fmt(v):
    if v is None:
        return "NULL"
    if isinstance(v, float):
        return f"{v:.4f}".rstrip("0").rstrip(".") if v != int(v) else f"{v:.1f}"
    return str(v)


def text_table(cols, rows):
    cells = [[fmt(v) for v in r] for r in rows]
    widths = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(cols)]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    line = lambda vals: "| " + " | ".join(v.ljust(w) for v, w in zip(vals, widths)) + " |"
    out = [sep, line(cols), sep.replace("-", "=")]
    out += [line(r) for r in cells] or ["| (no rows)".ljust(len(sep) - 1) + "|"]
    out.append(sep)
    return "\n".join(out)


def collect(backend, tests=None, selection="latest"):
    tests = tests or []
    view, window = TestLog.view(tests, selection)
    summary, *results = backend.run_all([SUMMARY[backend.key]] +
                                        [p[backend.key] for p in PANELS], window)
    if isinstance(summary, Exception):
        raise summary
    total, alerts, risky, mismatches, ml_hits, models = summary[1][0]
    panels = []
    for p, res in zip(PANELS, results):
        if isinstance(res, Exception):
            if "optional_table" not in p:
                raise res
            # Phase 4 tables exist only after a daemon run with --mitigate.
            cols, rows = ["note"], [(f"no mitigation data yet: {p['optional_table']} "
                                     f"({type(res).__name__})",)]
        else:
            cols, rows = res
        panels.append({"title": p["title"],
                       "sql": full_sql(p[backend.key], backend.key, window),
                       "columns": cols, "rows": rows})
    return {"source": backend.label, "tests": tests, "view": view,
            "summary": {"flows": total or 0, "alerts": alerts or 0,
                        "risk_flows": risky or 0,
                        "timestamp_mismatches": mismatches or 0,
                        "ml_score_ge_080": ml_hits or 0,
                        "scorers": sorted(set((models or "").split(",")) - {""})},
            "panels": panels}


def local_time(us):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(us / 1e6))


def describe_view(data):
    v, n = data["view"], len(data["tests"])
    if v["selected"] == "all":
        return ("View: all flows" + (f" ({n} test{'s' if n != 1 else ''} recorded; "
                                     "--test N shows one)" if n else
                                     " (no tests yet: start one with --new-test NAME "
                                     "or the button on the web page)"))
    span = (f"{local_time(v['start_us'])} to {local_time(v['end_us'])}" if v.get("end_us")
            else f"since {local_time(v['start_us'])}, still running")
    return f"View: test {v['selected']} \"{v['name']}\" ({span}); --test all shows everything"


def print_text(data, show_sql):
    s = data["summary"]
    print(f"SentinelFlow Phase 2/3 — {data['source']}")
    print(describe_view(data))
    print(f"flows={s['flows']}  is_alert=1: {s['alerts']}  "
          f"ndpi_risk_mask>0: {s['risk_flows']}  "
          f"timestamp mismatches: {s['timestamp_mismatches']}  "
          f"ml_score>=0.80: {s['ml_score_ge_080']}  scorer: {','.join(s['scorers'])}\n")
    for p in data["panels"]:
        print(p["title"])
        if show_sql:
            print("\n".join("    " + l for l in p["sql"].splitlines()))
        print(text_table(p["columns"], p["rows"]))
        print(f"({len(p['rows'])} row{'s' if len(p['rows']) != 1 else ''})\n")


# ── Web page ──────────────────────────────────────────────────────────────
# A static page; its script fetches /api/panels.json every 10 s and redraws
# in place (no page reload, so a half-typed test name or an open SQL box
# survives). Colors: the dataviz reference palette; status colors always
# come with a text label.
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelFlow dashboard</title>
<style>
:root {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --surface-2: #f1f0ec;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --accent: #2a78d6;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --surface-2: #252523;
    --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
    --accent: #3987e5;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --surface-2: #252523;
  --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  --accent: #3987e5;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink);
       font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
.page { max-width: 1440px; margin: 0 auto; padding: 20px 16px 48px; }
.top { display: flex; flex-wrap: wrap; gap: 8px 20px; align-items: center; justify-content: space-between; }
h1 { font-size: 20px; margin: 0; }
.meta { color: var(--ink-2); font-size: 13px; overflow-wrap: anywhere; }
.tools { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; color: var(--ink-2); font-size: 13px; }
a { color: var(--accent); }
button, select, input { font: inherit; color: var(--ink); background: var(--surface);
  border: 1px solid var(--axis); border-radius: 6px; padding: 6px 10px; }
button { cursor: pointer; }
button.primary { background: var(--accent); border-color: var(--accent); color: #ffffff; font-weight: 600; }
button:disabled { opacity: .6; cursor: default; }
button:focus-visible, select:focus-visible, input:focus-visible, summary:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px; }
.error { margin: 12px 0 0; padding: 10px 14px; border: 1px solid var(--ring);
  border-left: 4px solid var(--critical); border-radius: 8px; background: var(--surface); }
.testbar { margin: 16px 0 0; padding: 14px 16px; background: var(--surface);
  border: 1px solid var(--ring); border-radius: 10px; display: flex; flex-wrap: wrap; gap: 12px 24px; align-items: center; }
.current { flex: 1 1 320px; min-width: 0; }
.current .label { color: var(--ink-2); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
.current .name { display: block; font-size: 17px; font-weight: 600; overflow-wrap: anywhere; }
.current .span { color: var(--ink-2); font-size: 13px; }
.clock { font-variant-numeric: tabular-nums; }
.testbar form { display: flex; gap: 8px; flex-wrap: wrap; }
.testbar input { width: 240px; max-width: 100%; }
.testbar select { max-width: min(420px, 70vw); }
.hint { flex-basis: 100%; margin: 0; color: var(--ink-2); font-size: 12.5px; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin: 16px 0 4px; }
.tile { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 12px 14px; }
.tile .label { color: var(--ink-2); font-size: 13px; }
.tile .value { font-size: 28px; font-weight: 600; line-height: 1.2; margin-top: 2px; }
.tile .status { margin-top: 6px; }
h2.group { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--ink-2);
  margin: 28px 0 8px; font-weight: 600; }
.cards { display: grid; gap: 12px; }
@media (min-width: 1100px) { .cards.pair { grid-template-columns: 1fr 1fr; } }
.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px 16px; min-width: 0; }
.card-head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.card-head h3 { margin: 0; font-size: 15px; }
.badge { font-size: 11px; color: var(--ink-2); border: 1px solid var(--grid); border-radius: 999px; padding: 0 7px; }
.count { margin-left: auto; color: var(--ink-2); font-size: 12px; }
.note { margin: 2px 0 10px; color: var(--ink-2); font-size: 12.5px; }
.empty { margin: 8px 0; color: var(--ink-2); }
.table-wrap { overflow: auto; max-height: 440px; border-top: 1px solid var(--grid); }
table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
thead th { position: sticky; top: 0; z-index: 1; background: var(--surface); color: var(--ink-2); font-weight: 600;
  text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--axis); white-space: nowrap; }
td { padding: 6px 10px; border-bottom: 1px solid var(--grid); white-space: nowrap; vertical-align: top; }
tbody tr:hover td { background: var(--surface-2); }
th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
td.wrap { white-space: normal; min-width: 24ch; max-width: 56ch; overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.status { display: inline-flex; align-items: center; gap: 6px; padding: 1px 8px 1px 6px; border-radius: 999px;
  background: var(--surface-2); font-size: 12px; color: var(--ink); white-space: nowrap; }
.status .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); flex: none; }
.status.good .dot { background: var(--good); }
.status.warning .dot { background: var(--warning); }
.status.serious .dot { background: var(--serious); }
.status.critical .dot { background: var(--critical); }
.barwrap { display: flex; align-items: center; justify-content: flex-end; gap: 8px; }
.bartrack { width: 96px; flex: none; }
.bar { display: block; height: 6px; border-radius: 3px; background: var(--accent); min-width: 2px; }
details.sql { margin-top: 10px; }
details.sql summary { cursor: pointer; color: var(--ink-2); font-size: 12px; }
pre { margin: 8px 0 0; padding: 10px; background: var(--surface-2); border-radius: 6px; overflow: auto;
  font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
main { transition: opacity .2s; }
body.loading main { opacity: .6; }
</style>
</head>
<body>
<div class="page">
  <div class="top">
    <div>
      <h1>SentinelFlow</h1>
      <div class="meta" id="meta">Loading…</div>
    </div>
    <div class="tools">
      <span id="updated" aria-live="polite"></span>
      <button type="button" id="pause">Pause</button>
      <button type="button" id="theme" title="Colour theme">Theme: auto</button>
      <a href="/api/panels.json" id="json">JSON</a>
    </div>
  </div>
  <div class="error" id="error" role="alert" hidden></div>

  <section class="testbar" aria-label="Tests">
    <div class="current">
      <span class="label">Showing</span>
      <span class="name" id="view-name">…</span>
      <span class="span" id="view-span"></span> <span class="span clock" id="view-clock"></span>
    </div>
    <label class="tools">View
      <select id="test-select" aria-label="Which test to show"></select>
    </label>
    <form id="new-test">
      <input id="test-name" maxlength="80" placeholder="Test name (optional)" aria-label="New test name">
      <button type="submit" class="primary">Start new test</button>
    </form>
    <p class="hint">Starting a test hides the flows and blocking events stored before it, so each test starts empty.
      Nothing is deleted: pick an earlier test or “All flows” under View to see them again.</p>
  </section>

  <main>
    <div class="kpis" id="kpis"></div>
    <div id="groups"></div>
  </main>
</div>
<script>
"use strict";
const $ = (s) => document.querySelector(s);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

const PANEL_INFO = {
  "6":  ["Blocked addresses", "Status, reason and kernel drop counters of addresses with blocking activity in this view"],
  "6b": ["Blocking and scan events", "Latest 50, including detections that were not blocked"],
  "3":  ["Alerts", "is_alert = 1, top 100 by ML score"],
  "5":  ["Top ML scores", "Top 15 connections by ML score"],
  "1":  ["Protocols", "Connections, packets and bytes per protocol"],
  "2":  ["JA4 TLS fingerprints", "Newest 100 TLS connections"],
  "4":  ["Timestamp check", "Mismatches first, then the newest 100"],
};
const GROUPS = [["Blocking", ["6", "6b"], false], ["Detections", ["3", "5"], false],
                ["Traffic", ["1", "2"], true], ["Data checks", ["4"], false]];
const LABELS = { ml_anomaly_score: "ML score", c2_proba: "C2 prob.", iforest: "IForest",
  ja4_client: "JA4", app_protocol: "protocol", ndpi_risk_mask: "risk mask",
  ndpi_risk_str: "nDPI risks", is_alert: "alert", pkt_count: "packets",
  dropped_pkts: "dropped pkts", dropped_bytes: "dropped bytes", last_blocked: "last blocked",
  flow_duration_ms: "duration ms", delta_us: "Δ µs", duration_us: "duration µs",
  first_seen_us: "first seen µs", last_seen_us: "last seen µs", src_ip: "source",
  dst_ip: "destination", ml_model: "model", bytes_up: "bytes up", bytes_down: "bytes down" };
const COUNTS = new Set(["flows", "packets", "bytes_up", "bytes_down", "pkt_count",
                        "dropped_pkts", "dropped_bytes"]);
const SCORES = new Set(["score", "ml_anomaly_score", "c2_proba", "iforest"]);
const SEVERITY = new Set(["score", "ml_anomaly_score"]);
const MONO = new Set(["ip", "src_ip", "dst_ip", "flow", "ja4_client", "ml_model",
                      "first_seen_us", "last_seen_us", "delta_us", "duration_us"]);
const UTC_TEXT = new Set(["time", "last_blocked"]);   // 'YYYY-MM-DD HH:MM:SS' in UTC

const state = { test: new URLSearchParams(location.search).get("test") || "latest",
  paused: false, data: null, openSql: new Set(), busy: false, testsKey: "" };

const fmtNum = (v) => Number(v).toLocaleString();
const fmtScore = (v) => (v < 0 ? "–" : v.toFixed(3));
const fmtWhen = (ms) => new Date(ms).toLocaleString([], { month: "short", day: "numeric",
  hour: "2-digit", minute: "2-digit", second: "2-digit" });
function fmtSpan(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h ? `${h}h ${p(m)}m ${p(s)}s` : m ? `${m}m ${p(s)}s` : `${s}s`;
}
function statusChip(kind, label) {
  const s = el("span", "status " + kind);
  s.append(el("span", "dot"), el("span", null, label));
  return s;
}
const panelId = (p) => ((p.title.match(/^(\w+)\./) || [])[1] || p.title);
const isNote = (p) => p.columns.length === 1 && p.columns[0] === "note";

function cell(col, v, maxima) {
  const td = el("td");
  if (v === null || v === undefined || v === "") { td.className = "muted"; td.textContent = "–"; return td; }
  if (col === "status") {
    td.append(statusChip(v === "active" ? "critical" : "neutral", v)); return td;
  }
  if (col === "action") {
    const kind = { "block": "critical", "error": "critical", "detected, not blocked": "warning" }[v] || "neutral";
    td.append(statusChip(kind, v)); return td;
  }
  if (col === "verdict") { td.append(statusChip(v === "OK" ? "good" : "critical", v)); return td; }
  if (col === "is_alert") {
    if (v) td.append(statusChip("warning", "alert")); else { td.className = "muted"; td.textContent = "–"; }
    return td;
  }
  if (SCORES.has(col) && typeof v === "number") {
    td.className = "num";
    if (SEVERITY.has(col) && v >= 0.8) td.append(statusChip(v >= 0.95 ? "critical" : "warning", fmtScore(v)));
    else td.textContent = fmtScore(v);
    return td;
  }
  if (UTC_TEXT.has(col) && typeof v === "string") {
    const d = new Date(v.replace(" ", "T") + "Z");
    td.textContent = isNaN(d) ? v : fmtWhen(d.getTime());
    return td;
  }
  if (col === "flows" && maxima.flows) {
    td.className = "num";
    const wrap = el("div", "barwrap"), track = el("span", "bartrack"), bar = el("span", "bar");
    bar.style.width = (100 * v / maxima.flows).toFixed(1) + "%";
    track.append(bar);
    wrap.append(el("span", null, fmtNum(v)), track);
    td.append(wrap);
    return td;
  }
  if (COUNTS.has(col)) { td.className = "num"; td.textContent = fmtNum(v); return td; }
  if (typeof v === "number") {
    td.className = "num" + (MONO.has(col) ? " mono" : "");
    td.textContent = Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
    return td;
  }
  td.textContent = String(v);
  if (MONO.has(col)) td.classList.add("mono");
  if (col === "detail" || col === "ndpi_risk_str") td.classList.add("wrap");
  return td;
}

function renderPanel(p, view) {
  const id = panelId(p);
  const [name, note] = PANEL_INFO[id] || [p.title, ""];
  const card = el("section", "card");
  card.id = "panel-" + id;
  const head = el("div", "card-head");
  head.append(el("h3", null, name), el("span", "badge", "panel " + id));
  if (!isNote(p)) head.append(el("span", "count", `${fmtNum(p.rows.length)} row${p.rows.length === 1 ? "" : "s"}`));
  card.append(head, el("p", "note", note));
  if (isNote(p)) {
    card.append(el("p", "empty", "No blocking data yet: start the daemon with --mitigate dry-run (or nftables)."));
  } else if (!p.rows.length) {
    card.append(el("p", "empty", view.selected === "all" ? "No rows yet." : "Nothing in this test yet."));
  } else {
    const maxima = {};
    const fi = p.columns.indexOf("flows");
    if (fi >= 0) maxima.flows = Math.max(...p.rows.map((r) => Number(r[fi]) || 0));
    const wrap = el("div", "table-wrap"), table = el("table"), thead = el("thead"), tr = el("tr");
    table.setAttribute("aria-label", name);
    p.columns.forEach((c, i) => {
      const th = el("th", null, LABELS[c] || c.replace(/_/g, " "));
      const sample = p.rows.find((r) => r[i] !== null && r[i] !== "");
      if (sample && typeof sample[i] === "number" && c !== "is_alert") th.className = "num";
      tr.append(th);
    });
    thead.append(tr);
    const tbody = el("tbody");
    for (const r of p.rows) {
      const row = el("tr");
      p.columns.forEach((c, i) => row.append(cell(c, r[i], maxima)));
      tbody.append(row);
    }
    table.append(thead, tbody);
    wrap.append(table);
    card.append(wrap);
  }
  const det = el("details", "sql");
  det.open = state.openSql.has(id);
  det.addEventListener("toggle", () => (det.open ? state.openSql.add(id) : state.openSql.delete(id)));
  det.append(el("summary", null, "SQL"), el("pre", null, p.sql));
  card.append(det);
  return card;
}

function renderKpis(d) {
  const s = d.summary;
  const blocks = d.panels.find((p) => panelId(p) === "6");
  let active = 0;
  if (blocks && !isNote(blocks)) {
    const si = blocks.columns.indexOf("status");
    active = blocks.rows.filter((r) => r[si] === "active").length;
  }
  const tiles = [
    ["Connections", s.flows, null],
    ["Alerts", s.alerts, s.alerts ? ["warning", "is_alert = 1"] : null],
    ["ML score ≥ 0.80", s.ml_score_ge_080, null],
    ["With an nDPI risk", s.risk_flows, null],
    ["Active blocks", active, active ? ["critical", "blocking now"] : null],
    ["Timestamp mismatches", s.timestamp_mismatches,
     s.timestamp_mismatches ? ["critical", "check the sensor"] : ["good", "all match"]],
  ];
  const box = $("#kpis");
  box.replaceChildren(...tiles.map(([label, value, st]) => {
    const t = el("div", "tile");
    t.append(el("div", "label", label), el("div", "value", fmtNum(value)));
    if (st) t.append(statusChip(st[0], st[1]));
    return t;
  }));
}

function renderTests(d) {
  const key = JSON.stringify(d.tests);
  const sel = $("#test-select");
  if (key !== state.testsKey) {
    state.testsKey = key;
    const opts = [...d.tests].reverse().map((t) =>
      new Option(`${t.id} · ${t.name} (${fmtWhen(t.start_us / 1000)})`, String(t.id)));
    opts.push(new Option("All flows", "all"));
    sel.replaceChildren(...opts);
  }
  sel.value = String(d.view.selected);
  const v = d.view;
  $("#view-name").textContent = v.selected === "all" ? "All flows" : `Test ${v.selected}: ${v.name}`;
  if (v.selected === "all") {
    $("#view-span").textContent = d.tests.length ? "everything stored, from all tests"
                                                 : "no tests started yet";
  } else if (v.end_us) {
    $("#view-span").textContent = `${fmtWhen(v.start_us / 1000)} → ${fmtWhen(v.end_us / 1000)}`;
  } else {
    $("#view-span").textContent = `started ${fmtWhen(v.start_us / 1000)}`;
  }
  tick();
}

function tick() {
  const v = state.data && state.data.view;
  const c = $("#view-clock");
  if (!v || v.selected === "all") { c.textContent = ""; return; }
  c.textContent = v.end_us ? `· lasted ${fmtSpan((v.end_us - v.start_us) / 1e6)}`
                           : `· running ${fmtSpan(Date.now() / 1000 - v.start_us / 1e6)}`;
}

function render(d) {
  const scorers = d.summary.scorers.join(", ") || "none yet";
  $("#meta").textContent = `${d.source} · scorer: ${scorers}`;
  renderTests(d);
  renderKpis(d);
  const byId = Object.fromEntries(d.panels.map((p) => [panelId(p), p]));
  const groups = $("#groups");
  groups.replaceChildren(...GROUPS.map(([title, ids, pair]) => {
    const g = el("section");
    g.append(el("h2", "group", title));
    const cards = el("div", "cards" + (pair ? " pair" : ""));
    ids.filter((id) => byId[id]).forEach((id) => cards.append(renderPanel(byId[id], d.view)));
    g.append(cards);
    return g;
  }));
}

function setError(msg) { const e = $("#error"); e.hidden = !msg; e.textContent = msg || ""; }
function setUrl() {
  const u = new URL(location.href);
  if (state.test === "latest") u.searchParams.delete("test"); else u.searchParams.set("test", state.test);
  history.replaceState(null, "", u);
  $("#json").href = "/api/panels.json?test=" + encodeURIComponent(state.test);
}

async function refresh() {
  if (state.busy) return;
  state.busy = true;
  const dim = setTimeout(() => document.body.classList.add("loading"), 300);
  try {
    const r = await fetch("/api/panels.json?test=" + encodeURIComponent(state.test), { cache: "no-store" });
    const d = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
    if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
    state.data = d;
    render(d);
    setError(null);
    $("#updated").textContent = `Updated ${new Date().toLocaleTimeString()} · every 10 s`;
  } catch (e) {
    setError(`Can't load the data (${e.message}). Showing the last data received.`);
  } finally {
    clearTimeout(dim);
    document.body.classList.remove("loading");
    state.busy = false;
  }
}

$("#test-select").addEventListener("change", (ev) => { state.test = ev.target.value; setUrl(); refresh(); });
$("#new-test").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#new-test button");
  btn.disabled = true;
  try {
    const r = await fetch("/api/tests", { method: "POST", headers: { "Content-Type": "application/json" },
                                          body: JSON.stringify({ name: $("#test-name").value }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    $("#test-name").value = "";
    state.test = "latest";
    setUrl();
    await refresh();
  } catch (e) {
    setError(`Couldn't start a test: ${e.message}`);
  } finally {
    btn.disabled = false;
  }
});
$("#pause").addEventListener("click", () => {
  state.paused = !state.paused;
  $("#pause").textContent = state.paused ? "Resume" : "Pause";
  if (!state.paused) refresh();
});
const THEMES = ["auto", "light", "dark"];
function applyTheme(t) {
  if (t === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  $("#theme").textContent = "Theme: " + t;
}
let theme = "auto";
try { theme = localStorage.getItem("sf-theme") || "auto"; } catch (e) { /* storage unavailable */ }
if (!THEMES.includes(theme)) theme = "auto";
applyTheme(theme);
$("#theme").addEventListener("click", () => {
  theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
  applyTheme(theme);
  try { localStorage.setItem("sf-theme", theme); } catch (e) { /* storage unavailable */ }
});

setUrl();
refresh();
setInterval(() => { if (!state.paused && !document.hidden) refresh(); }, 10000);
setInterval(tick, 1000);
</script>
</body>
</html>
"""


def serve(backend, host, port, test_log):
    page = PAGE.encode()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, indent=1).encode(), "application/json")

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/":
                return self._send(200, page, "text/html")
            if url.path == "/api/panels.json":
                test = urllib.parse.parse_qs(url.query).get("test", ["latest"])[0]
                try:
                    return self._json(200, collect(backend, test_log.load(), test))
                except Exception as ex:  # surface DB errors to the page
                    return self._json(500, {"error": str(ex)})
            self.send_error(404)

        def do_POST(self):
            if urllib.parse.urlsplit(self.path).path != "/api/tests":
                return self.send_error(404)
            # Only this page may start a test: the Origin must match, and a
            # cross-site form can't send JSON (that needs a preflight, which
            # this server never answers).
            origin = self.headers.get("Origin")
            if origin and urllib.parse.urlsplit(origin).netloc != self.headers.get("Host"):
                return self._json(403, {"error": "cross-origin request refused"})
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self._json(415, {"error": "expected application/json"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 4096:
                    return self._json(413, {"error": "request too large"})
                body = json.loads(self.rfile.read(n) or b"{}")
                test = test_log.add(body.get("name", "") if isinstance(body, dict) else "")
            except ValueError:
                return self._json(400, {"error": "invalid request"})
            except OSError as ex:
                return self._json(500, {"error": str(ex)})
            self.log_message('started test %d "%s"', test["id"], test["name"])
            return self._json(200, {"test": test})

        def log_message(self, f, *a):
            sys.stderr.write("[dashboard] " + (f % a) + "\n")

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        sys.exit(f"[dashboard] cannot listen on {host}:{port}: {e.strerror} "
                 f"(is another program using the port? try --port {port + 1})")
    print(f"[dashboard] serving {backend.label} on http://{host}:{port}/ "
          f"(tests: {test_log.path})", file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    ap = argparse.ArgumentParser(description="SentinelFlow dashboard (terminal or web page)")
    ap.add_argument("--backend", choices=["sqlite", "clickhouse"], default="sqlite")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--ch-url", default=os.environ.get("CLICKHOUSE_URL",
                                                       "http://localhost:8123"))
    ap.add_argument("--ch-user", default=os.environ.get("CLICKHOUSE_USER", "sentinel"))
    ap.add_argument("--ch-password", default=os.environ.get("CLICKHOUSE_PASSWORD",
                                                            "sentinel"))
    ap.add_argument("--show-sql", action="store_true")
    ap.add_argument("--json", action="store_true", help="print panels as JSON")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--test", default="latest", metavar="N|latest|all",
                    help="which test to show in the terminal / JSON (default: the latest)")
    ap.add_argument("--new-test", nargs="?", const="", metavar="NAME",
                    help="start a new test now (older flows are hidden, not deleted) and exit")
    ap.add_argument("--tests-file", help="where tests are saved "
                                         "(default: beside the database, *.tests.json)")
    args = ap.parse_args()

    tests_file = args.tests_file or (
        os.path.splitext(args.db)[0] + ".tests.json" if args.backend == "sqlite"
        else os.path.join(HERE, "data", "clickhouse.tests.json"))
    test_log = TestLog(tests_file)
    if args.new_test is not None:
        try:
            t = test_log.add(args.new_test)
        except OSError as e:
            sys.exit(str(e))
        print(f'Started test {t["id"]} "{t["name"]}" at {local_time(t["start_us"])}. '
              "The dashboard now shows only flows stored from now on; older ones are "
              "hidden, not deleted (--test all shows everything).")
        return

    backend = (SQLiteBackend(args.db) if args.backend == "sqlite" else
               ClickHouseBackend(args.ch_url, args.ch_user, args.ch_password))
    if args.serve:
        serve(backend, args.host, args.port, test_log)
    elif args.json:
        print(json.dumps(collect(backend, test_log.load(), args.test), indent=2))
    else:
        print_text(collect(backend, test_log.load(), args.test), args.show_sql)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Output piped into head/less, which exited early: stop quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
