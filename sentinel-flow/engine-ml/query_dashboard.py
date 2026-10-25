#!/usr/bin/env python3
"""
SentinelFlow Phase 2/3 — query dashboard (standard library only).

Runs seven panel queries against the ingested flows and prints them as
tables, or serves them as an auto-refreshing HTML page.

  ./query_dashboard.py                         # SQLite (engine-ml/data/...)
  ./query_dashboard.py --backend clickhouse    # same panels from ClickHouse
  ./query_dashboard.py --show-sql              # print each SQL query too
  ./query_dashboard.py --serve [--port 8080]   # http://127.0.0.1:8080/
"""

import argparse
import html
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "data", "sentinel_flows.db")

# Each panel: title + SQL per backend. SQLite table is `network_flows`,
# ClickHouse table is `sentinel.network_flows`; columns are identical.
PANELS = [
    {
        "title": "1. Protocol Breakdown",
        "sqlite": """\
SELECT app_protocol,
       COUNT(*)        AS flows,
       SUM(pkt_count)  AS packets,
       SUM(bytes_up)   AS bytes_up,
       SUM(bytes_down) AS bytes_down
FROM network_flows
GROUP BY app_protocol
ORDER BY flows DESC, app_protocol""",
        "clickhouse": """\
SELECT app_protocol,
       count()         AS flows,
       sum(pkt_count)  AS packets,
       sum(bytes_up)   AS bytes_up,
       sum(bytes_down) AS bytes_down
FROM sentinel.network_flows
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
      FROM network_flows
      WHERE ja4_client NOT IN ('', 'N/A')
      ORDER BY first_seen_us DESC
      LIMIT 100)
ORDER BY ja4_client, first_seen_us""",
        "clickhouse": """\
SELECT ja4_client, flow, app_protocol
FROM (SELECT ja4_client, first_seen_us, app_protocol,
             concat(src_ip, ':', toString(src_port), ' -> ',
                    dst_ip, ':', toString(dst_port)) AS flow
      FROM sentinel.network_flows
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
FROM network_flows
WHERE is_alert = 1
ORDER BY ml_anomaly_score DESC, first_seen_us
LIMIT 100""",
        "clickhouse": """\
SELECT ndpi_risk_mask, ndpi_risk_str, src_ip, dst_ip, app_protocol,
       ml_anomaly_score, is_alert
FROM sentinel.network_flows
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
FROM network_flows
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
FROM sentinel.network_flows
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
FROM network_flows
ORDER BY ml_anomaly_score DESC, first_seen_us
LIMIT 15""",
    "clickhouse": """\
SELECT concat(src_ip, ' -> ', dst_ip, ':', toString(dst_port)) AS flow,
       app_protocol, ja4_client,
       round(ml_anomaly_score, 3) AS score, round(ml_c2_proba, 3) AS c2_proba,
       round(ml_iforest_score, 3) AS iforest, is_alert, ml_model
FROM sentinel.network_flows
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
       datetime(first_blocked_us / 1000000, 'unixepoch') AS first_blocked
FROM (SELECT b.ip, b.backend, b.reason, b.score, b.flow, b.dropped_pkts,
             b.dropped_bytes, b.first_blocked_us,
             CASE WHEN b.status = 'active'
                       AND e.until_us < CAST(strftime('%s', 'now') AS INTEGER) * 1000000
                  THEN 'expired' ELSE b.status END AS status
      FROM blocked_ips b
      LEFT JOIN (SELECT ip, MAX(ts_us + timeout_s * 1000000) AS until_us
                 FROM mitigation_events
                 WHERE action IN ('block', 'counters')
                 GROUP BY ip) e ON e.ip = b.ip)
ORDER BY (status = 'active') DESC, dropped_pkts DESC, first_blocked_us, ip""",
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
       formatDateTime(toDateTime(intDiv(minIf(ts_us, action = 'block'), 1000000), 'UTC'),
                      '%Y-%m-%d %H:%i:%S') AS first_blocked
FROM sentinel.mitigations
WHERE ip != '' AND action IN ('block', 'counters', 'expire', 'unblock')
GROUP BY ip
ORDER BY (status = 'active') DESC, dropped_pkts DESC, minIf(ts_us, action = 'block'), ip""",
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
WHERE action != 'counters'
ORDER BY ts_us DESC
LIMIT 50""",
    "clickhouse": """\
SELECT formatDateTime(toDateTime(intDiv(ts_us, 1000000), 'UTC'), '%Y-%m-%d %H:%i:%S') AS time,
       if(action = 'skip_protected', 'detected, not blocked', action) AS action,
       reason, ip, detail, flow, round(score, 3) AS score
FROM sentinel.mitigations
WHERE action != 'counters'
ORDER BY ts_us DESC
LIMIT 50""",
})

SUMMARY = {
    "sqlite": """\
SELECT COUNT(*), SUM(is_alert), SUM(ndpi_risk_mask > 0),
       SUM(last_seen_us - first_seen_us
           != CAST(ROUND(flow_duration_ms * 1000) AS INTEGER)),
       SUM(ml_anomaly_score >= 0.8), GROUP_CONCAT(DISTINCT ml_model)
FROM network_flows""",
    "clickhouse": """\
SELECT count(), sum(is_alert), countIf(ndpi_risk_mask > 0),
       countIf(toInt64(last_seen_us) - toInt64(first_seen_us)
               != toInt64(round(flow_duration_ms * 1000))),
       countIf(ml_anomaly_score >= 0.8), arrayStringConcat(groupUniqArray(ml_model), ',')
FROM sentinel.network_flows""",
}


# ── Backends: run(sql) -> (column_names, rows) ────────────────────────────
class SQLiteBackend:
    key = "sqlite"

    def __init__(self, path):
        if not os.path.exists(path):
            sys.exit(f"database not found: {path} (run daemon.py first)")
        self.path = path
        self.label = f"SQLite {os.path.relpath(path)}"

    def run(self, sql):
        # Read-only connection per query: safe under a live WAL writer.
        uri = f"file:{urllib.parse.quote(self.path)}?mode=ro"
        try:
            return self._query(uri, sql)
        except sqlite3.OperationalError as e:
            # A WAL database needs a -shm file beside it. When the daemon has
            # stopped (it removes that file) and this user can't create it,
            # e.g. the daemon ran as root and owns the folder, read the file as
            # a fixed snapshot instead. Nothing is writing to it at that point.
            if "readonly" not in str(e) and "unable to open" not in str(e):
                raise
            return self._query(uri + "&immutable=1", sql)

    @staticmethod
    def _query(uri, sql):
        db = sqlite3.connect(uri, uri=True)
        try:
            cur = db.execute(sql)
            return [d[0] for d in cur.description], cur.fetchall()
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


def collect(backend):
    total, alerts, risky, mismatches, ml_hits, models = backend.run(SUMMARY[backend.key])[1][0]
    panels = []
    for p in PANELS:
        try:
            cols, rows = backend.run(p[backend.key])
        except Exception as e:
            if "optional_table" not in p:
                raise
            # Phase 4 tables exist only after a daemon run with --mitigate.
            cols, rows = ["note"], [(f"no mitigation data yet: {p['optional_table']} "
                                     f"({type(e).__name__})",)]
        panels.append({"title": p["title"], "sql": p[backend.key],
                       "columns": cols, "rows": rows})
    return {"source": backend.label,
            "summary": {"flows": total or 0, "alerts": alerts or 0,
                        "risk_flows": risky or 0,
                        "timestamp_mismatches": mismatches or 0,
                        "ml_score_ge_080": ml_hits or 0,
                        "scorers": sorted(set((models or "").split(",")) - {""})},
            "panels": panels}


def print_text(data, show_sql):
    s = data["summary"]
    print(f"SentinelFlow Phase 2/3 — {data['source']}")
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


def render_html(data):
    e = html.escape
    s = data["summary"]
    parts = [f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="10"><title>SentinelFlow Phase 2/3</title>
<style>
body{{font:14px system-ui,sans-serif;margin:24px;background:#0f1419;color:#d6dde6}}
h1{{font-size:20px}} h2{{font-size:16px;margin-top:28px}}
.kpi{{display:flex;gap:16px;flex-wrap:wrap}}
.kpi div{{background:#1a2129;padding:10px 16px;border-radius:6px}}
.kpi b{{display:block;font-size:22px}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse}}
th,td{{padding:4px 10px;border-bottom:1px solid #2a333d;text-align:left;
white-space:nowrap;font-family:ui-monospace,monospace;font-size:12px}}
th{{color:#8fa3b8}} .bad{{color:#ff6b6b}} .ok{{color:#5fd38d}}
details{{margin:4px 0}} pre{{background:#1a2129;padding:8px;border-radius:4px}}
</style></head><body><h1>SentinelFlow Phase 2/3</h1>
<p>Source: {e(data['source'])} · refreshes every 10 s · <a style="color:#7ab7ff"
href="/api/panels.json">JSON</a></p><div class="kpi">
<div><b>{s['flows']}</b>flows</div><div><b>{s['alerts']}</b>is_alert = 1</div>
<div><b>{s['risk_flows']}</b>ndpi_risk_mask &gt; 0</div>
<div><b>{s['timestamp_mismatches']}</b>timestamp mismatches</div>
<div><b>{s['ml_score_ge_080']}</b>ML score &ge; 0.80</div></div>
<p>Scorer: {e(', '.join(s['scorers']))}</p>"""]
    for p in data["panels"]:
        parts.append(f"<h2>{e(p['title'])}</h2><details><summary>SQL</summary>"
                     f"<pre>{e(p['sql'])}</pre></details><div class='wrap'><table><tr>")
        parts += [f"<th>{e(c)}</th>" for c in p["columns"]]
        parts.append("</tr>")
        for r in p["rows"]:
            parts.append("<tr>")
            for c, v in zip(p["columns"], r):
                cls = (" class='ok'" if v == "OK" else " class='bad'"
                       if v == "MISMATCH" else "")
                parts.append(f"<td{cls}>{e(fmt(v))}</td>")
            parts.append("</tr>")
        if not p["rows"]:
            parts.append(f"<tr><td colspan='{len(p['columns'])}'>(no rows)</td></tr>")
        parts.append("</table></div>")
    parts.append("</body></html>")
    return "".join(parts)


def serve(backend, host, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            try:
                if path == "/":
                    body, ctype = render_html(collect(backend)).encode(), "text/html"
                elif path == "/api/panels.json":
                    body = json.dumps(collect(backend), indent=2).encode()
                    ctype = "application/json"
                else:
                    self.send_error(404)
                    return
            except Exception as ex:  # surface DB errors to the browser
                self.send_error(500, str(ex))
                return
            self.send_response(200)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, f, *a):
            sys.stderr.write("[dashboard] " + (f % a) + "\n")

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        sys.exit(f"[dashboard] cannot listen on {host}:{port}: {e.strerror} "
                 f"(is another program using the port? try --port {port + 1})")
    print(f"[dashboard] serving {backend.label} on http://{host}:{port}/",
          file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    ap = argparse.ArgumentParser(description="SentinelFlow Phase 2 query dashboard")
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
    args = ap.parse_args()

    backend = (SQLiteBackend(args.db) if args.backend == "sqlite" else
               ClickHouseBackend(args.ch_url, args.ch_user, args.ch_password))
    if args.serve:
        serve(backend, args.host, args.port)
    elif args.json:
        print(json.dumps(collect(backend), indent=2))
    else:
        print_text(collect(backend), args.show_sql)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Output piped into head/less, which exited early: stop quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
