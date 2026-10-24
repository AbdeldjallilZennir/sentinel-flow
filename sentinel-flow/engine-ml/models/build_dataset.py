#!/usr/bin/env python3
"""
SentinelFlow Phase 3 — build the labeled training set.

Every PCAP goes through the production path: `sensor -r` pushes JSON over
ZeroMQ to `zmq_sink`, and this script reads the sink's stdout. These are
the same bytes daemon.py ingests live, so training and inference see the
same feature source.

Sources and labels:
  * malware-traffic-analysis.net cases  (datasets/mta/, datasets/mta_labels.json)
      flow touches a curated malicious IP / domain -> malicious (1)
      flow touches a curated shared/legit service  -> ambiguous (-1, excluded)
      anything else in the capture                 -> benign background (0)
  * nDPI test corpus (~/nDPI/tests/cfgs/default/pcap), rules in NDPI_RULES
  * pcaps/ in this repo -> benign

Outputs (engine-ml/data/training/):
  flows_labeled.jsonl   23 sensor fields + label, label_name, family, source, pcap, group
  training.db           SQLite table training_flows (same columns)
  summary.json          counts per source / label / family
and, if ClickHouse is reachable, table sentinel.training_flows.

Usage:  python3 engine-ml/models/build_dataset.py [--no-clickhouse]
"""

import argparse
import collections
import glob
import json
import os
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(HERE)
ROOT = os.path.dirname(ENGINE)
sys.path.insert(0, ENGINE)
import daemon  # noqa: E402  (schema + validate)

SENSOR = os.path.join(ROOT, "sensor-c", "build", "sensor")
SINK = os.path.join(ROOT, "sensor-c", "build", "zmq_sink")
MTA_DIR = os.path.join(ENGINE, "datasets", "mta")
MTA_LABELS = os.path.join(ENGINE, "datasets", "mta_labels.json")
NDPI_DIR = os.path.expanduser("~/nDPI/tests/cfgs/default/pcap")
OUT = os.path.join(ENGINE, "data", "training")
ENDPOINT = "ipc:///tmp/sentinel_dataset_build.sock"

# Background/infrastructure protocols inside a malware capture: not C2 by
# themselves, so excluded (ambiguous) under the "non_infra" rule.
INFRA = {"DNS", "MDNS", "LLMNR", "NetBIOS", "SSDP", "DHCP", "DHCPV6", "NTP", "ICMP",
         "IGMP", "ICMPV6", "Kerberos", "LDAP", "SMBv23", "SMBv1", "RPC", "WSD"}

# nDPI corpus file rules (by file stem). Anything not listed is benign.
NDPI_RULES = {
    # malicious: whole capture is malware / tunnel traffic
    "malware": ("non_infra", "nDPI malware sample"),
    "emotet": ("non_infra", "Emotet"),
    "Emotet_infection_url_dga_positive": ("non_infra", "Emotet (DGA)"),
    "Emotet_infection_url_dga_negative": ("non_infra", "Emotet"),
    "trickbot": ("all", "TrickBot"),
    "websocket-chisel-ssh": ("all", "chisel tunnel"),
    "tls_malicious_sha1": ("all", "TLS cert on abuse.ch SSLBL"),
    "dns_exfiltration": ("all", "DNS exfiltration"),
    "dns-exf": ("all", "DNS exfiltration"),
    "dns-tunnel-iodine": ("all", "iodine DNS tunnel"),
    "dns2tcp_tunnel": ("all", "dns2tcp tunnel"),
    "icmp-tunnel": ("all", "ICMP tunnel"),
}
# Excluded: attacks that are not C2, anonymizers, and fuzzed/malformed input.
NDPI_EXCLUDE = re.compile(
    r"^(Webattack.*|sql_injection|xss|log4j-webapp-exploit|slowdos|slowloris|massscan|synscan|"
    r"tcp_scan|zmap|scanner|dos_win98_smb_netbeui|h323-overflow|exe_download.*|"
    r"portable_executable|elf|mining|monero|tor|tor-browser|psiphon3|ultrasurf|shadowsocks|"
    r"tls_heur__.*|fuzz-.*|ossfuzz_.*|malformed_.*|badpackets|bad-dns-traffic|reasm_.*|"
    r"ip_fragmented_garbage|dhcp-fuzz|kerberos_fuzz|quic-fuzz-overflow|tls-esni-fuzzed|"
    r"http-crash-content-disposition|README)$")


# ── Sensor -> ZMQ -> sink runner ─────────────────────────────────────────
class SensorRunner:
    """One long-lived zmq_sink; one sensor process per PCAP.

    The sensor drains its queue before exiting (ZMQ_LINGER) and a single
    PUSH->PULL pipe preserves order, so after `sensor` exits with
    "Flows exported: N" the next N sink lines belong to that PCAP.
    """

    def __init__(self):
        if os.path.exists(ENDPOINT[6:]):
            os.unlink(ENDPOINT[6:])
        # Buffered pipe: an unbuffered one makes Python read 1 byte per
        # syscall, which is slow enough to back up the ZMQ queues.
        self.sink = subprocess.Popen([SINK, ENDPOINT], stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
        self.q = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.sink.stdout:
            self.q.put(line)

    def run(self, pcap):
        # -A 0: one record per flow (no active-timeout snapshots), the
        # flow definition the Phase 3 models were trained on.
        p = subprocess.run([SENSOR, "-r", pcap, "-z", ENDPOINT, "-A", "0"],
                           capture_output=True, text=True, timeout=600)
        m = re.search(r"Flows exported:\s+(\d+)", p.stderr)
        d = re.search(r"Flows dropped:\s+(\d+)", p.stderr)
        if p.returncode != 0 or (d and int(d.group(1))):
            raise RuntimeError(f"sensor lost flows on {pcap}: exit {p.returncode}, "
                               f"{d.group(0) if d else 'no drop counter'}")
        n = int(m.group(1)) if m else 0
        rows = []
        for _ in range(n):
            raw = self.q.get(timeout=30)
            rows.append(json.loads(raw.decode("utf-8")))
        link = re.search(r"link type: (\S+)", p.stderr)
        return rows, (link.group(1) if link else "unsupported")

    def close(self):
        self.sink.terminate()
        self.sink.wait()


# ── MTA domain -> IP resolution (labeling only) ─────────────────────────
def capture_name_map(pcap):
    """{ip: {names}} from the capture's DNS answers, TLS SNI and HTTP Host."""
    names = collections.defaultdict(set)
    if not shutil.which("tshark"):
        return names
    queries = [
        ("dns.flags.response==1 && dns.a", ["dns.qry.name", "dns.a"], "answer"),
        ("tls.handshake.type==1", ["tls.handshake.extensions_server_name", "ip.dst"], "pair"),
        ("http.request", ["http.host", "ip.dst"], "pair"),
    ]
    for flt, fields, kind in queries:
        cmd = ["tshark", "-n", "-r", pcap, "-Y", flt, "-T", "fields", "-E", "separator=\t"]
        for f in fields:
            cmd += ["-e", f]
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2 or not parts[0] or not parts[1]:
                continue
            name = parts[0].split(",")[0].lower().rstrip(".")
            for ip in parts[1].split(","):
                names[ip.split(":")[0]].add(name)
    return names


def domain_match(name, domains):
    return any(name == d or name.endswith("." + d) for d in domains)


def mta_sources(labels):
    cases = labels["cases"]
    excluded = labels.get("exclude_pcaps", {})
    for case in sorted(os.listdir(MTA_DIR)):
        if case not in cases:
            print(f"[warn] MTA case {case} has no entry in mta_labels.json; skipped")
            continue
        for pcap in sorted(glob.glob(os.path.join(MTA_DIR, case, "*.pcap*"))):
            rel = f"{case}/{os.path.basename(pcap)}"
            if rel in excluded:
                print(f"[skip] {rel}: {excluded[rel]}")
                continue
            yield pcap, {"source": "mta", "group": f"mta:{case}", "rule": "mta",
                         "case": case, **cases[case]}


def ndpi_sources():
    if not os.path.isdir(NDPI_DIR):
        return
    for path in sorted(p for p in glob.glob(os.path.join(NDPI_DIR, "*"))
                       if p.endswith((".pcap", ".pcapng", ".cap"))):
        stem = os.path.basename(path).rsplit(".", 1)[0]
        if NDPI_EXCLUDE.match(stem):
            continue
        rule, family = NDPI_RULES.get(stem, ("benign", "nDPI corpus"))
        yield path, {"source": "ndpi", "group": f"ndpi:{stem}", "rule": rule, "family": family}


def repo_sources():
    for path in sorted(glob.glob(os.path.join(ROOT, "pcaps", "*.pcap*"))):
        yield path, {"source": "repo", "group": f"repo:{os.path.basename(path)}",
                     "rule": "benign", "family": "repo test pcap"}


def label_flow(r, meta, name_map):
    """Return (label, label_name, reason)."""
    rule = meta["rule"]
    master = r["app_protocol"].split(".")[0]
    if rule == "benign":
        return 0, "benign", "benign source"
    if rule == "all":
        return 1, "malicious", meta["family"]
    if rule == "non_infra":
        if master in INFRA:
            return -1, "ambiguous", f"{master} inside malware capture"
        return 1, "malicious", meta["family"]
    # rule == "mta": decide per endpoint
    mal_ips = set(meta.get("malicious_ips", []))
    amb_ips = set(meta.get("ambiguous_ips", []))
    mal_dom = meta.get("malicious_domains", [])
    amb_dom = meta.get("ambiguous_domains", [])
    for ip in (r["src_ip"], r["dst_ip"]):
        if ip in mal_ips:
            return 1, "malicious", f"IOC ip {ip}"
        hits = name_map.get(ip, ())
        for n in hits:
            if domain_match(n, mal_dom):
                return 1, "malicious", f"IOC domain {n} ({ip})"
    for ip in (r["src_ip"], r["dst_ip"]):
        if ip in amb_ips:
            return -1, "ambiguous", f"shared service ip {ip}"
        for n in name_map.get(ip, ()):
            if domain_match(n, amb_dom):
                return -1, "ambiguous", f"shared service {n} ({ip})"
    return 0, "benign", "background traffic in malware capture"


# ── Storage ──────────────────────────────────────────────────────────────
EXTRA = [("label", "INTEGER", "Int8"), ("label_name", "TEXT", "LowCardinality(String)"),
         ("label_reason", "TEXT", "String"), ("family", "TEXT", "LowCardinality(String)"),
         ("source", "TEXT", "LowCardinality(String)"), ("pcap", "TEXT", "String"),
         ("grp", "TEXT", "String")]
SENSOR_COLS = [n for n, _ in daemon.SENSOR_FIELDS]


def write_sqlite(rows, path):
    if os.path.exists(path):
        os.unlink(path)
    db = sqlite3.connect(path)
    types = {"ip": "TEXT", "str": "TEXT", "f64": "REAL"}
    cols = [f"{n} {types.get(k, 'INTEGER')}" for n, k in daemon.SENSOR_FIELDS]
    cols += [f"{n} {t}" for n, t, _ in EXTRA]
    db.execute(f"CREATE TABLE training_flows ({', '.join(cols)})")
    names = SENSOR_COLS + [n for n, _, _ in EXTRA]
    db.executemany(f"INSERT INTO training_flows VALUES ({','.join('?' * len(names))})",
                   [tuple(r[c] for c in names) for r in rows])
    db.commit()
    db.close()


def write_clickhouse(rows, url, user, password):
    hdr = {"X-ClickHouse-User": user, "X-ClickHouse-Key": password}

    def post(q, body=b""):
        req = urllib.request.Request(f"{url}/?{urllib.parse.urlencode({'query': q})}",
                                     data=body, headers=hdr, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    try:
        post("SELECT 1")
    except Exception as e:
        print(f"[clickhouse] not reachable ({e}); skipped")
        return False
    post("DROP TABLE IF EXISTS sentinel.training_flows")
    post("CREATE TABLE sentinel.training_flows AS sentinel.network_flows")
    # The training table has no enrichment columns; drop them, add labels.
    for c in ("ingested_at_us", "ml_anomaly_score", "is_alert", "ml_c2_proba",
              "ml_iforest_score", "ml_model"):
        post(f"ALTER TABLE sentinel.training_flows DROP COLUMN IF EXISTS {c}")
    for n, _, ch in EXTRA:
        post(f"ALTER TABLE sentinel.training_flows ADD COLUMN {n} {ch}")
    names = SENSOR_COLS + [n for n, _, _ in EXTRA]
    body = "".join(json.dumps({c: r[c] for c in names}) + "\n" for r in rows).encode()
    post("INSERT INTO sentinel.training_flows FORMAT JSONEachRow", body)
    n = post("SELECT count() FROM sentinel.training_flows").decode().strip()
    print(f"[clickhouse] sentinel.training_flows: {n} rows")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-clickhouse", action="store_true")
    ap.add_argument("--ch-url", default=os.environ.get("CLICKHOUSE_URL", "http://localhost:8123"))
    ap.add_argument("--ch-user", default=os.environ.get("CLICKHOUSE_USER", "sentinel"))
    ap.add_argument("--ch-password", default=os.environ.get("CLICKHOUSE_PASSWORD", "sentinel"))
    args = ap.parse_args()

    labels = json.load(open(MTA_LABELS))
    sources = list(mta_sources(labels)) + list(ndpi_sources()) + list(repo_sources())
    os.makedirs(OUT, exist_ok=True)
    env_ok = os.access(SENSOR, os.X_OK) and os.access(SINK, os.X_OK)
    if not env_ok:
        sys.exit("build sensor-c first (make sensor)")

    runner = SensorRunner()
    rows, per_pcap, rejected = [], [], 0
    try:
        for pcap, meta in sources:
            flows, link = runner.run(pcap)
            name_map = capture_name_map(pcap) if meta["rule"] == "mta" else {}
            counts = collections.Counter()
            for r in flows:
                try:
                    v = daemon.validate(r)
                except daemon.ValidationError:
                    rejected += 1
                    continue
                label, name, reason = label_flow(v, meta, name_map)
                v.update(label=label, label_name=name, label_reason=reason,
                         family=meta["family"] if label == 1 else
                         ("background" if meta["source"] == "mta" else meta["family"]),
                         source=meta["source"], pcap=os.path.basename(pcap), grp=meta["group"])
                rows.append(v)
                counts[name] += 1
            per_pcap.append({"pcap": os.path.basename(pcap), "group": meta["group"],
                             "source": meta["source"], "rule": meta["rule"], "link": link,
                             "flows": len(flows), **counts})
            if meta["source"] != "ndpi" or counts.get("malicious"):
                print(f"[{meta['source']}] {os.path.basename(pcap)}: {len(flows)} flows {dict(counts)}")
    finally:
        runner.close()

    with open(os.path.join(OUT, "flows_labeled.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    write_sqlite(rows, os.path.join(OUT, "training.db"))

    by = collections.Counter((r["source"], r["label_name"]) for r in rows)
    fam = collections.Counter(r["family"] for r in rows if r["label"] == 1)
    summary = {
        "pcaps": len(per_pcap),
        "pcaps_with_flows": sum(1 for p in per_pcap if p["flows"]),
        "flows": len(rows), "rejected_by_validation": rejected,
        "by_source_label": {f"{s}/{l}": n for (s, l), n in sorted(by.items())},
        "malicious_by_family": dict(fam.most_common()),
        "groups": {"benign": len({r["grp"] for r in rows if r["label"] == 0}),
                   "malicious": len({r["grp"] for r in rows if r["label"] == 1})},
        "per_pcap": per_pcap,
    }
    json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=2)
    print(json.dumps({k: v for k, v in summary.items() if k != "per_pcap"}, indent=2))
    if not args.no_clickhouse:
        write_clickhouse(rows, args.ch_url, args.ch_user, args.ch_password)


if __name__ == "__main__":
    main()
