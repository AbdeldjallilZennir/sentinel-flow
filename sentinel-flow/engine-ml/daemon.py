#!/usr/bin/env python3
"""
SentinelFlow Phase 2/3 — ingestion & scoring daemon.

Receives the 23-field flow JSON that `sensor` pushes over ZeroMQ, validates
it, scores each batch (Phase 3: ONNX LightGBM + IsolationForest, falling
back to the Phase 2 heuristic when onnxruntime or the models are missing),
adds the enrichment columns, and writes batches to:

  * SQLite  (engine-ml/data/sentinel_flows.db, WAL mode)   — always on
  * JSONL   (engine-ml/data/flows.jsonl)                    — always on
  * ClickHouse over HTTP (sentinel.network_flows)           — when reachable

Standard library only. Transport:

  1. `import zmq` works  -> bind a PULL socket directly (pyzmq).
  2. otherwise           -> spawn sensor-c/build/zmq_sink (C, libzmq) and
                            read its newline-delimited JSON from stdout.
  3. --from-jsonl FILE   -> read records from a file instead (replay/backfill).

Scoring (--scorer auto|onnx|heuristic, default auto):
  onnx       models/c2_detector.onnx + models/anomaly_iforest.onnx, verified
             against models/model_meta.json (SHA-256, feature list)
  heuristic  Phase 2 noisy-OR baseline, stdlib only

Usage:
  ./daemon.py                              # auto transport, auto backends
  ./daemon.py --max-messages 12            # exit after 12 accepted flows
  ./daemon.py --from-jsonl data/flows.jsonl --backend clickhouse   # backfill
"""

import argparse
import ipaddress
import json
import os
import queue
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:          # features.py lives next to this file
    sys.path.insert(0, HERE)
DEFAULT_ENDPOINT = "ipc:///tmp/ndpi_flows.sock"
DEFAULT_SINK = os.path.join(HERE, "..", "sensor-c", "build", "zmq_sink")
DEFAULT_DATA = os.path.join(HERE, "data")

# ── Schema ────────────────────────────────────────────────────────────────
# (name, kind) in sensor emission order. Kinds:
#   ip   – IPv4/IPv6 string      str  – any string
#   u8 / u16 / u64 – unsigned int  f64 – finite number (int accepted)
SENSOR_FIELDS = [
    ("src_ip", "ip"), ("dst_ip", "ip"),
    ("src_port", "u16"), ("dst_port", "u16"),
    ("protocol", "u8"),
    ("app_protocol", "str"), ("ja4_client", "str"),
    ("ndpi_risk_mask", "u64"), ("ndpi_risk_str", "str"),
    ("pkt_count", "u64"), ("bytes_up", "u64"), ("bytes_down", "u64"),
    ("flow_duration_ms", "f64"),
    ("iat_mean", "f64"), ("iat_stddev", "f64"),
    ("iat_min", "f64"), ("iat_max", "f64"),
    ("pkt_len_mean", "f64"), ("pkt_len_stddev", "f64"),
    ("bytes_up_down_ratio", "f64"), ("small_pkt_ratio", "f64"),
    ("first_seen_us", "u64"), ("last_seen_us", "u64"),
]
ENRICH_FIELDS = [("ingested_at_us", "u64"), ("ml_anomaly_score", "f64"),
                 ("is_alert", "u8"),
                 # Phase 3: raw model outputs and which scorer produced them.
                 # -1.0 = not computed (heuristic scorer).
                 ("ml_c2_proba", "f64"), ("ml_iforest_score", "f64"),
                 ("ml_model", "str")]
ENRICH_DEFAULTS = {"ml_c2_proba": -1.0, "ml_iforest_score": -1.0, "ml_model": ""}
ALL_FIELDS = SENSOR_FIELDS + ENRICH_FIELDS
COLUMNS = [n for n, _ in ALL_FIELDS]

# u64 fields are capped at 2^63 - 1: SQLite stores signed 64-bit integers,
# so a larger value would pass validation and then crash the write.
_UMAX = {"u8": 0xFF, "u16": 0xFFFF, "u64": 0x7FFFFFFFFFFFFFFF}
ALERT_THRESHOLD = 0.80


class ValidationError(ValueError):
    pass


# What one bad record can raise; it is rejected, the daemon keeps running.
# json.loads raises RecursionError (not a ValueError) on deeply nested input.
BAD_RECORD = (ValueError, RecursionError)


def validate(rec):
    """Return a clean dict with exactly the 23 sensor fields, or raise."""
    if not isinstance(rec, dict):
        raise ValidationError("record is not a JSON object")
    missing = [n for n, _ in SENSOR_FIELDS if n not in rec]
    if missing:
        raise ValidationError("missing fields: " + ",".join(missing))
    out = {}
    for name, kind in SENSOR_FIELDS:
        v = rec[name]
        if kind in ("str", "ip"):
            if not isinstance(v, str):
                raise ValidationError(f"{name}: expected string")
            if kind == "ip":
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValidationError(f"{name}: invalid IP {v!r}")
        elif kind in _UMAX:
            # bool is a subclass of int; reject it explicitly.
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValidationError(f"{name}: expected integer")
            if isinstance(v, float):
                if not v.is_integer():
                    raise ValidationError(f"{name}: non-integer {v}")
                v = int(v)
            if not 0 <= v <= _UMAX[kind]:
                raise ValidationError(f"{name}: {v} out of range for {kind}")
        else:  # f64
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValidationError(f"{name}: expected number")
            try:
                v = float(v)
            except OverflowError:            # a JSON integer too big for a float
                raise ValidationError(f"{name}: not finite") from None
            if v != v or v in (float("inf"), float("-inf")):
                raise ValidationError(f"{name}: not finite")
        out[name] = v
    if out["last_seen_us"] < out["first_seen_us"]:
        raise ValidationError("last_seen_us < first_seen_us")
    if out["pkt_count"] == 0:
        raise ValidationError("pkt_count is 0")
    return out


# ── Phase 2 baseline score ────────────────────────────────────────────────
# Noisy-OR over independent behavioural signals: score = 1 - Π(1 - w_i).
# This is a placeholder heuristic, NOT a trained model. Phase 3 replaces
# heuristic_score() with ONNX inference; the column and alert rule stay.
# Weights are chosen so the beacon-like triple (unknown protocol +
# unidirectional + periodic IAT) scores 0.805 >= 0.80, while no pair of
# behavioural signals alone reaches the alert threshold.
STANDARD_PORTS = {"TLS": {443, 8443, 993, 995, 465, 853},
                  "HTTP": {80, 8080, 8000, 3128}}


def score_signals(f):
    sig = []
    if f["ndpi_risk_mask"] > 0:
        sig.append(("ndpi_risk", 0.40))
    master = f["app_protocol"].split(".")[0]
    if master in ("Unknown", ""):
        sig.append(("unknown_protocol", 0.40))
    if f["pkt_count"] >= 3 and (f["bytes_up"] == 0 or f["bytes_down"] == 0):
        sig.append(("unidirectional", 0.35))
    if f["pkt_count"] >= 6 and f["iat_mean"] > 0 and \
            f["iat_stddev"] / f["iat_mean"] < 0.20:
        sig.append(("periodic_iat", 0.50))
    if f["bytes_down"] > 0 and f["bytes_up_down_ratio"] > 10.0:
        sig.append(("upload_heavy", 0.25))
    if master in STANDARD_PORTS and \
            f["dst_port"] not in STANDARD_PORTS[master] and \
            f["src_port"] not in STANDARD_PORTS[master]:
        sig.append(("nonstandard_port", 0.20))
    return sig


def heuristic_score(f):
    p = 1.0
    for _, w in score_signals(f):
        p *= (1.0 - w)
    return round(1.0 - p, 4)


# ── Scorers (Phase 3) ─────────────────────────────────────────────────────
MODELS_DIR = os.path.join(HERE, "models")
HEURISTIC_VERSION = "heuristic_v1"


class HeuristicScorer:
    name = HEURISTIC_VERSION

    def score(self, batch):
        for f in batch:
            f["ml_anomaly_score"] = heuristic_score(f)
            f["ml_c2_proba"] = -1.0
            f["ml_iforest_score"] = -1.0
            f["ml_model"] = HEURISTIC_VERSION


class OnnxScorer:
    """LightGBM P(malicious) + IsolationForest anomaly, via onnxruntime.

    ml_c2_proba      raw LightGBM probability
    ml_anomaly_score LightGBM probability mapped so 0.80 = the training
                     run's 1% out-of-fold benign false-positive point
    ml_iforest_score IsolationForest anomaly mapped so 0.80 = 99.5th
                     percentile of benign training flows (informational;
                     not part of the alert score, see model_meta.json)
    """

    def __init__(self, models_dir=MODELS_DIR):
        import hashlib
        import numpy as np
        import onnxruntime as ort
        import features
        self.np, self.features = np, features
        meta_path = os.path.join(models_dir, "model_meta.json")
        with open(meta_path) as fh:
            meta = json.load(fh)
        if meta["feature_version"] != features.FEATURE_VERSION or \
                meta["feature_names"] != features.FEATURE_NAMES:
            raise RuntimeError("model_meta.json feature list does not match features.py")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.log_severity_level = 3          # hide shape-hint warnings
        self.sessions = {}
        for key in ("lgbm", "iforest"):
            path = os.path.join(models_dir, meta[key]["file"])
            with open(path, "rb") as fh:
                blob = fh.read()
            if hashlib.sha256(blob).hexdigest() != meta[key]["sha256"]:
                raise RuntimeError(f"{meta[key]['file']}: SHA-256 does not match model_meta.json")
            self.sessions[key] = ort.InferenceSession(blob, opts,
                                                      providers=["CPUExecutionProvider"])
        self.meta = meta
        self.name = meta["model_version"]
        self.input = meta["input_name"]

    def _lgbm_norm(self, p):
        cal = self.meta["lgbm_calibration"]
        t, a = cal["raw_threshold"], cal["maps_to"]
        np = self.np
        return np.clip(np.where(p < t, a * p / t, a + (1 - a) * (p - t) / (1 - t)), 0, 1)

    def _if_norm(self, raw):
        cal = self.meta["iforest"]["calibration"]
        span = max(cal["q995"] - cal["q50"], 1e-9)
        return self.np.clip(cal["at_q995"] * (raw - cal["q50"]) / span, 0, 1)

    def score(self, batch):
        if not batch:
            return
        np = self.np
        X = np.array([self.features.extract(f) for f in batch], dtype=np.float32)
        lg = self.meta["lgbm"]
        p = self.sessions["lgbm"].run([lg["output"]], {self.input: X})[0][:, lg["column"]]
        s = self.sessions["iforest"].run([self.meta["iforest"]["output"]],
                                         {self.input: X})[0].reshape(-1)
        cal_p, if_n = self._lgbm_norm(p.astype(np.float64)), self._if_norm(-s.astype(np.float64))
        for f, a, b, c in zip(batch, cal_p, p, if_n):
            f["ml_anomaly_score"] = round(float(a), 6)
            f["ml_c2_proba"] = round(float(b), 6)
            f["ml_iforest_score"] = round(float(c), 6)
            f["ml_model"] = self.name


def make_scorer(kind, models_dir=MODELS_DIR, log_fn=None):
    if kind in ("auto", "onnx"):
        try:
            return OnnxScorer(models_dir)
        except Exception as e:   # ImportError, missing/corrupt model, mismatch
            if kind == "onnx":
                raise
            if log_fn:
                log_fn(f"scorer: ONNX unavailable ({type(e).__name__}: {e}); "
                       f"using {HEURISTIC_VERSION}")
    return HeuristicScorer()


def alert(f, risk_policy="any"):
    """is_alert = risk part OR ml_anomaly_score >= 0.80.

    risk_policy: any    -> any nDPI risk bit (Phase 2 rule, default)
                 severe -> only risks in features.SEVERE_MASK
                 none   -> ML score only
    """
    mask = f["ndpi_risk_mask"]
    if risk_policy == "any":
        risky = mask > 0
    elif risk_policy == "severe":
        import features
        risky = (mask & features.SEVERE_MASK) != 0
    else:
        risky = False
    f["is_alert"] = 1 if (risky or f["ml_anomaly_score"] >= ALERT_THRESHOLD) else 0
    return f


def stamp(f, now_us=None):
    f["ingested_at_us"] = now_us if now_us is not None else time.time_ns() // 1000
    return f


def finalize(batch, scorer, risk_policy="any"):
    scorer.score(batch)
    for f in batch:
        alert(f, risk_policy)
    return batch


def enrich(f, now_us=None, scorer=None, risk_policy="any"):
    """Single-record convenience wrapper (tests, tools)."""
    stamp(f, now_us)
    finalize([f], scorer or HeuristicScorer(), risk_policy)
    return f


# ── Storage backends ──────────────────────────────────────────────────────
_SQLITE_TYPES = {"ip": "TEXT", "str": "TEXT", "u8": "INTEGER",
                 "u16": "INTEGER", "u64": "INTEGER", "f64": "REAL"}


class SQLiteStore:
    name = "sqlite"

    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        cols = ",\n  ".join(f"{n} {_SQLITE_TYPES[k]} NOT NULL"
                            for n, k in ALL_FIELDS)
        self.db.execute(f"CREATE TABLE IF NOT EXISTS network_flows (\n  {cols}\n)")
        # Migrate tables created by Phase 2 (no ml_c2_proba etc.).
        have = {r[1] for r in self.db.execute("PRAGMA table_info(network_flows)")}
        for n, k in ENRICH_FIELDS:
            if n not in have:
                default = ENRICH_DEFAULTS[n]
                self.db.execute(f"ALTER TABLE network_flows ADD COLUMN {n} "
                                f"{_SQLITE_TYPES[k]} NOT NULL DEFAULT {default!r}")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_flows_order "
                        "ON network_flows(first_seen_us, app_protocol, src_ip)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_flows_alert "
                        "ON network_flows(is_alert)")
        self.db.commit()
        self._sql = (f"INSERT INTO network_flows ({','.join(COLUMNS)}) "
                     f"VALUES ({','.join('?' * len(COLUMNS))})")

    def write(self, batch):
        # sqlite3 binds Python ints as signed 64-bit; risk masks use < 2^63.
        rows = [tuple(r[c] for c in COLUMNS) for r in batch]
        with self.db:
            self.db.executemany(self._sql, rows)

    def close(self):
        self.db.close()


class JSONLStore:
    name = "jsonl"

    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.fh = open(path, "a", buffering=1)

    def write(self, batch):
        self.fh.write("".join(json.dumps(r, separators=(",", ":")) + "\n"
                              for r in batch))
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self):
        self.fh.close()


class ClickHouseStore:
    """ClickHouse HTTP interface via urllib; JSONEachRow inserts."""
    name = "clickhouse"

    def __init__(self, url, table, user=None, password=None, timeout=5.0):
        self.url = url.rstrip("/")
        self.table = table
        self.timeout = timeout
        self.headers = {}
        if user:
            self.headers["X-ClickHouse-User"] = user
        if password:
            self.headers["X-ClickHouse-Key"] = password

    def _post(self, query, body=b""):
        qs = urllib.parse.urlencode({"query": query})
        req = urllib.request.Request(f"{self.url}/?{qs}", data=body,
                                     headers=self.headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode()

    def ping(self):
        try:
            req = urllib.request.Request(f"{self.url}/ping")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                if r.read().strip() != b"Ok.":
                    return False
            if self._post(f"EXISTS TABLE {self.table}").strip() != "1":
                return False
            # Idempotent migration for tables created by the Phase 2 schema.
            for col, typ, default in (("ml_c2_proba", "Float64", "-1"),
                                      ("ml_iforest_score", "Float64", "-1"),
                                      ("ml_model", "LowCardinality(String)", "''")):
                self._post(f"ALTER TABLE {self.table} ADD COLUMN IF NOT EXISTS "
                           f"{col} {typ} DEFAULT {default}")
            return True
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def write(self, batch):
        body = "".join(json.dumps(r, separators=(",", ":")) + "\n"
                       for r in batch).encode()
        try:
            self._post(f"INSERT INTO {self.table} FORMAT JSONEachRow", body)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace").strip()
            raise RuntimeError(f"HTTP {e.code}: {detail[:300]}") from None

    def close(self):
        pass


# ── Transports (each feeds raw JSON lines into a queue) ───────────────────
EOF = object()


def _unlink_stale_ipc(endpoint):
    if endpoint.startswith("ipc://"):
        path = endpoint[len("ipc://"):]
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                os.unlink(path)
        except FileNotFoundError:
            pass


class PyZMQTransport:
    name = "pyzmq"

    def __init__(self, endpoint, q, stop):
        import zmq  # noqa: F401  (import checked by caller)
        self.zmq = zmq
        self.ctx = zmq.Context()
        self.sock = self.ctx.socket(zmq.PULL)
        self.sock.setsockopt(zmq.LINGER, 0)
        # Unlimited receive queue: with a bounded one, messages in transit
        # when the sensor disconnects are discarded (see docs/REPORT.md, Part 3).
        self.sock.setsockopt(zmq.RCVHWM, 0)
        _unlink_stale_ipc(endpoint)
        self.sock.bind(endpoint)
        self.q, self.stop = q, stop
        self.t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.t.start()

    def _run(self):
        poller = self.zmq.Poller()
        poller.register(self.sock, self.zmq.POLLIN)
        while not self.stop.is_set():
            if poller.poll(200):
                self.q.put(self.sock.recv().decode("utf-8", "replace"))
        self.q.put(EOF)

    def close(self):
        self.sock.close()
        self.ctx.term()


class ZmqSinkTransport:
    name = "zmq_sink"

    def __init__(self, endpoint, q, stop, sink_path):
        sink_path = os.path.abspath(sink_path)
        if not os.access(sink_path, os.X_OK):
            raise RuntimeError(f"zmq_sink not executable: {sink_path} "
                               "(build it with `make` first)")
        _unlink_stale_ipc(endpoint)
        # zmq_sink takes the endpoint as its positional argument.
        self.proc = subprocess.Popen([sink_path, endpoint],
                                     stdout=subprocess.PIPE, stderr=sys.stderr,
                                     text=True, bufsize=1)
        self.q, self.stop = q, stop
        self.t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.t.start()

    def _run(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self.q.put(line)
        self.q.put(EOF)  # child exited

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class FileTransport:
    name = "jsonl-file"

    def __init__(self, path, q, stop):
        self.path, self.q, self.stop = path, q, stop
        self.t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.t.start()

    def _run(self):
        fh = sys.stdin if self.path == "-" else open(self.path)
        for line in fh:
            if self.stop.is_set():
                break
            if line.strip():
                self.q.put(line.strip())
        self.q.put(EOF)

    def close(self):
        pass


# ── Daemon ────────────────────────────────────────────────────────────────
def log(msg):
    print(f"[daemon] {msg}", file=sys.stderr, flush=True)


def build_backends(args):
    stores = []
    if args.backend in ("auto", "sqlite", "both"):
        stores.append(SQLiteStore(args.db))
        stores.append(JSONLStore(args.jsonl))
    ch = None
    if args.backend in ("auto", "clickhouse", "both"):
        ch = ClickHouseStore(args.ch_url, args.ch_table,
                             args.ch_user, args.ch_password)
        if ch.ping():
            stores.append(ch)
            log(f"clickhouse: {args.ch_url} table {args.ch_table} reachable")
        elif args.backend == "auto":
            log(f"clickhouse: {args.ch_url} not reachable — SQLite/JSONL only "
                "(re-probed every 30 s)")
        else:
            log(f"clickhouse: {args.ch_url} / {args.ch_table} not reachable")
            sys.exit(2)
    return stores, ch


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("-e", "--endpoint", default=DEFAULT_ENDPOINT)
    ap.add_argument("--transport", choices=["auto", "pyzmq", "zmq_sink"],
                    default="auto")
    ap.add_argument("--zmq-sink", default=DEFAULT_SINK)
    ap.add_argument("--from-jsonl", metavar="FILE",
                    help="read records from FILE ('-' = stdin) instead of ZMQ")
    ap.add_argument("--backend", choices=["auto", "sqlite", "clickhouse", "both"],
                    default="auto",
                    help="auto: SQLite+JSONL always, ClickHouse if reachable\n"
                         "both: SQLite+JSONL+ClickHouse, fail if CH is down")
    ap.add_argument("--db", default=os.path.join(DEFAULT_DATA, "sentinel_flows.db"))
    ap.add_argument("--jsonl", default=os.path.join(DEFAULT_DATA, "flows.jsonl"))
    ap.add_argument("--rejected", default=os.path.join(DEFAULT_DATA, "rejected.jsonl"))
    ap.add_argument("--ch-url", default=os.environ.get("CLICKHOUSE_URL",
                                                       "http://localhost:8123"))
    ap.add_argument("--ch-table", default="sentinel.network_flows")
    ap.add_argument("--ch-user", default=os.environ.get("CLICKHOUSE_USER", "sentinel"))
    ap.add_argument("--ch-password", default=os.environ.get("CLICKHOUSE_PASSWORD",
                                                            "sentinel"))
    ap.add_argument("--batch-size", type=int, default=1000,
                    help="rows per write (README: 1,000 rows or 1 s)")
    ap.add_argument("--scorer", choices=["auto", "onnx", "heuristic"], default="auto")
    ap.add_argument("--models-dir", default=MODELS_DIR)
    ap.add_argument("--alert-risk-policy", choices=["any", "severe", "none"], default="severe",
                    help="which nDPI risks raise is_alert on their own (default severe; "
                         "'any' is the Phase 2 rule, which fires on ~18%% of benign flows, "
                         "see docs/REPORT.md, Part 3 section 8.4)")
    mg = ap.add_argument_group("Phase 4 mitigation (see mitigator.py)")
    mg.add_argument("--mitigate", choices=["none", "dry-run", "nftables"], default="none",
                    help="block remote endpoints per IP: one flow >= --block-high-score, "
                         "--block-repeat flows >= 0.80, severe nDPI risk, or a scan (see mitigator.py)")
    mg.add_argument("--mitigate-netns", help="apply nftables inside this network namespace")
    mg.add_argument("--block-timeout", type=int, default=900, help="seconds (default 15 min)")
    mg.add_argument("--protected-cidr", action="append",
                    help="never block these (repeatable / comma list; default RFC 1918 + 127/8)")
    mg.add_argument("--allow-private-blocks", action="store_true",
                    help="drop RFC 1918 from the protected list (lab tests)")
    mg.add_argument("--allowlist", action="append", default=[], help="IPs/CIDRs never blocked")
    mg.add_argument("--allowlist-file", help="file of IPs/CIDRs never blocked (one per line, # comments)")
    mg.add_argument("--no-severe-risk-blocks", action="store_true",
                    help="block on the ML score only")
    mg.add_argument("--block-high-score", type=float, default=0.95,
                    help="one flow at or above this score blocks its remote IP (default 0.95)")
    mg.add_argument("--block-repeat", type=int, default=2,
                    help="flows >= 0.80 to one remote IP that block it (default 2; "
                         "1 with --block-high-score 0.80 = old per-flow rule)")
    mg.add_argument("--block-repeat-window", type=float, default=3600,
                    help="seconds in which --block-repeat flows must occur (default 3600)")
    mg.add_argument("--scan-ports", type=int, default=50,
                    help="distinct ports on one host from one source within --scan-window "
                         "that count as a port scan (default 50; 0 = off)")
    mg.add_argument("--sweep-hosts", type=int, default=100,
                    help="distinct hosts on one port from one source (short flows) within "
                         "--scan-window that count as a host sweep (default 100; 0 = off)")
    mg.add_argument("--scan-window", type=float, default=60, help="seconds (default 60)")
    mg.add_argument("--mitigations-jsonl", default=os.path.join(DEFAULT_DATA, "mitigations.jsonl"))
    ap.add_argument("--flush-interval", type=float, default=1.0,
                    help="seconds before a partial batch is written")
    ap.add_argument("--max-messages", type=int, default=0,
                    help="exit after this many accepted flows (0 = run forever)")
    args = ap.parse_args()

    stop = threading.Event()
    q = queue.Queue(maxsize=10000)

    def on_signal(signum, _frame):
        log(f"signal {signum} — flushing and stopping")
        stop.set()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    stores, ch = build_backends(args)
    scorer = make_scorer(args.scorer, args.models_dir, log)
    log(f"scorer: {scorer.name}  alert-risk-policy: {args.alert_risk_policy}")
    mit = None
    if args.mitigate != "none":
        import mitigator as mg_mod

        def own_addresses(first=False):     # re-read with each mitigation refresh
            try:
                return mg_mod.local_ipv4_addresses(args.mitigate_netns)
            except Exception as e:
                if first:
                    log(f"mitigation: cannot read this machine's addresses ({e}); "
                        "protect a public one with --allowlist")
                return None

        policy = mg_mod.BlockPolicy(own_addresses=own_addresses(first=True) or (),
            protected_cidrs=args.protected_cidr or mg_mod.DEFAULT_PROTECTED,
            allowlist=args.allowlist, allow_private_blocks=args.allow_private_blocks,
            use_severe_risk=not args.no_severe_risk_blocks,
            allowlist_file=args.allowlist_file,
            high_threshold=args.block_high_score, repeat_count=args.block_repeat,
            repeat_window_s=args.block_repeat_window, scan_ports=args.scan_ports,
            sweep_hosts=args.sweep_hosts, scan_window_s=args.scan_window)
        sinks = [mg_mod.JsonlEventSink(args.mitigations_jsonl)]
        if args.backend in ("auto", "sqlite", "both"):
            sinks.append(mg_mod.SqliteEventSink(args.db))
        if ch is not None and ch in stores:
            sinks.append(mg_mod.ClickHouseEventSink(ch))
        mit = mg_mod.Mitigator(policy, mg_mod.make_backend(args.mitigate, args.block_timeout,
                                                           args.mitigate_netns),
                               args.block_timeout, sinks, log_fn=log)
        log(f"mitigation: backend={args.mitigate}"
            f"{' netns=' + args.mitigate_netns if args.mitigate_netns else ''} "
            f"timeout={args.block_timeout}s rule=score>={policy.high_threshold:.2f}|"
            f"{policy.repeat_count}x>={policy.threshold:.2f}/{args.block_repeat_window:g}s"
            f"{'|severe' if policy.use_severe_risk else ''}"
            f"|scan>={policy.scan_ports}ports,{policy.sweep_hosts}hosts/{args.scan_window:g}s protected="
            f"{','.join(str(n) for n in policy.protected) or 'none'} "
            f"allowlist={','.join(str(n) for n in policy.allowlist) or 'none'} "
            f"own={','.join(sorted(map(str, policy.own))) or 'none'} "
            f"sinks={','.join(type(x).__name__ for x in sinks)}")

    if args.from_jsonl:
        transport = FileTransport(args.from_jsonl, q, stop)
    else:
        use_pyzmq = False
        if args.transport in ("auto", "pyzmq"):
            try:
                import zmq  # noqa: F401
                use_pyzmq = True
            except ImportError:
                if args.transport == "pyzmq":
                    log("pyzmq requested but not installed")
                    sys.exit(2)
        transport = (PyZMQTransport(args.endpoint, q, stop) if use_pyzmq else
                     ZmqSinkTransport(args.endpoint, q, stop, args.zmq_sink))
    transport.start()
    log(f"transport={transport.name} endpoint="
        f"{args.from_jsonl or args.endpoint} "
        f"backends={','.join(s.name for s in stores)} ready")

    batch, accepted, rejected, ch_failed = [], 0, 0, 0
    last_flush = time.monotonic()
    last_ch_probe = time.monotonic()
    rej_fh = None

    def flush():
        nonlocal batch, last_flush, ch_failed
        if batch:
            t0 = time.perf_counter()
            finalize(batch, scorer, args.alert_risk_policy)
            score_ms = (time.perf_counter() - t0) * 1000
            for s in list(stores):
                try:
                    s.write(batch)
                except Exception as e:  # keep the durable stores going
                    if s is not ch:
                        raise
                    if stores == [ch]:
                        # --backend clickhouse: nowhere else to keep the rows,
                        # so stop instead of silently dropping the rest.
                        log(f"clickhouse write failed ({e}); no other store — stopping. "
                            f"Rows before this batch were written "
                            f"({accepted - len(batch)} of {accepted} accepted).")
                        sys.exit(1)
                    ch_failed += len(batch)
                    stores.remove(ch)
                    log(f"clickhouse write failed ({e}); "
                        f"{len(batch)} rows kept in SQLite/JSONL only")
            log(f"flushed {len(batch)} rows -> {','.join(s.name for s in stores)}"
                f" (scored in {score_ms:.1f} ms; alerts={sum(f['is_alert'] for f in batch)};"
                f" total accepted={accepted} rejected={rejected})")
            if mit is not None:
                mit.process(batch)
            batch = []
        last_flush = time.monotonic()

    while True:
        try:
            item = q.get(timeout=0.2)
        except queue.Empty:
            item = None
        if item is EOF:
            break
        if item is not None:
            try:
                rec = stamp(validate(json.loads(item)))
                batch.append(rec)
                accepted += 1
            except BAD_RECORD as e:
                rejected += 1
                log(f"rejected: {e}")
                if rej_fh is None:
                    os.makedirs(os.path.dirname(args.rejected), exist_ok=True)
                    rej_fh = open(args.rejected, "a", buffering=1)
                rej_fh.write(json.dumps({"error": str(e), "raw": item}) + "\n")
        if len(batch) >= args.batch_size or \
                (batch and time.monotonic() - last_flush >= args.flush_interval):
            flush()
        if args.max_messages and accepted >= args.max_messages:
            log(f"reached --max-messages {args.max_messages}")
            break
        if stop.is_set():
            break
        if mit is not None and time.time() - mit.last_refresh >= mit.refresh_s:
            mit.refresh()                    # kernel drop counters, expiries
            own = own_addresses()            # e.g. a new DHCP address
            if own is not None and set(own) != {str(a) for a in mit.policy.own}:
                mit.policy.set_own_addresses(own)
                log(f"mitigation: own addresses now {','.join(own) or 'none'}")
        # Re-attach ClickHouse if it comes back after a failed write.
        if ch is not None and ch not in stores and args.backend in ("auto", "both") and \
                time.monotonic() - last_ch_probe > 30:
            last_ch_probe = time.monotonic()
            if ch.ping():
                stores.append(ch)
                log("clickhouse: now reachable, attached")

    # Drain anything already queued before shutting down.
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            break
        if item is EOF:
            continue
        try:
            batch.append(stamp(validate(json.loads(item))))
            accepted += 1
        except BAD_RECORD:
            rejected += 1
    flush()
    if mit is not None:
        mit.refresh()
        log(f"mitigation: {mit.stats}; active blocks left in place: "
            f"{len(mit.active)} (they expire after --block-timeout)")
    stop.set()
    transport.close()
    for s in stores:
        s.close()
    if rej_fh:
        rej_fh.close()
    log(f"stopped: accepted={accepted} rejected={rejected} "
        f"clickhouse_failed={ch_failed}")


if __name__ == "__main__":
    main()
