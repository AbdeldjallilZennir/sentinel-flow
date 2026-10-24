#!/usr/bin/env python3
"""
SentinelFlow Phase 3 — end-to-end evaluation on held-out captures.

For every PCAP in datasets/mta_holdout/ (never used for training):
  1. start daemon.py (ONNX scorer, real ZeroMQ transport, private SQLite)
  2. replay the PCAP with `sensor -r` into the daemon's endpoint
  3. stop the daemon (SIGTERM -> flush), read the stored rows
  4. label each stored flow from datasets/mta_holdout_labels.json
     (same label_flow() as the training set builder)
and report detection per capture and overall, next to the Phase 2 rules.

Usage:  python3 engine-ml/models/evaluate_holdout.py [--risk-policy any|severe|none]
Writes: engine-ml/models/evaluation_holdout.json
"""

import argparse
import collections
import glob
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(HERE)
ROOT = os.path.dirname(ENGINE)
sys.path.insert(0, ENGINE)
sys.path.insert(0, HERE)
import build_dataset as bd  # noqa: E402
import daemon               # noqa: E402
import features             # noqa: E402

HOLDOUT_DIR = os.path.join(ENGINE, "datasets", "mta_holdout")
LABELS = os.path.join(ENGINE, "datasets", "mta_holdout_labels.json")


def run_pipeline(pcap, risk_policy, tmp):
    ep = f"ipc://{tmp}/holdout.sock"
    db = os.path.join(tmp, "flows.db")
    log = open(os.path.join(tmp, "daemon.log"), "w+")
    d = subprocess.Popen([sys.executable, os.path.join(ENGINE, "daemon.py"), "-e", ep,
                          "--backend", "sqlite", "--db", db,
                          "--jsonl", os.path.join(tmp, "flows.jsonl"),
                          "--rejected", os.path.join(tmp, "rejected.jsonl"),
                          "--scorer", "onnx", "--alert-risk-policy", risk_policy],
                         stderr=log)
    # Wait for the daemon to bind its endpoint before replaying. Loading
    # numpy/onnxruntime + the models can take well over 10 s on small cloud
    # machines; a sensor that finds no consumer discards its flows at exit.
    t0 = time.time()
    while True:
        log.seek(0)
        text = log.read()
        if " ready" in text:
            break
        if d.poll() is not None or time.time() - t0 > 180:
            d.kill()
            raise RuntimeError("daemon.py did not become ready "
                               f"({'exited' if d.returncode is not None else 'timeout'}); "
                               "last log lines:\n" + "\n".join(text.splitlines()[-8:]))
        time.sleep(0.2)
    print(f"    daemon ready after {time.time() - t0:.1f} s", flush=True)
    # -A 0: same flow definition as the training set (see build_dataset.py).
    s = subprocess.run([bd.SENSOR, "-r", pcap, "-z", ep, "-A", "0"],
                       capture_output=True, text=True)
    time.sleep(2.0)                       # > daemon --flush-interval
    d.send_signal(signal.SIGTERM)
    d.wait(timeout=60)
    log.seek(0)
    dlog = log.read()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM network_flows")]
    con.close()
    exported = int(s.stderr.split("Flows exported:")[1].split()[0])
    return rows, exported, s.returncode, dlog


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--risk-policy", default="any", choices=["any", "severe", "none"])
    args = ap.parse_args()
    labels = json.load(open(LABELS))
    meta = json.load(open(os.path.join(HERE, "model_meta.json")))
    print(f"[model] {meta['model_version']}  alert-risk-policy={args.risk_policy}")

    per_case, all_rows = [], []
    for case in sorted(os.listdir(HOLDOUT_DIR)):
        info = labels["cases"][case]
        meta_case = {"source": "mta", "rule": "mta", "family": info["family"], **info}
        for pcap in sorted(glob.glob(os.path.join(HOLDOUT_DIR, case, "*.pcap*"))):
            with tempfile.TemporaryDirectory() as tmp:
                rows, exported, rc, dlog = run_pipeline(pcap, args.risk_policy, tmp)
            names = bd.capture_name_map(pcap)
            c = collections.Counter()
            for r in rows:
                r["label"], r["label_name"], r["label_reason"] = bd.label_flow(r, meta_case, names)
                r["case"] = case
                c[r["label_name"]] += 1
            mal = [r for r in rows if r["label"] == 1]
            ben = [r for r in rows if r["label"] == 0]
            rule = lambda r: r["is_alert"] == 1
            ml = lambda r: r["ml_anomaly_score"] >= daemon.ALERT_THRESHOLD
            risk_any = lambda r: r["ndpi_risk_mask"] > 0
            res = {
                "case": case, "family": info["family"], "pcap": os.path.basename(pcap),
                "sensor_exit": rc, "sensor_exported": exported, "daemon_stored": len(rows),
                "scorer": rows[0]["ml_model"] if rows else None,
                "labels": dict(c),
                "malicious_flows": len(mal),
                "ml_detected": sum(ml(r) for r in mal),
                "ml_false_alerts": sum(ml(r) for r in ben),
                "is_alert_detected": sum(rule(r) for r in mal),
                "is_alert_false_alerts": sum(rule(r) for r in ben),
                "risk_any_false_alerts": sum(risk_any(r) for r in ben),
                "benign_flows": len(ben),
                "top_malicious": sorted(({"dst": f"{r['dst_ip']}:{r['dst_port']}",
                                          "app": r["app_protocol"],
                                          "score": r["ml_anomaly_score"],
                                          "p": r["ml_c2_proba"]} for r in mal),
                                        key=lambda x: -x["score"])[:5],
            }
            # Per malicious endpoint (what an IP blocker acts on).
            ep = collections.defaultdict(lambda: {"flows": 0, "alerted": 0, "max_score": 0.0,
                                                  "services": set()})
            for r in mal:
                e = ep[r["dst_ip"]]
                e["flows"] += 1
                e["alerted"] += int(ml(r))
                e["max_score"] = max(e["max_score"], r["ml_anomaly_score"])
                e["services"].add(f"{r['dst_port']}/{r['app_protocol']}")
            res["malicious_endpoints"] = {k: {**v, "services": sorted(v["services"])}
                                          for k, v in sorted(ep.items(), key=lambda x: -x[1]["flows"])}
            res["endpoints_alerted"] = sum(1 for v in ep.values() if v["alerted"])
            per_case.append(res)
            all_rows += rows
            print(f"[{case}] {info['family']}: stored {len(rows)}/{exported} flows, "
                  f"{len(mal)} malicious -> ML detected {res['ml_detected']}, "
                  f"is_alert {res['is_alert_detected']}; benign {len(ben)} -> "
                  f"ML false alerts {res['ml_false_alerts']}, is_alert {res['is_alert_false_alerts']}")

    lab = [r for r in all_rows if r["label"] in (0, 1)]
    def agg(pred):
        tp = sum(1 for r in lab if r["label"] == 1 and pred(r))
        fp = sum(1 for r in lab if r["label"] == 0 and pred(r))
        p = sum(1 for r in lab if r["label"] == 1); n = len(lab) - p
        return {"tp": tp, "fp": fp, "malicious": p, "benign": n,
                "recall": tp / p if p else None, "fpr": fp / n if n else None,
                "precision": tp / (tp + fp) if tp + fp else None,
                "captures_detected": sum(1 for c in per_case
                                         if any(pred(r) for r in lab
                                                if r["case"] == c["case"] and r["label"] == 1))}
    thr = daemon.ALERT_THRESHOLD
    summary = {
        "ml (ml_anomaly_score >= 0.80)": agg(lambda r: r["ml_anomaly_score"] >= thr),
        "severe_risk OR ml": agg(lambda r: r["ml_anomaly_score"] >= thr or
                                 (r["ndpi_risk_mask"] & features.SEVERE_MASK) != 0),
        "any_risk OR ml (Phase 2 rule)": agg(lambda r: r["ml_anomaly_score"] >= thr or
                                             r["ndpi_risk_mask"] > 0),
        "phase2_heuristic >= 0.80": agg(lambda r: daemon.heuristic_score(r) >= thr),
    }
    print(f"\n[holdout] {len(lab)} labeled flows "
          f"({sum(r['label'] == 1 for r in lab)} malicious) from {len(per_case)} captures")
    for k, v in summary.items():
        f = lambda x: "n/a" if x is None else f"{x:.3f}"
        print(f"  {k:32s} recall={f(v['recall'])} precision={f(v['precision'])} "
              f"fpr={f(v['fpr'])} captures_detected={v['captures_detected']}/{len(per_case)}")
    n_ep = sum(len(c["malicious_endpoints"]) for c in per_case)
    n_al = sum(c["endpoints_alerted"] for c in per_case)
    print(f"  malicious endpoints with >= 1 ML alert: {n_al}/{n_ep}")
    summary["ml_endpoints"] = {"alerted": n_al, "total": n_ep}
    out = {"model_version": meta["model_version"], "risk_policy": args.risk_policy,
           "summary": summary, "cases": per_case}
    json.dump(out, open(os.path.join(HERE, "evaluation_holdout.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
