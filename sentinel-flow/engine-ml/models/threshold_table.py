#!/usr/bin/env python3
"""
Phase 4 — read-only threshold / risk-policy comparison for blocking.

Replays mitigator.BlockPolicy over predictions that were already saved in
Part 3 (nothing is re-trained or re-scored) and counts, per capture:
  * malicious endpoints caught   = remote IPs of label-1 flows that get blocked
  * benign endpoints blocked     = remote IPs seen only in label-0 flows that get blocked
Endpoints are (capture, IP) pairs. Ambiguous flows are ignored.

Sources:
  holdout  engine-ml/data/sentinel_flows.db (Part 3/4 live run) rows from the
           5 holdout captures, assigned to a capture by capture time and
           labeled with datasets/mta_holdout_labels.json (same label_flow()).
  cv       data/training/oof_predictions.jsonl (seed 42, calibrated scores)
           joined row-by-row with data/training/flows_labeled.jsonl.

Usage:  python3 engine-ml/models/threshold_table.py
Writes: engine-ml/models/threshold_table.json
"""
import collections
import glob
import json
import os
import sqlite3
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(HERE)
sys.path.insert(0, ENGINE)
sys.path.insert(0, HERE)
import build_dataset as bd  # noqa: E402
import mitigator            # noqa: E402

THRESHOLDS = (0.70, 0.80, 0.90)
POLICIES = ("none", "severe")


def capture_range(pcap):
    out = subprocess.run(["capinfos", "-T", "-r", "-a", "-e", "-S", pcap],
                         capture_output=True, text=True).stdout.split("\t")
    return int(float(out[1]) * 1e6), int(float(out[2]) * 1e6) + 1


def holdout_rows():
    labels = json.load(open(os.path.join(ENGINE, "datasets", "mta_holdout_labels.json")))
    db = sqlite3.connect(os.path.join(ENGINE, "data", "sentinel_flows.db"))
    db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute("SELECT * FROM network_flows")]
    out = []
    for case in sorted(os.listdir(os.path.join(ENGINE, "datasets", "mta_holdout"))):
        info = labels["cases"][case]
        meta = {"source": "mta", "rule": "mta", **info}
        for pcap in glob.glob(os.path.join(ENGINE, "datasets", "mta_holdout", case, "*.pcap")):
            lo, hi = capture_range(pcap)
            names = bd.capture_name_map(pcap)
            mine = [r for r in rows if lo <= r["first_seen_us"] <= hi]
            for r in mine:
                r["label"] = bd.label_flow(r, meta, names)[0]
                r["group"] = case
            out += mine
    return out


def cv_rows():
    tr = os.path.join(ENGINE, "data", "training")
    flows = [json.loads(l) for l in open(os.path.join(tr, "flows_labeled.jsonl"))]
    flows = [f for f in flows if f["label"] in (0, 1)]
    oof = [json.loads(l) for l in open(os.path.join(tr, "oof_predictions.jsonl"))]
    assert len(flows) == len(oof)
    out = []
    for f, o in zip(flows, oof):
        assert (f["grp"], f["src_ip"], f["dst_ip"], f["label"]) == \
               (o["grp"], o["src_ip"], o["dst_ip"], o["label"]), "row order mismatch"
        out.append({**f, "ml_anomaly_score": o["lgbm_cal"], "ml_model": "oof-seed42",
                    "group": f["grp"]})
    return out


def evaluate(rows, threshold, policy):
    pol = mitigator.BlockPolicy(threshold=threshold, use_severe_risk=(policy == "severe"))
    mal, ben, blocked = set(), set(), set()
    for r in rows:
        if r["label"] not in (0, 1):
            continue
        # The remote endpoint of this flow, as the policy would pick it.
        remote = next((ip for ip in (r["dst_ip"], r["src_ip"])
                       if pol.why_protected(ip) is None), None)
        if remote is None:
            continue
        key = (r["group"], remote)
        (mal if r["label"] == 1 else ben).add(key)
        d = pol.decide(r)
        if d.action == "block":
            blocked.add((r["group"], d.ip))
    ben -= mal                       # an IP with any malicious flow is malicious
    return {"malicious_endpoints": len(mal), "caught": len(blocked & mal),
            "benign_endpoints": len(ben), "false_blocks": len(blocked & ben),
            "infections_with_a_block": len({g for g, _ in blocked & mal}),
            "infections": len({g for g, _ in mal})}


def main():
    result = {}
    for name, rows in (("holdout", holdout_rows()), ("cv_seed42", cv_rows())):
        result[name] = {}
        print(f"\n== {name}: {len(rows)} flows")
        print(f"  {'threshold':>9s} {'risk':>6s} {'caught':>14s} {'false blocks':>16s} {'infections hit':>15s}")
        for t in THRESHOLDS:
            for p in POLICIES:
                m = evaluate(rows, t, p)
                result[name][f"{t:.2f}/{p}"] = m
                print(f"  {t:9.2f} {p:>6s} {m['caught']:5d}/{m['malicious_endpoints']:<5d}"
                      f"({m['caught'] / max(m['malicious_endpoints'], 1):5.1%}) "
                      f"{m['false_blocks']:5d}/{m['benign_endpoints']:<5d}({m['false_blocks'] / max(m['benign_endpoints'], 1):5.2%}) "
                      f"{m['infections_with_a_block']:6d}/{m['infections']}")
    json.dump(result, open(os.path.join(HERE, "threshold_table.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
