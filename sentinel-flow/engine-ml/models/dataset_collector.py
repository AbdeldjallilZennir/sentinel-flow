#!/usr/bin/env python3
"""
Sort and label captured lab flows from flows.jsonl into TP/FN/FP/TN buckets
and append deduplicated records to data/collected/extra_labeled.jsonl.
"""
import argparse
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "data" / "flows.jsonl"
DEFAULT_OUT_DIR = BASE_DIR / "data" / "collected"


def flow_key(rec):
    return (
        rec.get("src_ip"),
        rec.get("dst_ip"),
        rec.get("src_port"),
        rec.get("dst_port"),
        rec.get("protocol"),
        rec.get("first_seen_us"),
    )


def collect_session(input_path, out_dir, positive_ip, group_id, threshold):
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    # Deduplicate active-timeout (-A) snapshots: keep final record with max pkt_count / last_seen_us
    by_flow = {}
    with open(input_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            k = flow_key(rec)
            prev = by_flow.get(k)
            if prev is None or (
                rec.get("pkt_count", 0),
                rec.get("last_seen_us", 0),
            ) >= (
                prev.get("pkt_count", 0),
                prev.get("last_seen_us", 0),
            ):
                by_flow[k] = rec

    buckets = {"tp": [], "fn": [], "fp": [], "tn": []}
    labeled_rows = []

    for rec in by_flow.values():
        is_pos = (rec.get("src_ip") == positive_ip) or (rec.get("dst_ip") == positive_ip)
        label = 1 if is_pos else 0
        score = float(rec.get("ml_anomaly_score", 0.0))
        flagged = score >= threshold

        row = dict(rec)
        row["label"] = label
        row["source"] = "lab"
        row["capture_id"] = group_id
        row["family"] = group_id if label == 1 else "benign_lab"
        labeled_rows.append(row)

        if label == 1 and flagged:
            buckets["tp"].append(row)
        elif label == 1 and not flagged:
            buckets["fn"].append(row)
        elif label == 0 and flagged:
            buckets["fp"].append(row)
        else:
            buckets["tn"].append(row)

    for name, rows in buckets.items():
        with open(out_dir / f"{name}.jsonl", "a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    master_path = out_dir / "extra_labeled.jsonl"
    with open(master_path, "a", encoding="utf-8") as fh:
        for r in labeled_rows:
            fh.write(json.dumps(r) + "\n")

    print(f"=== Session Harvested: {group_id} (positive_ip={positive_ip}, threshold={threshold}) ===")
    print(f"  Total deduplicated flows : {len(labeled_rows)}")
    print(f"  Caught Positive (TP)     : {len(buckets['tp'])}  -> {out_dir / 'tp.jsonl'}")
    print(f"  Missed Positive (FN)     : {len(buckets['fn'])}  -> {out_dir / 'fn.jsonl'}")
    print(f"  False Alarms    (FP)     : {len(buckets['fp'])}  -> {out_dir / 'fp.jsonl'}")
    print(f"  Clean Benign    (TN)     : {len(buckets['tn'])}  -> {out_dir / 'tn.jsonl'}")
    print(f"  Master training append   : {master_path}")


def merge_for_training(extra_path, base_training_path):
    extra_path = Path(extra_path)
    base_training_path = Path(base_training_path)
    if not extra_path.exists():
        raise SystemExit(f"No extra_labeled.jsonl found at {extra_path}")

    with open(extra_path, "r", encoding="utf-8") as src, open(base_training_path, "a", encoding="utf-8") as dst:
        count = 0
        for line in src:
            if line.strip():
                dst.write(line)
                count += 1
    print(f"Appended {count} rows from {extra_path} into {base_training_path}.")
    print("Now run: make train")


def main():
    ap = argparse.ArgumentParser(description="Collect and sort lab flows for retraining.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="Sort flows.jsonl into TP/FN/FP/TN and extra_labeled.jsonl")
    c.add_argument("--positive-ip", required=True, help="IP of the test client generating positive flows")
    c.add_argument("--group-id", required=True, help="Session tag / capture_id for grouped CV")
    c.add_argument("--threshold", type=float, default=0.80, help="Alert score threshold (default 0.80)")
    c.add_argument("--input-jsonl", default=str(DEFAULT_INPUT), help="Path to flows.jsonl")
    c.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="Output directory")

    m = sub.add_parser("merge", help="Append collected extra_labeled.jsonl into data/training/flows_labeled.jsonl")
    m.add_argument("--extra-jsonl", default=str(DEFAULT_OUT_DIR / "extra_labeled.jsonl"))
    m.add_argument("--training-jsonl", default=str(BASE_DIR / "data" / "training" / "flows_labeled.jsonl"))

    args = ap.parse_args()
    if args.cmd == "collect":
        collect_session(args.input_jsonl, args.out_dir, args.positive_ip, args.group_id, args.threshold)
    elif args.cmd == "merge":
        merge_for_training(args.extra_jsonl, args.training_jsonl)


if __name__ == "__main__":
    main()
