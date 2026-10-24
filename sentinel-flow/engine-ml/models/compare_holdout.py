#!/usr/bin/env python3
"""
Compare two evaluate_holdout.py results (before / after a retrain).

Usage:  python3 engine-ml/models/compare_holdout.py BEFORE.json AFTER.json

The holdout captures are fixed, so this is the like-for-like comparison
between models trained on different datasets. Cross-validation numbers are
not comparable across datasets (different flows, different difficulty).
"""
import json
import sys

ML = "ml (ml_anomaly_score >= 0.80)"


def load(path):
    with open(path) as fh:
        return json.load(fh)


def fmt(x, pct=False):
    if x is None:
        return "n/a"
    return f"{100 * x:.1f} %" if pct else f"{x:.3f}"


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a, b = load(sys.argv[1]), load(sys.argv[2])
    sa, sb = a["summary"][ML], b["summary"][ML]
    ea, eb = a["summary"]["ml_endpoints"], b["summary"]["ml_endpoints"]
    w = 34
    print(f"{'':{w}s} {'before':>22s} {'after':>22s}")
    print(f"{'model':{w}s} {a['model_version'][-22:]:>22s} {b['model_version'][-22:]:>22s}")
    rows = [
        ("infections detected (of 5)", sa["captures_detected"], sb["captures_detected"]),
        ("malicious endpoints alerted", f"{ea['alerted']}/{ea['total']}", f"{eb['alerted']}/{eb['total']}"),
        ("flow recall", fmt(sa["recall"]), fmt(sb["recall"])),
        ("precision", fmt(sa["precision"]), fmt(sb["precision"])),
        ("false alerts (benign flows)", f"{sa['fp']}/{sa['benign']}", f"{sb['fp']}/{sb['benign']}"),
        ("false-alarm rate", fmt(sa["fpr"], True), fmt(sb["fpr"], True)),
    ]
    for name, x, y in rows:
        print(f"{name:{w}s} {str(x):>22s} {str(y):>22s}")
    print("\nper capture: ML-detected malicious flows / endpoints alerted / false alerts")
    cb = {c["case"]: c for c in b["cases"]}
    for c in a["cases"]:
        d = cb.get(c["case"])
        if d is None:
            continue
        before = f"{c['ml_detected']}/{c['malicious_flows']}  {c['endpoints_alerted']}/{len(c['malicious_endpoints'])}  {c['ml_false_alerts']}"
        after = f"{d['ml_detected']}/{d['malicious_flows']}  {d['endpoints_alerted']}/{len(d['malicious_endpoints'])}  {d['ml_false_alerts']}"
        print(f"  {c['case']} {c['family'][:24]:24s} {before:>22s} {after:>22s}")


if __name__ == "__main__":
    main()
