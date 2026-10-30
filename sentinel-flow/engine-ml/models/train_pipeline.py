#!/usr/bin/env python3
"""
SentinelFlow Phase 3 — train, evaluate and export the flow models.

Input:  engine-ml/data/training/flows_labeled.jsonl   (build_dataset.py)
Output: engine-ml/models/c2_detector.onnx       LightGBM, P(malicious)
        engine-ml/models/anomaly_iforest.onnx   IsolationForest on benign flows
        engine-ml/models/model_meta.json        features, score calibration,
                                                thresholds, metrics, hashes
        engine-ml/models/evaluation.json        full cross-validation report

Evaluation is grouped: every capture (one MTA case or one nDPI file) is
either entirely in the training folds or entirely in the test fold, so
near-duplicate flows from one capture cannot leak across the split.

Needs: numpy, lightgbm, scikit-learn, onnxmltools, skl2onnx, onnx, onnxruntime
(see engine-ml/requirements-train.txt). Inference only needs onnxruntime.

Usage:  engine-ml/.venv-train/bin/python engine-ml/models/train_pipeline.py
"""

import argparse
import collections
import hashlib
import json
import os
import platform
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(HERE)
sys.path.insert(0, ENGINE)
import daemon    # noqa: E402  (heuristic baseline)
import features  # noqa: E402

DATA = os.path.join(ENGINE, "data", "training", "flows_labeled.jsonl")
SEED = 42
ALERT_THRESHOLD = daemon.ALERT_THRESHOLD   # 0.80, same rule as Phase 2
GROUP_CAP = 50   # one capture contributes at most this many "effective" flows
LGBM_PARAMS = dict(n_estimators=300, learning_rate=0.05, num_leaves=31,
                   min_child_samples=10, subsample=0.8, subsample_freq=1,
                   colsample_bytree=0.8, reg_lambda=1.0, random_state=SEED,
                   n_jobs=4, verbose=-1)
IFOREST_PARAMS = dict(n_estimators=200, max_samples=256, contamination="auto",
                      random_state=SEED)


def load():
    """Labeled rows + features. Conversation features are computed over ALL
    rows of a capture (ambiguous ones too: the daemon sees them live), in
    file order = sensor export order, with a fresh tracker per capture."""
    rows, feats, tracker, capture = [], [], None, None
    for line in open(DATA):
        r = json.loads(line)
        if (r["grp"], r["pcap"]) != capture:
            capture, tracker = (r["grp"], r["pcap"]), features.ConversationTracker()
        conv = tracker.observe(r)
        if r["label"] in (0, 1):                               # drop ambiguous
            rows.append(r)
            feats.append(features.extract(r, conv))
    X = np.array(feats, dtype=np.float32)
    y = np.array([r["label"] for r in rows], dtype=np.int32)
    g = np.array([r["grp"] for r in rows])
    return rows, X, y, g


def group_weights(groups):
    """Cap each capture's total weight at GROUP_CAP flows."""
    n = collections.Counter(groups)
    return np.array([min(1.0, GROUP_CAP / n[x]) for x in groups], dtype=np.float64)


def iforest_calibration(raw_benign):
    """Map raw anomaly (higher = stranger) to [0, 1]: benign median -> 0,
    benign 99.5th percentile -> ALERT_THRESHOLD, linear, clipped."""
    q50, q995 = np.percentile(raw_benign, [50, 99.5])
    return {"q50": float(q50), "q995": float(q995), "at_q995": ALERT_THRESHOLD}


def iforest_norm(raw, cal):
    span = max(cal["q995"] - cal["q50"], 1e-9)
    return np.clip(cal["at_q995"] * (raw - cal["q50"]) / span, 0.0, 1.0)


CLASS_BALANCE = False   # set by --class-balance


def train_weights(y, groups):
    w = group_weights(groups)
    if CLASS_BALANCE:   # equal total weight for both classes
        w[y == 1] *= w[y == 0].sum() / max(w[y == 1].sum(), 1e-9)
    return w


FPR_BUDGET = 0.01   # LightGBM: score 0.80 <=> 1% of held-out benign flows


def lgbm_calibration(oof_p, y):
    """Monotone map of P(malicious) so ALERT_THRESHOLD sits at the raw
    probability where out-of-fold benign FPR = FPR_BUDGET.
    Piecewise linear through (0,0), (t, 0.80), (1,1)."""
    neg = np.sort(oof_p[y == 0])[::-1]
    k = int(np.floor(FPR_BUDGET * len(neg)))
    t = float(min(max(neg[k] + 1e-9, 1e-6), 1 - 1e-6))
    return {"raw_threshold": t, "maps_to": ALERT_THRESHOLD, "fpr_budget": FPR_BUDGET,
            "fit_on": "out-of-fold predictions"}


def lgbm_norm(p, cal):
    t, a = cal["raw_threshold"], cal["maps_to"]
    p = np.asarray(p, dtype=np.float64)
    return np.where(p < t, a * p / t, a + (1 - a) * (p - t) / (1 - t)).clip(0, 1)


def fit_fold(Xtr, ytr, gtr, seed=SEED):
    import lightgbm as lgb
    from sklearn.ensemble import IsolationForest
    clf = lgb.LGBMClassifier(**{**LGBM_PARAMS, "random_state": seed})
    clf.fit(Xtr, ytr, sample_weight=train_weights(ytr, gtr))
    iso = IsolationForest(**{**IFOREST_PARAMS, "random_state": seed}).fit(Xtr[ytr == 0])
    cal = iforest_calibration(-iso.decision_function(Xtr[ytr == 0]))
    return clf, iso, cal


# ── Metrics ─────────────────────────────────────────────────────────────
def binary_metrics(y, score, thr=ALERT_THRESHOLD):
    from sklearn.metrics import average_precision_score, roc_auc_score
    pred = score >= thr
    tp = int(np.sum(pred & (y == 1))); fp = int(np.sum(pred & (y == 0)))
    fn = int(np.sum(~pred & (y == 1))); tn = int(np.sum(~pred & (y == 0)))
    m = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
         "precision": tp / (tp + fp) if tp + fp else None,
         "recall": tp / (tp + fn) if tp + fn else None,
         "fpr": fp / (fp + tn) if fp + tn else None}
    if len(set(y)) == 2 and len(set(np.round(score, 9))) > 1:
        m["roc_auc"] = float(roc_auc_score(y, score))
        m["pr_auc"] = float(average_precision_score(y, score))
    return m


def recall_at_fpr(y, score, target):
    """Best recall reachable while FPR <= target (threshold chosen on OOF)."""
    neg = np.sort(score[y == 0])[::-1]
    k = int(np.floor(target * len(neg)))
    thr = neg[k] + 1e-12 if k < len(neg) else -np.inf
    return {"fpr_target": target, "threshold": float(thr),
            "recall": float(np.mean(score[y == 1] >= thr))}


def breakdown(rows, y, score, thr=ALERT_THRESHOLD):
    """Per-family recall, per-capture detection, FPR per benign source."""
    fam = collections.defaultdict(lambda: [0, 0])
    case = collections.defaultdict(lambda: [0, 0])
    src = collections.defaultdict(lambda: [0, 0])
    for r, yi, s in zip(rows, y, score):
        hit = int(s >= thr)
        if yi == 1:
            fam[r["family"]][0] += hit; fam[r["family"]][1] += 1
            case[r["grp"]][0] += hit; case[r["grp"]][1] += 1
        else:
            key = "mta_background" if r["source"] == "mta" else r["source"]
            src[key][0] += hit; src[key][1] += 1
    return {
        "family_recall": {k: {"detected": a, "flows": n, "recall": a / n}
                          for k, (a, n) in sorted(fam.items(), key=lambda x: -x[1][1])},
        "captures_with_malicious_flows": len(case),
        "captures_detected": sum(1 for a, _ in case.values() if a > 0),
        "captures_missed": sorted(k for k, (a, _) in case.items() if a == 0),
        "benign_fpr_by_source": {k: {"false_alerts": a, "flows": n, "fpr": a / n}
                                 for k, (a, n) in src.items()},
    }


def cross_validate(rows, X, y, g, k, seed=SEED, quiet=False):
    from sklearn.model_selection import StratifiedGroupKFold
    cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    oof_lgbm = np.zeros(len(y)); oof_if = np.zeros(len(y))
    folds = []
    for i, (tr, te) in enumerate(cv.split(X, y, g)):
        clf, iso, cal = fit_fold(X[tr], y[tr], g[tr], seed)
        oof_lgbm[te] = clf.predict_proba(X[te])[:, 1]
        oof_if[te] = iforest_norm(-iso.decision_function(X[te]), cal)
        f = {"fold": i, "test_flows": int(len(te)), "test_malicious": int(y[te].sum()),
             "test_captures": int(len(set(g[te]))),
             "test_malicious_captures": int(len(set(g[te][y[te] == 1])))}
        f.update({"lgbm": binary_metrics(y[te], oof_lgbm[te])})
        folds.append(f)
        if not quiet:
            print(f"  fold {i}: {f['test_flows']} flows ({f['test_malicious']} malicious, "
              f"{f['test_malicious_captures']} malicious captures) "
              f"recall={f['lgbm']['recall']:.3f} fpr={f['lgbm']['fpr']:.4f}")
    return oof_lgbm, oof_if, folds


def baselines(rows):
    heur = np.array([daemon.heuristic_score(r) for r in rows])
    risk = np.array([1.0 if r["ndpi_risk_mask"] > 0 else 0.0 for r in rows])
    return heur, risk


# ── Export ──────────────────────────────────────────────────────────────
def export_onnx(clf, iso, n_features):
    import onnx
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType as SkFloat
    lgbm_onnx = convert_lightgbm(clf, initial_types=[("input", FloatTensorType([None, n_features]))],
                                 zipmap=False, target_opset=15)
    iso_onnx = convert_sklearn(iso, initial_types=[("input", SkFloat([None, n_features]))],
                               target_opset={"": 15, "ai.onnx.ml": 3})
    paths = {"c2_detector.onnx": lgbm_onnx, "anomaly_iforest.onnx": iso_onnx}
    for name, model in paths.items():
        onnx.checker.check_model(model)
        with open(os.path.join(HERE, name), "wb") as f:
            f.write(model.SerializeToString())
    return list(paths)


def onnx_parity_and_latency(clf, iso, X):
    import onnxruntime as ort
    lg = ort.InferenceSession(os.path.join(HERE, "c2_detector.onnx"),
                              providers=["CPUExecutionProvider"])
    io = ort.InferenceSession(os.path.join(HERE, "anomaly_iforest.onnx"),
                              providers=["CPUExecutionProvider"])
    out_lg = lg.run(None, {"input": X})
    out_io = io.run(None, {"input": X})
    names_lg = [o.name for o in lg.get_outputs()]
    names_io = [o.name for o in io.get_outputs()]
    p_onnx = out_lg[names_lg.index("probabilities")][:, 1]
    s_onnx = out_io[names_io.index("scores")].reshape(-1)
    p_nat = clf.predict_proba(X)[:, 1]
    s_nat = iso.decision_function(X)
    lat = {}
    for n in (1, 100, 1000):
        xb = X[:n]
        for _ in range(5):
            lg.run(None, {"input": xb}); io.run(None, {"input": xb})
        reps = 200 if n == 1 else 20
        t = time.perf_counter()
        for _ in range(reps):
            lg.run(None, {"input": xb}); io.run(None, {"input": xb})
        lat[f"batch_{n}_ms"] = (time.perf_counter() - t) / reps * 1000
    return {
        "lgbm_outputs": names_lg, "iforest_outputs": names_io,
        "lgbm_max_abs_diff": float(np.max(np.abs(p_onnx - p_nat))),
        "iforest_max_abs_diff": float(np.max(np.abs(s_onnx - s_nat))),
        "alert_decisions_differ": int(np.sum((p_onnx >= ALERT_THRESHOLD) != (p_nat >= ALERT_THRESHOLD))),
        "rows_checked": int(len(X)),
        "latency_both_models": lat,
        "onnxruntime": ort.__version__,
    }


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--class-balance", action="store_true")
    ap.add_argument("--seeds", type=int, default=5,
                    help="repeat CV with this many fold/model seeds to measure spread")
    ap.add_argument("--no-export", action="store_true", help="cross-validate only")
    args = ap.parse_args()
    global CLASS_BALANCE
    CLASS_BALANCE = args.class_balance

    import lightgbm, sklearn, onnx, onnxmltools, skl2onnx  # noqa: E401
    rows, X, y, g = load()
    print(f"[data] {len(y)} labeled flows: {int(y.sum())} malicious "
          f"({len(set(g[y == 1]))} captures), {int((y == 0).sum())} benign "
          f"({len(set(g[y == 0]))} captures), {X.shape[1]} features")

    print(f"[cv] StratifiedGroupKFold k={args.folds}, grouped by capture, seed {SEED}")
    oof_lgbm, oof_if, folds = cross_validate(rows, X, y, g, args.folds)
    heur, risk = baselines(rows)

    # Repeat CV with other seeds: different fold assignment + model seed.
    seeds = [SEED + i for i in range(args.seeds)]
    oofs = {SEED: oof_lgbm}
    for sd in seeds[1:]:
        print(f"[cv] repeat with seed {sd}")
        oofs[sd] = cross_validate(rows, X, y, g, args.folds, seed=sd, quiet=True)[0]
    # Operating point: median over seeds of the raw threshold at 1% OOF FPR.
    per_seed_t = [lgbm_calibration(oofs[sd], y)["raw_threshold"] for sd in seeds]
    lcal = lgbm_calibration(oof_lgbm, y)
    lcal.update(raw_threshold=float(np.median(per_seed_t)),
                per_seed_raw_thresholds=per_seed_t,
                fit_on=f"median over {len(seeds)} CV seeds of the 1%-OOF-FPR threshold")
    oof_cal = lgbm_norm(oof_lgbm, lcal)
    spread = collections.defaultdict(list)
    for sd in seeds:
        m = binary_metrics(y, lgbm_norm(oofs[sd], lcal))
        for k in ("recall", "precision", "fpr", "roc_auc", "pr_auc"):
            spread[k].append(m[k])
    seed_summary = {k: {"mean": float(np.mean(v)), "std": float(np.std(v)),
                        "min": float(np.min(v)), "max": float(np.max(v)), "values": v}
                    for k, v in spread.items()}
    print(f"\n[cv] calibrated LightGBM at 0.80 over {len(seeds)} seeds "
          f"(raw thresholds {', '.join(f'{t:.3f}' for t in per_seed_t)}; median used):")
    for k, v in seed_summary.items():
        print(f"  {k:9s} mean={v['mean']:.3f} std={v['std']:.3f} "
              f"min={v['min']:.3f} max={v['max']:.3f}")

    scores = {"lgbm_raw": oof_lgbm, "lgbm_calibrated": oof_cal, "iforest": oof_if,
              "max(lgbm_cal, iforest)": np.maximum(oof_cal, oof_if),
              "phase2_heuristic": heur, "ndpi_risk_only": risk}
    report = {"threshold": ALERT_THRESHOLD, "folds": folds, "oof": {}}
    print(f"\n[oof] out-of-fold results at threshold {ALERT_THRESHOLD} (all {len(y)} flows):")
    print(f"  {'score':22s} {'recall':>7s} {'precision':>9s} {'FPR':>8s} {'ROC-AUC':>8s} {'PR-AUC':>7s}")
    for name, s in scores.items():
        m = binary_metrics(y, s)
        report["oof"][name] = {"metrics": m, **breakdown(rows, y, s)}
        f = lambda v, d=3: "  n/a" if v is None else f"{v:.{d}f}"
        print(f"  {name:22s} {f(m['recall']):>7s} {f(m['precision']):>9s} {f(m['fpr'], 4):>8s} "
              f"{f(m.get('roc_auc')):>8s} {f(m.get('pr_auc')):>7s}")
    report["oof"]["lgbm_raw"]["recall_at_fpr"] = [recall_at_fpr(y, oof_lgbm, t)
                                                  for t in (0.001, 0.005, 0.01, 0.02, 0.05)]
    report["class_balance"] = CLASS_BALANCE
    report["seed_spread"] = {"seeds": seeds, "lgbm_calibrated": seed_summary}

    # is_alert policy variants (alert = risk part OR calibrated score >= 0.80)
    mask = np.array([int(r["ndpi_risk_mask"]) for r in rows], dtype=object)
    risk_any = np.array([m > 0 for m in mask])
    risk_sev = np.array([(m & features.SEVERE_MASK) != 0 for m in mask])
    ml = oof_cal >= ALERT_THRESHOLD
    rules = {"any_risk OR ml (Phase 2 spec)": risk_any | ml,
             "severe_risk OR ml": risk_sev | ml, "ml only": ml}
    report["alert_rules"] = {}
    print("\n[oof] is_alert policies:")
    for name, pred in rules.items():
        m = binary_metrics(y, pred.astype(float), thr=0.5)
        bg = [i for i, r in enumerate(rows) if r["source"] == "mta" and y[i] == 0]
        m["fpr_mta_background"] = float(np.mean(pred[bg])) if bg else None
        report["alert_rules"][name] = m
        print(f"  {name:32s} recall={m['recall']:.3f} precision={m['precision']:.3f} "
              f"fpr={m['fpr']:.4f} fpr_on_real_background={m['fpr_mta_background']:.4f}")

    # Per-flow out-of-fold scores, for later analysis.
    with open(os.path.join(ENGINE, "data", "training", "oof_predictions.jsonl"), "w") as f:
        for r, yi, a, b in zip(rows, y, oof_lgbm, oof_if):
            f.write(json.dumps({"grp": r["grp"], "family": r["family"], "label": int(yi),
                                "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
                                "dst_port": r["dst_port"], "app_protocol": r["app_protocol"],
                                "lgbm_raw": float(a), "lgbm_cal": float(lgbm_norm(a, lcal)),
                                "iforest": float(b)}) + "\n")
    report["lgbm_calibration"] = lcal

    if args.no_export:
        json.dump(report, open(os.path.join(HERE, "evaluation_cv_only.json"), "w"),
                  indent=2, default=float)
        return
    # Final models on all labeled data.
    print("\n[fit] final models on all labeled flows")
    clf, iso, cal = fit_fold(X, y, g, SEED)
    files = export_onnx(clf, iso, X.shape[1])
    parity = onnx_parity_and_latency(clf, iso, X)
    print(f"[onnx] parity: lgbm max|diff|={parity['lgbm_max_abs_diff']:.2e}, "
          f"iforest max|diff|={parity['iforest_max_abs_diff']:.2e}, "
          f"alert decisions differing: {parity['alert_decisions_differ']}/{parity['rows_checked']}")
    print(f"[onnx] latency (both models): " +
          ", ".join(f"{k}={v:.3f}" for k, v in parity["latency_both_models"].items()))

    gain = clf.booster_.feature_importance(importance_type="gain")
    top = sorted(zip(features.FEATURE_NAMES, gain), key=lambda x: -x[1])[:15]
    meta = {
        "model_version": f"lgbm+iforest-fv{features.FEATURE_VERSION}-"
                         f"{sha256(os.path.join(HERE, 'c2_detector.onnx'))[:8]}",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature_version": features.FEATURE_VERSION,
        "feature_names": features.FEATURE_NAMES,
        "input_name": "input",
        "lgbm": {"file": "c2_detector.onnx", "output": "probabilities", "column": 1,
                 "calibration": "see lgbm_calibration",
                 "sha256": sha256(os.path.join(HERE, "c2_detector.onnx")), "params": LGBM_PARAMS},
        "iforest": {"file": "anomaly_iforest.onnx", "output": "scores",
                    "raw": "negated decision_function (higher = more anomalous)",
                    "calibration": cal,
                    "sha256": sha256(os.path.join(HERE, "anomaly_iforest.onnx")),
                    "params": IFOREST_PARAMS},
        "lgbm_calibration": lcal,
        "class_balance": CLASS_BALANCE,
        "score_policy": "ml_anomaly_score = lgbm_norm(P_lgbm); ml_iforest_score stored "
                        "separately (not in the alert score: it added false alerts "
                        "without recall in cross-validation)",
        "alert_threshold": ALERT_THRESHOLD,
        "training_data": {"file": os.path.relpath(DATA, ENGINE), "sha256": sha256(DATA),
                          "flows": int(len(y)), "malicious": int(y.sum()),
                          "malicious_captures": int(len(set(g[y == 1]))),
                          "benign_captures": int(len(set(g[y == 0]))), "group_cap": GROUP_CAP},
        "cv_summary": {k: report["oof"][k]["metrics"] for k in scores},
        "cv_seed_spread": seed_summary,
        "top_features_by_gain": [[n, float(v)] for n, v in top],
        "onnx_parity": parity,
        "versions": {"python": platform.python_version(), "numpy": np.__version__,
                     "lightgbm": lightgbm.__version__, "scikit-learn": sklearn.__version__,
                     "onnx": onnx.__version__, "onnxmltools": onnxmltools.__version__,
                     "skl2onnx": skl2onnx.__version__},
        "files": files,
    }
    json.dump(meta, open(os.path.join(HERE, "model_meta.json"), "w"), indent=2)
    json.dump(report, open(os.path.join(HERE, "evaluation.json"), "w"), indent=2, default=float)
    print(f"[done] wrote {', '.join(files)}, model_meta.json, evaluation.json")
    print("[top features by gain] " + ", ".join(n for n, _ in top[:10]))


if __name__ == "__main__":
    main()
