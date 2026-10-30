#!/usr/bin/env python3
"""Unit tests for daemon.validate / enrich (stdlib unittest)."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import daemon  # noqa: E402

# Real record captured from sensor on test_tls_full.pcap (docs/REPORT.md, Part 1.2 §2.6).
GOOD = {"src_ip": "192.168.1.13", "dst_ip": "178.62.197.130", "src_port": 55523,
        "dst_port": 443, "protocol": 6, "app_protocol": "TLS.ntop",
        "ja4_client": "t12d6707h2_2955a3196ffa_c83f907a73d3", "ndpi_risk_mask": 0,
        "ndpi_risk_str": "", "pkt_count": 109, "bytes_up": 3546, "bytes_down": 68910,
        "flow_duration_ms": 1096.093, "iat_mean": 10149.0093, "iat_stddev": 75724.1596,
        "iat_min": 1, "iat_max": 783975, "pkt_len_mean": 612.990826,
        "pkt_len_stddev": 697.460917, "bytes_up_down_ratio": 0.051458424,
        "small_pkt_ratio": 0.541284404, "first_seen_us": 1581113120474299,
        "last_seen_us": 1581113121570392}


def mutate(**kw):
    r = copy.deepcopy(GOOD)
    for k, v in kw.items():
        if v is KeyError:
            del r[k]
        else:
            r[k] = v
    return r


class Validate(unittest.TestCase):
    def test_good_record(self):
        out = daemon.validate(GOOD)
        self.assertEqual(list(out), [n for n, _ in daemon.SENSOR_FIELDS])
        self.assertEqual(out["first_seen_us"], 1581113120474299)
        self.assertIsInstance(out["iat_min"], float)       # f64 column
        self.assertIsInstance(out["bytes_up"], int)        # u64 column

    def test_extra_fields_dropped(self):
        self.assertNotIn("junk", daemon.validate(mutate(junk=1)))

    def test_rejections(self):
        bad = {
            "missing field": mutate(ja4_client=KeyError),
            "bad ip": mutate(src_ip="999.1.1.1"),
            "port range": mutate(dst_port=70000),
            "negative u64": mutate(bytes_up=-1),
            "bool as int": mutate(protocol=True),
            "string number": mutate(pkt_count="109"),
            "fractional u64": mutate(first_seen_us=1.5),
            "nan": mutate(iat_mean=float("nan")),
            "time reversed": mutate(last_seen_us=1),
            "zero packets": mutate(pkt_count=0),
            "not object": [1, 2],
        }
        for name, rec in bad.items():
            with self.subTest(name), self.assertRaises(daemon.ValidationError):
                daemon.validate(rec)

    def test_ipv6_accepted(self):
        daemon.validate(mutate(src_ip="2001:db8::1"))


class Enrich(unittest.TestCase):
    def test_clean_tls_not_alert(self):
        f = daemon.enrich(daemon.validate(GOOD), now_us=42)
        self.assertEqual(f["ingested_at_us"], 42)
        self.assertEqual(f["ml_anomaly_score"], 0.0)
        self.assertEqual(f["is_alert"], 0)

    def test_risk_mask_forces_alert(self):
        f = daemon.enrich(daemon.validate(mutate(ndpi_risk_mask=128)))
        self.assertLess(f["ml_anomaly_score"], daemon.ALERT_THRESHOLD)
        self.assertEqual(f["is_alert"], 1)

    def test_score_threshold_alert_without_risk(self):
        # unknown proto + unidirectional + periodic + nonstandard → noisy-OR
        f = daemon.enrich(daemon.validate(mutate(
            app_protocol="Unknown", bytes_down=0, bytes_up_down_ratio=0.0,
            iat_mean=1000.0, iat_stddev=10.0)))
        self.assertEqual(f["ml_anomaly_score"], 0.805)  # 1 - 0.6*0.65*0.5
        self.assertEqual(f["is_alert"], 1)

    def test_two_signals_below_threshold(self):
        f = daemon.enrich(daemon.validate(mutate(
            app_protocol="Unknown", iat_mean=1000.0, iat_stddev=10.0)))
        self.assertEqual(f["ml_anomaly_score"], 0.7)   # 1 - 0.6*0.5
        self.assertEqual(f["is_alert"], 0)

    def test_score_bounded(self):
        f = daemon.enrich(daemon.validate(mutate(
            ndpi_risk_mask=1, app_protocol="TLS", dst_port=4444, src_port=5555,
            bytes_down=0, iat_mean=1000.0, iat_stddev=1.0)))
        self.assertTrue(0.0 <= f["ml_anomaly_score"] <= 1.0)


class Scorers(unittest.TestCase):
    """Phase 3 scoring. ONNX tests skip when onnxruntime/numpy are absent."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.onnx = daemon.OnnxScorer()
        except Exception as e:   # noqa: BLE001
            cls.onnx = None
            cls.onnx_err = e

    def need_onnx(self):
        if self.onnx is None:
            self.skipTest(f"ONNX scorer unavailable: {self.onnx_err}")

    def test_onnx_scores_real_record(self):
        self.need_onnx()
        f = daemon.validate(GOOD)
        daemon.finalize([daemon.stamp(f)], self.onnx)
        self.assertEqual(f["ml_model"], self.onnx.name)
        for k in ("ml_anomaly_score", "ml_c2_proba", "ml_iforest_score"):
            self.assertTrue(0.0 <= f[k] <= 1.0, (k, f[k]))
        self.assertIn(f["is_alert"], (0, 1))

    def test_conversation_history_carries_across_batches(self):
        # Live records arrive in many small batches; the conversation
        # features must not depend on where the batches split.
        self.need_onnx()
        beacon = [daemon.validate(mutate(dst_ip="8.8.8.8", src_port=50000 + i,
                                         first_seen_us=GOOD["first_seen_us"] + i * 60_000_000,
                                         last_seen_us=GOOD["last_seen_us"] + i * 60_000_000))
                  for i in range(8)]
        one_by_one, together = daemon.OnnxScorer(), daemon.OnnxScorer()
        a = [daemon.finalize([dict(r)], one_by_one)[0] for r in beacon]
        b = daemon.finalize([dict(r) for r in beacon], together)
        self.assertEqual([r["ml_c2_proba"] for r in a], [r["ml_c2_proba"] for r in b])
        self.assertEqual(len(one_by_one.conversations), 1)
        conv = next(iter(one_by_one.conversations.convs.values()))
        self.assertEqual(len(conv.conns), 8)

    def test_calibration_is_monotone_and_maps_threshold(self):
        self.need_onnx()
        import numpy as np
        t = self.onnx.meta["lgbm_calibration"]["raw_threshold"]
        p = np.linspace(0, 1, 1001)
        out = self.onnx._lgbm_norm(p)
        self.assertTrue(np.all(np.diff(out) >= 0))
        self.assertAlmostEqual(float(self.onnx._lgbm_norm(np.array([t]))[0]), 0.80, places=6)

    def test_tampered_model_rejected_and_auto_falls_back(self):
        self.need_onnx()
        import shutil, tempfile
        with tempfile.TemporaryDirectory() as d:
            for n in os.listdir(daemon.MODELS_DIR):
                if n.endswith((".onnx", ".json")):
                    shutil.copy(os.path.join(daemon.MODELS_DIR, n), d)
            with open(os.path.join(d, "c2_detector.onnx"), "ab") as fh:
                fh.write(b"\0")                      # one extra byte
            with self.assertRaises(RuntimeError):
                daemon.OnnxScorer(d)
            self.assertIsInstance(daemon.make_scorer("auto", d), daemon.HeuristicScorer)
            with self.assertRaises(RuntimeError):
                daemon.make_scorer("onnx", d)

    def test_missing_models_fall_back_to_heuristic(self):
        s = daemon.make_scorer("auto", "/nonexistent")
        self.assertIsInstance(s, daemon.HeuristicScorer)
        f = daemon.enrich(daemon.validate(GOOD), scorer=s)
        self.assertEqual((f["ml_model"], f["ml_c2_proba"]), ("heuristic_v1", -1.0))

    def test_alert_policies(self):
        unidirectional = 1 << 46        # not in SEVERE_MASK
        malicious_fp = 1 << 28          # in SEVERE_MASK
        for mask, policy, want in [(unidirectional, "any", 1), (unidirectional, "severe", 0),
                                   (malicious_fp, "severe", 1), (malicious_fp, "none", 0)]:
            with self.subTest(mask=mask, policy=policy):
                f = dict(ndpi_risk_mask=mask, ml_anomaly_score=0.1)
                self.assertEqual(daemon.alert(f, policy)["is_alert"], want)
        self.assertEqual(daemon.alert(dict(ndpi_risk_mask=0, ml_anomaly_score=0.8),
                                      "none")["is_alert"], 1)

    def test_sqlite_migrates_phase2_table(self):
        import sqlite3, tempfile
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "old.db")
            con = sqlite3.connect(db)
            phase2 = [c for c in daemon.ALL_FIELDS if c[0] not in daemon.ENRICH_DEFAULTS]
            con.execute("CREATE TABLE network_flows (" +
                        ", ".join(f"{n} {daemon._SQLITE_TYPES[k]}" for n, k in phase2) + ")")
            con.commit(); con.close()
            store = daemon.SQLiteStore(db)
            store.write([daemon.enrich(daemon.validate(GOOD))])
            cols = [r[1] for r in store.db.execute("PRAGMA table_info(network_flows)")]
            self.assertEqual(cols, daemon.COLUMNS)
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
