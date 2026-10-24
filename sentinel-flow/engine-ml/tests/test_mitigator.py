#!/usr/bin/env python3
"""Unit tests for the Phase 4 blocking policy (mitigator.BlockPolicy)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import features   # noqa: E402
import mitigator  # noqa: E402

MODEL = "lgbm+iforest-fv1-test"


def rec(src="10.1.2.3", dst="203.0.113.7", score=0.95, mask=0, model=MODEL):
    return {"src_ip": src, "dst_ip": dst, "ml_anomaly_score": score,
            "ndpi_risk_mask": mask, "ml_model": model}


class Policy(unittest.TestCase):
    def setUp(self):
        self.p = mitigator.BlockPolicy()

    def test_blocks_remote_c2_not_victim(self):
        d = self.p.decide(rec())
        self.assertEqual((d.action, d.ip, d.reason), ("block", "203.0.113.7", "ml_score"))

    def test_victim_as_responder_blocks_the_other_side(self):
        # Inbound flow: remote host initiated, LAN host is dst.
        d = self.p.decide(rec(src="198.51.100.9", dst="192.168.1.20"))
        self.assertEqual((d.action, d.ip), ("block", "198.51.100.9"))

    def test_threshold_is_inclusive(self):
        self.assertEqual(self.p.decide(rec(score=0.80)).action, "block")
        self.assertEqual(self.p.decide(rec(score=0.7999)).action, "skip")

    def test_heuristic_scores_never_block(self):
        for model in ("heuristic_v1", ""):
            self.assertEqual(self.p.decide(rec(score=0.99, model=model)).action, "skip")
        trusting = mitigator.BlockPolicy(trust_heuristic=True)
        self.assertEqual(trusting.decide(rec(score=0.99, model="heuristic_v1")).action, "block")

    def test_only_severe_risks_block_without_ml(self):
        unidirectional = 1 << 46          # common benign-ish risk
        self.assertEqual(self.p.decide(rec(score=0.1, mask=unidirectional)).action, "skip")
        for name, bit in features.SEVERE_RISKS.items():
            with self.subTest(name):
                d = self.p.decide(rec(score=0.1, mask=1 << bit))
                self.assertEqual((d.action, d.reason), ("block", "severe_risk"))
                self.assertIn(name, d.detail)
        no_sev = mitigator.BlockPolicy(use_severe_risk=False)
        self.assertEqual(no_sev.decide(rec(score=0.1, mask=1 << 28)).action, "skip")

    def test_both_private_endpoints_never_blocked_by_default(self):
        d = self.p.decide(rec(src="10.0.0.5", dst="10.0.0.17"))     # e.g. WinRM to the DC
        self.assertEqual(d.action, "skip")
        self.assertIn("both endpoints protected", d.detail)

    def test_allow_private_blocks_for_lab(self):
        lab = mitigator.BlockPolicy(allow_private_blocks=True)
        d = lab.decide(rec(src="10.200.0.1", dst="10.200.0.2"))
        self.assertEqual((d.action, d.ip), ("block", "10.200.0.2"))

    def test_special_addresses_always_protected(self):
        lab = mitigator.BlockPolicy(allow_private_blocks=True, protected_cidrs=())
        for ip in ("127.0.0.1", "169.254.1.1", "224.0.0.251", "0.0.0.0",
                   "255.255.255.255", "240.0.0.1"):
            with self.subTest(ip):
                self.assertIsNotNone(lab.why_protected(ip))
                self.assertEqual(lab.decide(rec(src=ip, dst=ip)).action, "skip")

    def test_allowlist_and_custom_protected(self):
        p = mitigator.BlockPolicy(allowlist=["203.0.113.0/24"],
                                  protected_cidrs=["100.64.0.0/10,10.0.0.0/8"])
        self.assertEqual(p.decide(rec(dst="203.0.113.7")).action, "skip")
        self.assertEqual(p.decide(rec(src="100.64.1.1", dst="198.51.100.1")).ip, "198.51.100.1")
        # 192.168/16 is not in this custom protected list -> blockable
        self.assertEqual(p.decide(rec(src="10.0.0.1", dst="192.168.5.5")).ip, "192.168.5.5")

    def test_allowlist_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# cloud / CDN ranges kept reachable\n\n"
                     "13.107.0.0/16   # Microsoft\n"
                     "172.67.74.152\n")
        try:
            p = mitigator.BlockPolicy(allowlist_file=fh.name)
            self.assertEqual(p.decide(rec(dst="13.107.213.57")).action, "skip")
            self.assertIn("allowlisted", p.decide(rec(dst="172.67.74.152")).detail)
            self.assertEqual(p.decide(rec(dst="185.39.19.96")).action, "block")
            with open(fh.name, "a") as f:
                f.write("not-an-ip\n")
            with self.assertRaisesRegex(ValueError, r":5: not an IP address or CIDR"):
                mitigator.BlockPolicy(allowlist_file=fh.name)
        finally:
            os.unlink(fh.name)

    def test_ipv6_never_blocked(self):
        self.assertEqual(self.p.why_protected("2001:db8::1"), "not IPv4")
        self.assertEqual(self.p.decide(rec(src="2001:db8::1", dst="2001:db8::2")).action, "skip")


def flow(dst="203.0.113.7", src="10.1.2.3", score=0.95, model=MODEL, mask=0):
    r = rec(src=src, dst=dst, score=score, model=model, mask=mask)
    r.update(src_port=50000, dst_port=443, app_protocol="TLS")
    return r


class ListSink:
    def __init__(self):
        self.rows = []

    def write_event(self, row):
        self.rows.append(row)


class FakeKernel(mitigator.DryRunBackend):
    """Dry-run backend whose counters/expiry the test controls."""
    name = "fake"

    def __init__(self):
        super().__init__()
        self.counters = {}
        self.fail = False

    def block(self, ip, timeout_s, reason_code, comment=""):
        if self.fail:
            raise mitigator.BackendError("nft: permission denied")
        return super().block(ip, timeout_s, reason_code, comment)

    def list(self):
        return {ip: {"expires_s": 60, "packets": self.counters.get(ip, (0, 0))[0],
                     "bytes": self.counters.get(ip, (0, 0))[1]} for ip in self.entries}


class MitigatorFlow(unittest.TestCase):
    def setUp(self):
        self.k, self.sink = FakeKernel(), ListSink()
        self.m = mitigator.Mitigator(mitigator.BlockPolicy(), self.k, timeout_s=900,
                                     sinks=[self.sink], refresh_s=3600)

    def actions(self):
        return [(r["action"], r["ip"]) for r in self.sink.rows]

    def test_blocks_once_per_ip(self):
        self.m.process([flow(), flow(), flow(dst="198.51.100.1")])
        self.assertEqual(self.actions(), [("block", "203.0.113.7"), ("block", "198.51.100.1")])
        self.assertEqual(set(self.k.entries), {"203.0.113.7", "198.51.100.1"})
        row = self.sink.rows[0]
        self.assertEqual((row["backend"], row["reason"], row["timeout_s"]), ("fake", "ml_score", 900))
        self.assertIn("10.1.2.3:50000 -> 203.0.113.7:443", row["flow"])

    def test_benign_and_heuristic_records_do_nothing(self):
        self.m.process([flow(score=0.3), flow(score=0.99, model="heuristic_v1")])
        self.assertEqual(self.sink.rows, [])
        self.assertEqual(self.k.entries, {})

    def test_protected_skip_is_audited(self):
        self.m.process([flow(src="10.0.0.5", dst="10.0.0.17")])
        self.assertEqual(self.actions(), [("skip_protected", "")])
        self.assertEqual(self.k.entries, {})

    def test_backend_error_is_logged_not_raised(self):
        self.k.fail = True
        self.m.process([flow()])
        self.assertEqual(self.actions(), [("error", "203.0.113.7")])
        self.assertEqual(self.m.stats["errors"], 1)

    def test_counters_and_expiry_events(self):
        self.m.process([flow()])
        self.k.counters["203.0.113.7"] = (12, 1536)
        self.m.refresh()
        self.m.refresh()                                  # unchanged -> no new event
        del self.k.entries["203.0.113.7"]                 # kernel timeout expired it
        self.m.refresh()
        self.assertEqual(self.actions(), [("block", "203.0.113.7"), ("counters", "203.0.113.7"),
                                          ("expire", "203.0.113.7")])
        self.assertEqual((self.sink.rows[2]["dropped_pkts"], self.sink.rows[2]["dropped_bytes"]),
                         (12, 1536))
        self.m.process([flow()])                           # can be blocked again
        self.assertEqual(self.actions()[-1], ("block", "203.0.113.7"))

    def test_sqlite_sink_tracks_state(self):
        import sqlite3, tempfile
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "m.db")
            m = mitigator.Mitigator(mitigator.BlockPolicy(), self.k, 900,
                                    sinks=[mitigator.SqliteEventSink(db)], refresh_s=3600)
            m.process([flow()])
            self.k.counters["203.0.113.7"] = (5, 640)
            m.refresh()
            m.unblock("203.0.113.7")
            con = sqlite3.connect(db)
            state = con.execute("SELECT ip, status, reason, dropped_pkts, dropped_bytes "
                                "FROM blocked_ips").fetchall()
            n = con.execute("SELECT COUNT(*) FROM mitigation_events").fetchone()[0]
        self.assertEqual(state, [("203.0.113.7", "unblocked", "ml_score", 5, 640)])
        self.assertEqual(n, 3)

    def test_cli_refuses_protected_ip(self):
        import subprocess
        p = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..",
                                                         "mitigator.py"),
                            "--backend", "dry-run", "block", "192.168.1.1"],
                           capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refusing to block 192.168.1.1", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
