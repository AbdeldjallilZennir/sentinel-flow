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

    def test_thresholds_are_inclusive(self):
        self.assertEqual(self.p.decide(rec(score=0.95, dst="203.0.113.1")).action, "block")
        self.assertEqual(self.p.decide(rec(score=0.80, dst="203.0.113.2")).action, "skip")
        d = self.p.decide(rec(score=0.80, dst="203.0.113.2"))           # second flow
        self.assertEqual((d.action, d.reason), ("block", "ml_repeat"))
        p = mitigator.BlockPolicy()
        for _ in range(3):
            self.assertEqual(p.decide(rec(score=0.7999)).action, "skip")

    def test_one_moderate_flow_does_not_block(self):
        d = self.p.decide(rec(score=0.90))
        self.assertEqual((d.action, d.reason_code), ("skip", 0))
        self.assertIn("watching", d.detail)

    def test_repeat_counts_per_remote_ip(self):
        self.assertEqual(self.p.decide(rec(score=0.85, dst="203.0.113.1")).action, "skip")
        self.assertEqual(self.p.decide(rec(score=0.85, dst="203.0.113.2")).action, "skip")
        d = self.p.decide(rec(score=0.85, dst="203.0.113.1"))
        self.assertEqual((d.action, d.ip, d.reason), ("block", "203.0.113.1", "ml_repeat"))
        self.assertIn("2 flows", d.detail)

    def test_repeat_window_uses_flow_time(self):
        hour = 3600 * 10**6
        r1 = dict(rec(score=0.85), last_seen_us=10 * hour)
        r2 = dict(rec(score=0.85), last_seen_us=11 * hour + 1)          # 1 h + 1 µs later
        r3 = dict(rec(score=0.85), last_seen_us=11 * hour + 2)
        self.assertEqual(self.p.decide(r1).action, "skip")
        self.assertEqual(self.p.decide(r2).action, "skip")              # r1 fell out
        self.assertEqual(self.p.decide(r3).action, "block")

    def test_per_flow_rule_can_be_restored(self):
        old = mitigator.BlockPolicy(high_threshold=0.80, repeat_count=1)
        self.assertEqual(old.decide(rec(score=0.80)).action, "block")
        old = mitigator.BlockPolicy(repeat_count=1)
        self.assertEqual(old.decide(rec(score=0.85)).reason, "ml_repeat")

    def test_moderate_score_with_severe_risk_blocks_now(self):
        d = self.p.decide(rec(score=0.85, mask=1 << features.SEVERE_RISKS["susp_dga"]))
        self.assertEqual((d.action, d.reason), ("block", "severe_risk"))

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


def probe(src, dst, port, t_s, proto=6, pkts=2):
    """A scan probe as the sensor exports it (SYN + RST)."""
    return {"src_ip": src, "dst_ip": dst, "src_port": 40000, "dst_port": port,
            "protocol": proto, "pkt_count": pkts, "app_protocol": "Unknown",
            "ml_anomaly_score": 0.01, "ndpi_risk_mask": 0, "ml_model": MODEL,
            "first_seen_us": int(t_s * 1e6), "last_seen_us": int(t_s * 1e6) + 500}


class Scans(unittest.TestCase):
    def setUp(self):
        self.p = mitigator.BlockPolicy()

    def run_flows(self, flows):
        return [d for f in flows for d in self.p.decisions(f)]

    def test_port_scan_blocks_the_source(self):
        ds = self.run_flows(probe("198.51.100.66", "192.168.1.10", port, port * 0.05)
                            for port in range(1, 61))
        self.assertEqual(len(ds), 1)
        d = ds[0]
        self.assertEqual((d.action, d.ip, d.reason), ("block", "198.51.100.66", "scan"))
        self.assertIn("port scan: 50 TCP ports on 192.168.1.10", d.detail)

    def test_ports_spread_over_more_than_the_window_do_not_fire(self):
        ds = self.run_flows(probe("198.51.100.66", "192.168.1.10", port, port * 2.0)
                            for port in range(1, 200))             # 30 ports per minute
        self.assertEqual(ds, [])

    def test_below_threshold_does_not_fire(self):
        ds = self.run_flows(probe("198.51.100.66", "192.168.1.10", port, 0) for port in range(49))
        self.assertEqual(ds, [])

    def test_host_sweep_counts_only_short_flows(self):
        long_flows = [probe("198.51.100.66", f"192.0.2.{i}", 443, i * 0.1, pkts=40)
                      for i in range(1, 150)]
        self.assertEqual(self.run_flows(long_flows), [])          # e.g. a busy client
        ds = self.run_flows(probe("198.51.100.77", f"10.9.{i // 250}.{i % 250}", 445, i * 0.1)
                            for i in range(150))
        self.assertEqual([(d.action, d.ip, d.reason) for d in ds],
                         [("block", "198.51.100.77", "scan")])
        self.assertIn("host sweep: 100 hosts on TCP/445", ds[0].detail)

    def test_lan_scanner_is_reported_not_blocked_and_cooldown_applies(self):
        ds = self.run_flows(probe("192.168.230.1", "192.168.230.128", port, port * 0.01)
                            for port in range(1, 1001))           # nmap top-1000 in 10 s
        self.assertEqual(len(ds), 1)                               # cooldown: once per 10 min
        self.assertEqual((ds[0].action, ds[0].reason), ("skip", "scan"))
        self.assertIn("scanner protected (192.168.230.1", ds[0].detail)
        later = self.run_flows(probe("192.168.230.1", "192.168.230.128", port, 700 + port * 0.01)
                               for port in range(1, 61))
        self.assertEqual(len(later), 1)

    def test_scans_can_be_disabled(self):
        p = mitigator.BlockPolicy(scan_ports=0, sweep_hosts=0)
        ds = [d for port in range(1, 500)
              for d in p.decisions(probe("198.51.100.66", "192.168.1.10", port, 0))]
        self.assertEqual(ds, [])

    def test_lab_nmap_session(self):
        """The 2026-10-24 lab nmap session (1,137 flows, 1,002 ports in 220 s)."""
        import gzip
        import json
        path = os.path.join(os.path.dirname(__file__), "data", "lab_nmap_flows.jsonl.gz")
        with gzip.open(path, "rt") as fh:
            flows = [json.loads(line) for line in fh]
        self.assertEqual(len(flows), 1137)
        ds = self.run_flows(flows)
        scans = [d for d in ds if d.reason == "scan"]
        self.assertTrue(scans)
        self.assertTrue(all("192.168.230.1" in d.detail for d in scans))


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

    def test_scan_blocks_source_with_audit_row(self):
        self.m.process([probe("198.51.100.66", "192.168.1.10", p, p * 0.01) for p in range(1, 80)])
        self.assertEqual(self.actions(), [("block", "198.51.100.66")])
        self.assertEqual(self.sink.rows[0]["reason"], "scan")
        self.assertEqual(self.sink.rows[0]["score"], -1.0)

    def test_moderate_flows_block_on_second_hit(self):
        self.m.process([flow(score=0.85)])
        self.assertEqual(self.sink.rows, [])
        self.m.process([flow(score=0.85)])
        self.assertEqual(self.actions(), [("block", "203.0.113.7")])
        self.assertEqual(self.sink.rows[0]["reason"], "ml_repeat")

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
