#!/usr/bin/env python3
"""Unit tests for features.py: the conversation tracker (fv2) and is_internet."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import features  # noqa: E402

S = 1_000_000           # one second in microseconds
T0 = 1_700_000_000 * S
NAMES = features.CONV_FEATURE_NAMES


def flow(start_s, sport, dst="203.0.113.5", dport=443, proto=6, up=300, down=900,
         pkts=8, dur_s=1.0, src="10.0.0.2"):
    start = T0 + int(start_s * S)
    return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "bytes_up": up, "bytes_down": down, "pkt_count": pkts,
            "first_seen_us": start, "last_seen_us": start + int(dur_s * S)}


def named(values):
    return dict(zip(NAMES, values))


class IsInternet(unittest.TestCase):
    def test_addresses(self):
        for ip, want in [("8.8.8.8", True), ("203.0.113.5", False),   # TEST-NET is not global
                         ("142.250.74.110", True), ("2606:4700::1111", True),
                         ("10.1.2.3", False), ("192.168.1.1", False), ("100.64.0.1", False),
                         ("239.255.255.250", False),    # SSDP
                         ("224.0.0.251", False),        # mDNS
                         ("224.0.0.252", False),        # LLMNR
                         ("ff02::fb", False),           # mDNS v6
                         ("255.255.255.255", False), ("127.0.0.1", False),
                         ("not-an-ip", False)]:
            with self.subTest(ip=ip):
                self.assertEqual(features.is_internet(ip), want)


class Tracker(unittest.TestCase):
    def setUp(self):
        # 203.0.113.0/24 is documentation space (not global): use lab mode so
        # the tests can use it, and test the Internet-only rule separately.
        self.t = features.ConversationTracker(lab=True)

    def stats(self, r):
        """Observe r, return its raw statistics."""
        self.t.observe(r)
        conv = self.t.convs[(r["src_ip"], r["dst_ip"], r["dst_port"], r["protocol"])]
        return self.t.stats(conv, conv.conns[r["src_port"]])

    def test_periodic_beacon_with_new_connections(self):
        for i in range(9):
            self.t.observe(flow(60 * i, 50000 + i))
        r = flow(540, 50009)
        f = named(self.t.observe(r))
        self.assertEqual(f["conv_periodicity"], 1.0)
        self.assertAlmostEqual(f["conv_log_beacon_interval_s"], features._log1p(60))
        self.assertEqual(f["conv_same_size_ratio"], 1.0)
        self.assertEqual(f["conv_up_regularity"], 1.0)
        self.assertEqual(f["conv_pkt_regularity"], 1.0)
        st = self.stats(r)
        self.assertEqual((st["n_prev"], st["n_60s"], st["n_300s"]), (9, 1, 5))
        self.assertEqual((st["age_s"], st["median_gap_s"], st["mad_ratio"]), (540, 60, 0))

    def test_jittered_beacon_is_still_mostly_periodic(self):
        gaps = [60, 55, 66, 61, 58, 90, 63, 59]          # one late check-in
        t = 0
        for i, g in enumerate(gaps):
            self.t.observe(flow(t, 40000 + i))
            t += g
        r = flow(t, 40100)
        self.assertAlmostEqual(self.stats(r)["periodicity"], 7 / 8)
        self.assertAlmostEqual(named(self.t.observe(r))["conv_periodicity"], (7 / 8 - 0.5) / 0.5)

    def test_no_pattern_looks_like_no_history(self):
        # Irregular gaps and sizes: every feature is 0, exactly as for a
        # first contact, so the model can't learn "has history" itself.
        first = self.t.observe(flow(0, 41000, up=100, down=100, pkts=2))
        self.assertEqual(first, features.CONV_NONE)
        for i, (t, up, down, pkts) in enumerate([(3, 900, 40, 5), (50, 120, 7000, 12),
                                                 (52, 5000, 300, 9), (200, 60, 90000, 80),
                                                 (207, 2500, 2500, 20)]):
            r = flow(t, 41001 + i, up=up, down=down, pkts=pkts)
            self.assertEqual(self.t.observe(r), features.CONV_NONE, i)
        self.assertEqual(self.stats(r)["n_prev"], 5)

    def test_keepalive_pieces_are_one_connection(self):
        # One TCP connection, a keep-alive every 45 s, the sensor splits it
        # into a new record each time (30 s idle timeout): same source port.
        for i in range(20):
            r = flow(45 * i, 51000, up=60, down=60, pkts=2, dur_s=0.1)
            self.assertEqual(self.t.observe(r), features.CONV_NONE, i)
            self.assertEqual(self.stats(r)["n_prev"], 0)
        # A second real connection later sees one earlier connection whose
        # size is the sum of all pieces.
        self.assertEqual(self.stats(flow(2000, 51001))["n_prev"], 1)
        conv = next(iter(self.t.convs.values()))
        self.assertEqual(conv.conns[51000].totals(), (1200, 1200, 40))

    def test_snapshot_then_final_record_updates_one_connection(self):
        for i in range(4):
            self.t.observe(flow(30 * i, 52000 + i))
        snap = flow(120, 52010, up=1000, down=5000, pkts=20, dur_s=60)
        final = dict(snap, bytes_up=1500, bytes_down=8000, pkt_count=30,
                     last_seen_us=snap["first_seen_us"] + 90 * S)
        a = self.t.observe(snap)
        b = self.t.observe(final)
        self.assertEqual(a, b)
        self.assertEqual(a[0], 1.0)                   # 4 earlier at 30 s: periodic
        conv = next(iter(self.t.convs.values()))
        self.assertEqual(len(conv.conns), 5)
        self.assertEqual(conv.conns[52010].totals(), (1500, 8000, 30))

    def test_only_earlier_connections_count(self):
        # A long connection exported after shorter ones that started later.
        for i in range(5):
            self.t.observe(flow(10 + 10 * i, 53000 + i))
        r = flow(0, 53100, dur_s=600)
        self.assertEqual(self.t.observe(r), features.CONV_NONE)
        st = self.stats(r)
        self.assertEqual((st["n_prev"], st["age_s"]), (0, 0))

    def test_conversations_are_separate(self):
        for i in range(5):
            self.t.observe(flow(60 * i, 54000 + i, dport=443))
        self.assertEqual(self.stats(flow(300, 54100, dport=8443))["n_prev"], 0)
        self.assertEqual(self.stats(flow(300, 54101, src="10.0.0.3"))["n_prev"], 0)
        self.assertEqual(self.stats(flow(300, 54102))["n_prev"], 5)

    def test_size_statistics(self):
        sizes = [(100, 200), (100, 200), (100, 200), (400, 50)]
        for i, (u, d) in enumerate(sizes):
            self.t.observe(flow(10 * i + i * i, 55000 + i, up=u, down=d))
        r = flow(100, 55100)
        f = named(self.t.observe(r))
        self.assertEqual(f["conv_same_size_ratio"], 0.75)
        self.assertEqual(f["conv_up_regularity"], 0.0)  # CV of bytes_up > 0.25
        self.assertEqual(f["conv_pkt_regularity"], 1.0)  # same pkt_count each time
        self.assertGreater(self.stats(r)["cv_bytes_up"], 0.5)

    def test_internet_only_by_default(self):
        t = features.ConversationTracker()
        for dst in ("10.0.0.9", "239.255.255.250", "224.0.0.251", "255.255.255.255"):
            for i in range(5):
                self.assertEqual(t.observe(flow(60 * i, 56000 + i, dst=dst)), features.CONV_NONE)
        self.assertEqual(len(t), 0)
        for i in range(5):
            f = t.observe(flow(60 * i, 56000 + i, dst="8.8.8.8"))
        self.assertEqual(f[0], 1.0)
        # lab mode accepts private servers, never multicast or broadcast
        lab = features.ConversationTracker(lab=True)
        for dst, want in (("10.0.0.9", 1.0), ("239.255.255.250", 0.0), ("255.255.255.255", 0.0)):
            for i in range(5):
                f = lab.observe(flow(60 * i, 56000 + i, dst=dst))
            self.assertEqual(f[0], want, dst)

    def test_idle_conversation_expires(self):
        for i in range(5):
            self.t.observe(flow(60 * i, 57000 + i))
        self.assertEqual(self.stats(flow(25 * 3600, 57100))["n_prev"], 0)

    def test_history_cap_still_counts_all_connections(self):
        self.t = features.ConversationTracker(lab=True, history=5)
        for i in range(11):
            self.t.observe(flow(60 * i, 58000 + i))
        self.assertEqual(self.stats(flow(660, 58011))["n_prev"], 11)
        self.assertEqual(len(next(iter(self.t.convs.values())).conns), 5)

    def test_conversation_cap(self):
        t = features.ConversationTracker(lab=True, max_conversations=3)
        for i in range(10):
            t.observe(flow(i, 59000, dst=f"198.51.100.{i}"))
        self.assertEqual(len(t), 3)

    def test_vector_length_and_names(self):
        self.assertEqual(len(features.CONV_NONE), len(NAMES))
        self.assertEqual(len(set(features.FEATURE_NAMES)), features.N_FEATURES)
        self.assertEqual(features.FEATURE_NAMES[-len(NAMES):], NAMES)


if __name__ == "__main__":
    unittest.main(verbosity=1)
