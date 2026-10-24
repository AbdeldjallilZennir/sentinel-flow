#!/usr/bin/env python3
"""
Black-box regression tests for the compiled sensor (stdlib only).

Generates small synthetic PCAPs, runs `sensor -r <pcap> -v`, and checks
the exported JSON. Covers behaviour that unit tests cannot reach because
it lives in main.c's packet loop:

  * 30 s idle expiry (flow re-appears after a gap -> exported twice)
  * out-of-order timestamps (no unsigned underflow in duration / IAT)
  * JA4 only reported for TLS-family flows (union read bug)
  * every exported line is valid UTF-8 JSON
  * non-Ethernet link types (Linux cooked v1/v2, BSD loopback, raw IP)
  * no flow loss over ZMQ when the consumer stalls during a burst
  * microsecond precision of flow_duration_ms on long flows
  * active-timeout snapshots (-A) of flows that never go idle

Usage:  python3 sensor-c/tests/test_sensor_pcaps.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SENSOR = os.path.join(HERE, "..", "build", "sensor")
SINK = os.path.join(HERE, "..", "build", "zmq_sink")
NDPI_PCAPS = os.path.expanduser("~/nDPI/tests/cfgs/default/pcap")
ENV = dict(os.environ, LD_LIBRARY_PATH=os.environ.get(
    "LD_LIBRARY_PATH", os.path.expanduser("~/nDPI/src/lib")))


def _csum(b):
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return b"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00" + ip + udp


def write_pcap(path, records, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for t, frame in records:
            sec, usec = int(t), int(round((t - int(t)) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)


def run_sensor(pcap, *extra):
    with tempfile.TemporaryDirectory() as d:
        # A consumer is not needed: -v prints the same JSON that is pushed.
        p = subprocess.run([SENSOR, "-r", pcap, "-v", "-z", f"ipc://{d}/s.sock", *extra],
                           capture_output=True, env=ENV, timeout=60)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    lines = [l for l in p.stdout.splitlines() if l.startswith(b"{")]
    return [json.loads(l.decode("utf-8")) for l in lines]   # strict UTF-8


A = ([10, 0, 0, 1], [10, 0, 0, 2], 40000, 9999)
B = ([10, 0, 0, 3], [10, 0, 0, 4], 40001, 9998)
T0 = 1700000000.0


class SensorPcapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.access(SENSOR, os.X_OK):
            raise unittest.SkipTest(f"sensor not built: {SENSOR}")
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def pcap(self, name, records, linktype=1):
        path = os.path.join(self.tmp.name, name)
        write_pcap(path, records, linktype)
        return path

    def test_idle_expiry_splits_flow(self):
        # A at t=0..0.4, 1000 filler pkts at t=40 (triggers the expiry
        # check, cutoff = 10 s), then A again at t=42 -> two A records.
        recs = [(T0 + 0.1 * i, udp_frame(*A, b"A" * 50)) for i in range(5)]
        recs += [(T0 + 40 + 0.001 * i, udp_frame(*B, b"B" * 50)) for i in range(1000)]
        recs += [(T0 + 42 + 0.1 * i, udp_frame(*A, b"A" * 50)) for i in range(5)]
        flows = run_sensor(self.pcap("expiry.pcap", recs))
        a = sorted((f for f in flows if f["src_port"] == 40000),
                   key=lambda f: f["first_seen_us"])
        self.assertEqual(len(flows), 3)
        self.assertEqual(len(a), 2)
        self.assertEqual([f["pkt_count"] for f in a], [5, 5])
        self.assertEqual(a[0]["last_seen_us"], int(T0 * 1e6) + 400000)
        self.assertEqual(a[1]["first_seen_us"], int(T0 * 1e6) + 42000000)

    def test_out_of_order_timestamps_no_underflow(self):
        # Packet times: 10, 11, 5 (goes backwards), 12  (seconds after T0)
        times = [10, 11, 5, 12]
        recs = [(T0 + t, udp_frame(*A, b"x" * 40)) for t in times]
        (f,) = run_sensor(self.pcap("reorder.pcap", recs))
        us = lambda s: int((T0 + s) * 1e6)
        self.assertEqual(f["first_seen_us"], us(5))       # min, not first
        self.assertEqual(f["last_seen_us"], us(12))       # max
        self.assertAlmostEqual(f["flow_duration_ms"], 7000.0)
        self.assertEqual(f["iat_min"], 0)                 # backwards step -> 0
        self.assertEqual(f["iat_max"], 1e6)               # 11->12 or 10->11
        self.assertLess(f["iat_mean"], 1e7)

    def test_no_ja4_on_non_tls_flow(self):
        # nDPI's metadata.protos is a union. Before the fix, reading
        # tls_quic.ja4_client on these non-TLS flows printed other
        # dissectors' state as a "JA4" (DHCP -> "19", TiVo -> "inidlna",
        # SSDP -> invalid UTF-8). Real captures from the nDPI corpus.
        cases = {"mikrotik_mndp.pcap": "Mikrotik", "TivoDVR.pcap": "TiVoConnect",
                 "ssdp.pcapng": "SSDP", "gnutella.pcap": "DHCP"}
        for name, proto in cases.items():
            path = os.path.join(NDPI_PCAPS, name)
            if not os.path.exists(path):
                self.skipTest(f"nDPI corpus not found: {path}")
            with self.subTest(name):
                flows = [f for f in run_sensor(path)
                         if f["app_protocol"].split(".")[0] == proto]
                self.assertTrue(flows, f"no {proto} flow in {name}")
                self.assertEqual({f["ja4_client"] for f in flows}, {"N/A"})

    def test_non_ethernet_link_types(self):
        # Same UDP flow re-framed for each link type (LINKTYPE_* values).
        ip_udp = udp_frame(*A, b"L" * 30)[14:]                 # strip Ethernet
        framings = {
            "linux_sll":  (113, b"\x00\x00\x00\x01\x00\x06" + b"\x02" * 6 + b"\0\0" + b"\x08\x00"),
            "linux_sll2": (276, b"\x08\x00\0\0" + b"\0\0\0\x02" + b"\x00\x01\x00\x06" + b"\x02" * 6 + b"\0\0"),
            "null_le":    (0,   struct.pack("<I", 2)),
            "loop_be":    (108, struct.pack(">I", 2)),
            "raw":        (101, b""),
            "ipv4":       (228, b""),
        }
        for name, (lt, prefix) in framings.items():
            with self.subTest(name):
                recs = [(T0 + i, prefix + ip_udp) for i in range(3)]
                flows = run_sensor(self.pcap(f"{name}.pcap", recs, lt))
                self.assertEqual(len(flows), 1, name)
                self.assertEqual((flows[0]["src_ip"], flows[0]["pkt_count"]), ("10.0.0.1", 3))

    def test_stalled_consumer_loses_nothing(self):
        # 1500 one-packet flows (> the old 1000-message receive limit).
        # The consumer reads nothing until the sensor has exited, so the
        # sink blocks on a full stdout pipe and ZMQ queues back up.
        recs = [(T0 + i * 0.001, udp_frame([10, 1, i >> 8, i & 255], [10, 2, 0, 1],
                                           20000 + i, 53, b"q" * 20)) for i in range(1500)]
        pcap = self.pcap("burst.pcap", recs)
        with tempfile.TemporaryDirectory() as d:
            ep = f"ipc://{d}/burst.sock"
            sink = subprocess.Popen([SINK, "-n", "1500", ep], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=ENV)
            try:
                import time
                time.sleep(0.3)
                p = subprocess.run([SENSOR, "-r", pcap, "-z", ep], capture_output=True,
                                   text=True, env=ENV, timeout=120)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("Flows exported:    1500", p.stderr)
                self.assertIn("Flows dropped:     0", p.stderr)
                # Only now start reading; -n 1500 makes the sink exit once
                # it has received (and printed) all 1500 messages.
                out, _ = sink.communicate(timeout=60)
            finally:
                if sink.poll() is None:
                    sink.kill()
        lines = [l for l in out.splitlines() if l.startswith(b"{")]
        self.assertEqual(len(lines), 1500)

    def test_long_flow_duration_keeps_microseconds(self):
        # 5003.499711 s apart: needs 10 significant digits in ms. The old
        # %.9g number format printed 5003499.71 (lost 1 us).
        recs = [(T0, udp_frame(*A, b"x")), (T0 + 5003.499711, udp_frame(*A, b"x"))]
        (f,) = run_sensor(self.pcap("long.pcap", recs))
        self.assertEqual(f["last_seen_us"] - f["first_seen_us"], 5003499711)
        self.assertEqual(round(f["flow_duration_ms"] * 1000), 5003499711)

    def test_active_timeout_snapshots(self):
        # A packet every 10 s for 150 s: never idle, so without an active
        # timeout the only record would come at the end.
        recs = [(T0 + 10 * i, udp_frame(*A, b"s" * 40)) for i in range(16)]
        pcap = self.pcap("active.pcap", recs)
        us = lambda s: int((T0 + s) * 1e6)
        default = run_sensor(pcap)                       # -A 60 by default
        # Snapshots taken when the t=60 and t=120 packets arrive (state up
        # to the previous packet, cumulative), then the final record.
        self.assertEqual([f["pkt_count"] for f in default], [6, 12, 16])
        self.assertEqual({f["first_seen_us"] for f in default}, {us(0)})
        self.assertEqual([f["last_seen_us"] for f in default], [us(50), us(110), us(150)])
        off = run_sensor(pcap, "-A", "0")
        self.assertEqual([f["pkt_count"] for f in off], [16])
        a30 = run_sensor(pcap, "-A", "30")
        self.assertEqual([f["pkt_count"] for f in a30], [3, 6, 9, 12, 15, 16])

    def test_no_snapshot_of_idle_flow(self):
        # Two packets 5000 s apart: the flow was idle, so no snapshot is
        # taken even though 5000 s > the active timeout.
        recs = [(T0, udp_frame(*A, b"x")), (T0 + 5000, udp_frame(*A, b"x"))]
        flows = run_sensor(self.pcap("idle.pcap", recs))
        self.assertEqual([f["pkt_count"] for f in flows], [2])

    def test_active_timeout_rejects_bad_values(self):
        for bad in ("abc", "-5", "100000"):
            p = subprocess.run([SENSOR, "-r", "/dev/null", "-A", bad],
                               capture_output=True, text=True, env=ENV)
            self.assertEqual(p.returncode, 1, bad)
            self.assertIn("-A must be", p.stderr)

    def test_ja4_still_reported_for_tls(self):
        path = os.path.join(HERE, "..", "..", "pcaps", "test_tls_full.pcap")
        (f,) = run_sensor(path)
        self.assertEqual(f["ja4_client"], "t12d6707h2_2955a3196ffa_c83f907a73d3")

if __name__ == "__main__":
    unittest.main(verbosity=2)
