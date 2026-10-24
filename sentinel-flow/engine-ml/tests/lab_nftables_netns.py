#!/usr/bin/env python3
"""
Lab test for the nftables mitigation backend, on real packets, in two
throwaway network namespaces (the host's own ruleset is never touched):

   sf_remote                                   sf_victim
   203.0.113.66  ("C2", gets blocked)          192.168.50.10  (protected host)
   203.0.113.10  ("benign")    veth-r <==> veth-v       nftables table inet sentinel
                                                         UDP listener :9999

Checks:
  1. Mitigator turns a scored C2 record into an nft set element for .66
  2. Inbound: N UDP packets from .66 -> 0 delivered, nft counter == N pkts
     and N * (20 + 8 + payload) bytes; N packets from .10 -> N delivered
  3. Outbound: victim -> .66 dropped (counter grows), victim -> .10 passes
  4. A 3 s block expires on its own; refresh() logs "expire"; traffic flows
  5. Manual unblock removes the element

Needs passwordless sudo (ip netns, nft). Usage:
  python3 engine-ml/tests/lab_nftables_netns.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import mitigator  # noqa: E402

V, R = "sf_victim", "sf_remote"
VICTIM, C2, BENIGN = "192.168.50.10", "203.0.113.66", "203.0.113.10"
PORT, PAYLOAD, N = 9999, 100, 50
PY = "/usr/bin/python3"

SEND = r"""
import socket, sys
src, dst, port, n, size = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 0))
for i in range(n): s.sendto(b"x" * size, (dst, port))
"""
LISTEN = r"""
import socket, sys, collections, time, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", int(sys.argv[1])))
s.settimeout(0.2); seen = collections.Counter(); end = time.time() + float(sys.argv[2])
while time.time() < end:
    try: _, (ip, _) = s.recvfrom(4096); seen[ip] += 1
    except socket.timeout: pass
print(json.dumps(seen))
"""


def sh(*cmd, check=True, **kw):
    p = subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {p.stderr.strip()}")
    return p


def ns(name, *cmd, **kw):
    return sh("ip", "netns", "exec", name, *cmd, **kw)


def setup_lab():
    for n in (V, R):
        sh("ip", "netns", "add", n)
    sh("ip", "link", "add", "veth-v", "netns", V, "type", "veth", "peer", "name", "veth-r", "netns", R)
    ns(V, "ip", "addr", "add", f"{VICTIM}/24", "dev", "veth-v")
    ns(R, "ip", "addr", "add", "192.168.50.1/24", "dev", "veth-r")
    for ip in (C2, BENIGN):
        ns(R, "ip", "addr", "add", f"{ip}/32", "dev", "veth-r")
    for n, dev in ((V, "veth-v"), (R, "veth-r")):
        ns(n, "ip", "link", "set", dev, "up")
        ns(n, "ip", "link", "set", "lo", "up")
    ns(V, "ip", "route", "add", "203.0.113.0/24", "via", "192.168.50.1")


def teardown_lab():
    for n in (V, R):
        sh("ip", "netns", "del", n, check=False)


def wave(senders, listen_s=2.0):
    """senders: [(src_ns, src_ip, dst_ip)]; returns {src_ip: received} at the victim."""
    with tempfile.TemporaryDirectory() as d:
        lp, sp = os.path.join(d, "l.py"), os.path.join(d, "s.py")
        open(lp, "w").write(LISTEN); open(sp, "w").write(SEND)
        os.chmod(d, 0o755); os.chmod(lp, 0o644); os.chmod(sp, 0o644)
        lst = subprocess.Popen(["sudo", "-n", "ip", "netns", "exec", V, PY, lp, str(PORT),
                                str(listen_s)], stdout=subprocess.PIPE, text=True)
        time.sleep(0.4)
        for src_ns, src, dst in senders:
            ns(src_ns, PY, sp, src, dst, str(PORT), str(N), str(PAYLOAD))
        out, _ = lst.communicate(timeout=listen_s + 5)
    return json.loads(out)


def send_out(dst):
    """Victim -> dst, N packets; returns True if sendto() raised (nft drop on output)."""
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "s.py"); open(sp, "w").write(SEND)
        os.chmod(d, 0o755); os.chmod(sp, 0o644)
        p = ns(V, PY, sp, VICTIM, dst, str(PORT), str(N), str(PAYLOAD), check=False)
    return p.returncode != 0, p.stderr.strip().splitlines()[-1:] if p.stderr else []


def main():
    results = {}
    teardown_lab()
    setup_lab()
    try:
        events = []

        class Sink:
            def write_event(self, row):
                events.append(row)

        backend = mitigator.NftablesBackend(default_timeout_s=900, netns=V)
        mit = mitigator.Mitigator(mitigator.BlockPolicy(), backend, timeout_s=900,
                                  sinks=[Sink()], refresh_s=0)
        print(f"[lab] namespaces {V}/{R} up; nft table created in {V}")

        # Baseline: everything passes before any block.
        base = wave([(R, C2, VICTIM), (R, BENIGN, VICTIM)])
        print(f"[baseline] received at victim: {base}")
        results["baseline"] = base

        # 1. Scored C2 record -> block.
        rec = {"src_ip": VICTIM, "src_port": 50000, "dst_ip": C2, "dst_port": 443,
               "app_protocol": "TLS", "ml_anomaly_score": 0.97, "ndpi_risk_mask": 0,
               "ml_model": "lgbm+iforest-fv1-lab"}
        mit.process([rec])
        blocked = backend.list()
        print(f"[block] events: {[(e['action'], e['ip'], e['reason']) for e in events]}")
        print(f"[block] nft set: {blocked}")
        results["set_after_block"] = blocked

        # 2. Inbound wave.
        got = wave([(R, C2, VICTIM), (R, BENIGN, VICTIM)])
        k = backend.list()[C2]
        print(f"[inbound] sent {N} from each; received at victim: {got}; "
              f"nft counter for {C2}: packets={k['packets']} bytes={k['bytes']} "
              f"(expected {N} and {N * (20 + 8 + PAYLOAD)})")
        results["inbound"] = {"received": got, "counter": k}

        # 3. Outbound.
        out_c2 = send_out(C2)
        out_benign = send_out(BENIGN)
        k2 = backend.list()[C2]
        print(f"[outbound] victim->{C2}: send failed={out_c2[0]} {out_c2[1]}; "
              f"victim->{BENIGN}: send failed={out_benign[0]}; "
              f"nft counter now packets={k2['packets']} bytes={k2['bytes']}")
        results["outbound"] = {"c2_send_failed": out_c2[0], "benign_send_failed": out_benign[0],
                               "counter": k2}

        # Counter refresh logs a "counters" event.
        mit.refresh()

        # 4. Expiry: short block on the benign address.
        backend.block(BENIGN, 3, mitigator.REASON_MANUAL, "expiry test")
        mit.refresh()
        during = wave([(R, BENIGN, VICTIM)], listen_s=1.0)
        time.sleep(3.5)
        mit.refresh()
        after = wave([(R, BENIGN, VICTIM)], listen_s=1.0)
        print(f"[expiry] 3 s block on {BENIGN}: received during={during} after={after}; "
              f"set now: {sorted(backend.list())}")
        results["expiry"] = {"during": during, "after": after}

        # 5. Manual unblock of the C2.
        ev = mit.unblock(C2)
        again = wave([(R, C2, VICTIM)], listen_s=1.0)
        print(f"[unblock] {ev['action']} {ev['ip']} final dropped_pkts={ev['dropped_pkts']} "
              f"bytes={ev['dropped_bytes']}; received after unblock: {again}")
        results["unblock"] = {"event": ev, "received": again}
        print("[events] " + ", ".join(f"{e['action']}:{e['ip']}" for e in events))
        results["events"] = [(e["action"], e["ip"], e["dropped_pkts"]) for e in events]
        ruleset = ns(V, "nft", "list", "table", "inet", "sentinel").stdout
        print("[ruleset]\n" + ruleset)
    finally:
        teardown_lab()
        left = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
        print(f"[cleanup] lab namespaces remaining: {[l for l in left.split() if l.startswith('sf_')]}")
    return results


if __name__ == "__main__":
    main()
