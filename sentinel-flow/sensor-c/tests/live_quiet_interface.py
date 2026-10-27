#!/usr/bin/env python3
"""
Live test: the sensor must keep working on a QUIET interface.

Before the fix, pcap_dispatch() blocked until a packet arrived, so on an idle
interface (1) a finished flow was not exported until some other packet came
in, and (2) SIGTERM / Ctrl+C was ignored until then.

Uses a throwaway `dummy` interface: nothing ever arrives on it, and one UDP
packet sent to it is seen by the capture. The interface is removed at the end.

Checks:
  1. one UDP packet, then silence -> the flow is exported ~30 s later (idle
     timeout), with no other traffic
  2. SIGTERM -> the sensor exits within 3 s, with no traffic

Needs passwordless sudo (ip link, live capture). Usage:
  python3 sensor-c/tests/live_quiet_interface.py [path/to/sensor]
"""
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SENSOR = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "sensor"))
SINK = os.path.join(os.path.dirname(SENSOR), "zmq_sink")
NDPI_LIB = os.environ.get("NDPI_LIB", os.path.expanduser("~/nDPI/src/lib"))
IF, NET, PEER, PORT = "sfquiet0", "10.213.0.1/24", "10.213.0.2", 55890
EP = f"tcp://127.0.0.1:{PORT}"
IDLE_S, EXPORT_DEADLINE_S, EXIT_DEADLINE_S = 30, 45, 3


def sh(*cmd, check=True):
    return subprocess.run(["sudo", "-n", *cmd], check=check, capture_output=True, text=True)


def main():
    results, sink, sensor = [], None, None
    sh("ip", "link", "del", IF, check=False)
    sh("ip", "link", "add", IF, "type", "dummy")
    try:
        sh("ip", "addr", "add", NET, "dev", IF)
        sh("ip", "link", "set", IF, "up")
        sink = subprocess.Popen([SINK, "-n", "1", EP], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        sensor = subprocess.Popen(["sudo", "-n", "env", f"LD_LIBRARY_PATH={NDPI_LIB}", SENSOR,
                                   "-i", IF, "-z", EP], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, text=True)
        time.sleep(2)

        # 1. One packet, then nothing: the record must still arrive.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"quiet-interface-test", (PEER, 9))
        s.close()
        t0 = time.monotonic()
        try:
            line = sink.communicate(timeout=EXPORT_DEADLINE_S)[0].strip()
            took = time.monotonic() - t0
            rec = json.loads(line.splitlines()[0])
            ok = rec["dst_ip"] == PEER and IDLE_S - 1 <= took <= EXPORT_DEADLINE_S
            results.append((ok, f"flow exported {took:.1f} s after the only packet "
                                f"(expected ~{IDLE_S} s, no other traffic)"))
        except subprocess.TimeoutExpired:
            sink.kill()
            results.append((False, f"no record within {EXPORT_DEADLINE_S} s of silence "
                                   "(housekeeping waits for a packet)"))

        # 2. SIGTERM with no traffic: must exit promptly.
        pid = subprocess.run(["pgrep", "-P", str(sensor.pid)], capture_output=True,
                             text=True).stdout.split()
        target = pid[0] if pid else str(sensor.pid)
        t1 = time.monotonic()
        sh("kill", "-TERM", target)
        try:
            sensor.wait(timeout=EXIT_DEADLINE_S)
            results.append((True, f"SIGTERM -> exited in {time.monotonic() - t1:.1f} s"))
        except subprocess.TimeoutExpired:
            results.append((False, f"SIGTERM ignored for {EXIT_DEADLINE_S} s on a quiet interface"))
    finally:
        for p in (sink, sensor):
            if p and p.poll() is None:
                if p is sensor:
                    sh("pkill", "-KILL", "-P", str(p.pid), check=False)
                p.kill()
        sh("ip", "link", "del", IF, check=False)

    for ok, msg in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {msg}")
    left = subprocess.run(["ip", "link", "show", IF], capture_output=True).returncode
    print(f"[cleanup] interface {IF} {'removed' if left else 'STILL PRESENT'}")
    sys.exit(0 if results and all(ok for ok, _ in results) else 1)


if __name__ == "__main__":
    main()
