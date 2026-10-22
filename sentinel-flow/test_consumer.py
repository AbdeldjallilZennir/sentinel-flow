#!/usr/bin/env python3
"""
Simple ZMQ PULL consumer to capture flow JSON from the sensor.
"""
import zmq
import sys
import json

def main():
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "ipc:///tmp/ndpi_flows.sock"
    
    ctx = zmq.Context()
    sock = ctx.socket(zmq.PULL)
    sock.bind(endpoint)
    
    print(f"[consumer] listening on {endpoint}", file=sys.stderr)
    sys.stderr.flush()
    
    try:
        while True:
            msg = sock.recv_string()
            # Pretty-print each JSON flow
            try:
                flow = json.loads(msg)
                print(json.dumps(flow, indent=2))
            except:
                print(msg)
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        ctx.term()

if __name__ == '__main__':
    main()
