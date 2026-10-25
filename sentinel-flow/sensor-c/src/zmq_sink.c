/*
 * zmq_sink.c — Minimal ZeroMQ PULL sink for SentinelFlow end-to-end test
 *
 * Binds a ZMQ_PULL socket, receives JSON flow records from the sensor
 * PUSH socket, and writes each one to stdout (one JSON object per line).
 *
 * Usage:
 *   ./zmq_sink [-n N] [endpoint]
 *   ./zmq_sink -n 1 ipc:///tmp/ndpi_flows.sock
 *
 * The sink is the persistent server: it binds the IPC endpoint. The
 * sensor connects to it, so starting the sink first is required.
 *
 * With -n N the sink exits cleanly (status 0) after receiving N messages.
 * Without -n it runs until SIGINT/SIGTERM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include "zmq.h"

static volatile int running = 1;

static void sig_handler(int s) { (void)s; running = 0; }

int main(int argc, char *argv[])
{
    long expected = -1;   /* -1 = run forever */
    int opt;

    while ((opt = getopt(argc, argv, "n:h")) != -1) {
        switch (opt) {
        case 'n':
            expected = strtol(optarg, NULL, 10);
            if (expected <= 0) {
                fprintf(stderr, "[zmq_sink] -n must be positive\n");
                return 1;
            }
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s [-n N] [endpoint]\n", argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    const char *endpoint = (optind < argc) ? argv[optind]
                                           : "ipc:///tmp/ndpi_flows.sock";

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    void *ctx  = zmq_ctx_new();
    void *sock = zmq_socket(ctx, ZMQ_PULL);

    /* Linger 0 on the sink side is fine — we only receive */
    int linger = 0;
    zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));

    /* No receive high-water mark. With the default (1000), a consumer
     * that reads our stdout slowly lets the queue fill; when the sensor
     * then disconnects, messages still in transit are discarded
     * (observed: 1001 of 1105 flows delivered). Unlimited keeps
     * accepting while stdout drains. Memory is bounded by the sender's
     * own queue (ZMQ_SNDHWM 10000). */
    int rcvhwm = 0;
    zmq_setsockopt(sock, ZMQ_RCVHWM, &rcvhwm, sizeof(rcvhwm));

    if (zmq_bind(sock, endpoint) != 0) {
        fprintf(stderr, "[zmq_sink] bind(%s) failed: %s\n",
                endpoint, zmq_strerror(zmq_errno()));
        zmq_close(sock);
        zmq_ctx_destroy(ctx);
        return 1;
    }

    fprintf(stderr, "[zmq_sink] listening on %s", endpoint);
    if (expected > 0)
        fprintf(stderr, " (expecting %ld message%s)", expected,
                expected == 1 ? "" : "s");
    fprintf(stderr, "\n");
    fflush(stderr);

    char buf[65536];
    long received = 0;

    while (running) {
        int n = zmq_recv(sock, buf, sizeof(buf) - 1, 0);
        if (n < 0) {
            if (running)
                fprintf(stderr, "[zmq_sink] recv error: %s\n",
                        zmq_strerror(zmq_errno()));
            break;
        }
        if ((size_t)n > sizeof(buf) - 1) {
            /* zmq_recv returns the full message length even when it cut
             * the message to fit buf: drop it instead of writing past buf
             * or passing on a truncated record. Still counted below, so
             * the "expecting N messages" exit is unchanged. */
            fprintf(stderr, "[zmq_sink] dropped a %d-byte message (max %zu)\n",
                    n, sizeof(buf) - 1);
        } else {
            buf[n] = '\0';
            printf("%s\n", buf);
            fflush(stdout);
        }
        received++;

        if (expected > 0 && received >= expected) {
            fprintf(stderr, "[zmq_sink] received %ld/%ld — exiting\n",
                    received, expected);
            break;
        }
    }

    zmq_close(sock);
    zmq_ctx_destroy(ctx);
    fprintf(stderr, "[zmq_sink] done\n");
    return 0;
}
