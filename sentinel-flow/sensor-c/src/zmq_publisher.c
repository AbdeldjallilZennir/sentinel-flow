/*
 * zmq_publisher.c — Non-blocking ZeroMQ PUSH socket for flow export
 *
 * Binds a ZMQ_PUSH socket to an IPC endpoint and sends serialized
 * JSON flow records.  Non-blocking sends ensure the packet-capture
 * loop is never stalled by a slow or absent consumer.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "zmq.h"
#include "zmq_publisher.h"

/* ── Module-level state ──────────────────────────────────────────── */

static void *zmq_ctx  = NULL;
static void *zmq_sock = NULL;

/* ── Initialization ──────────────────────────────────────────────── */

int zmq_publisher_init(const char *endpoint)
{
    if (zmq_ctx) {
        fprintf(stderr, "[zmq] already initialized\n");
        return 0;
    }

    zmq_ctx = zmq_ctx_new();
    if (!zmq_ctx) {
        fprintf(stderr, "[zmq] zmq_ctx_new() failed: %s\n",
                zmq_strerror(zmq_errno()));
        return -1;
    }

    zmq_sock = zmq_socket(zmq_ctx, ZMQ_PUSH);
    if (!zmq_sock) {
        fprintf(stderr, "[zmq] zmq_socket(PUSH) failed: %s\n",
                zmq_strerror(zmq_errno()));
        zmq_ctx_destroy(zmq_ctx);
        zmq_ctx = NULL;
        return -1;
    }

    /* Set a send high-water mark so we drop rather than block */
    int hwm = 10000;
    zmq_setsockopt(zmq_sock, ZMQ_SNDHWM, &hwm, sizeof(hwm));

    /* Linger 2 s so queued messages are flushed before close. */
    int linger = 2000;
    zmq_setsockopt(zmq_sock, ZMQ_LINGER, &linger, sizeof(linger));

    /* Bounded blocking send timeout: a retry without ZMQ_DONTWAIT
     * waits up to this long for the IPC handshake to complete. */
    int sndtimeo = 200;
    zmq_setsockopt(zmq_sock, ZMQ_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

    /* Connect — the sink (persistent server) binds the endpoint. */
    if (zmq_connect(zmq_sock, endpoint) != 0) {
        fprintf(stderr, "[zmq] zmq_connect(%s) failed: %s\n",
                endpoint, zmq_strerror(zmq_errno()));
        zmq_close(zmq_sock);
        zmq_ctx_destroy(zmq_ctx);
        zmq_sock = NULL;
        zmq_ctx  = NULL;
        return -1;
    }

    /* Give the ZMQ background thread time to complete the IPC
     * handshake with the sink before the capture loop starts.
     * Without this, an offline PCAP finishes before any peer is
     * attached and the queued messages are dropped at close. */
    usleep(100000);

    fprintf(stderr, "[zmq] PUSH socket connected to %s\n", endpoint);
    return 0;
}

/* ── Send ────────────────────────────────────────────────────────── */

int zmq_publisher_send(const char *json_str)
{
    if (!zmq_sock || !json_str)
        return -1;

    size_t len = strlen(json_str);
    int rc = zmq_send(zmq_sock, json_str, len, ZMQ_DONTWAIT);

    if (rc < 0 && zmq_errno() == EAGAIN) {
        /* Peer not yet attached — retry once with a bounded block
         * (ZMQ_SNDTIMEO is 200 ms). This covers the offline-PCAP
         * race where the sender finishes before the handshake. */
        rc = zmq_send(zmq_sock, json_str, len, 0);
    }

    if (rc < 0)
        return -1;

    return 0;
}

/* ── Teardown ────────────────────────────────────────────────────── */

void zmq_publisher_destroy(void)
{
    if (zmq_sock) {
        zmq_close(zmq_sock);
        zmq_sock = NULL;
    }
    if (zmq_ctx) {
        zmq_ctx_destroy(zmq_ctx);
        zmq_ctx = NULL;
    }
    fprintf(stderr, "[zmq] publisher destroyed\n");
}
