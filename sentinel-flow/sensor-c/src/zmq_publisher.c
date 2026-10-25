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
static void *zmq_mon  = NULL;   /* PAIR socket receiving monitor events */
static int   peers    = 0;      /* currently connected consumers */

#define MON_ENDPOINT "inproc://sentinel-zmq-monitor"

/* Drain pending monitor events and update the connected-peer count. */
static void poll_monitor(void)
{
    if (!zmq_mon)
        return;
    unsigned char ev[6];
    char endpoint[256];
    for (;;) {
        int n = zmq_recv(zmq_mon, ev, sizeof(ev), ZMQ_DONTWAIT);
        if (n < 0)
            return;                                /* EAGAIN: no more events */
        /* Frame 2 is the endpoint string; always present. */
        (void)zmq_recv(zmq_mon, endpoint, sizeof(endpoint), 0);
        if (n < 2)
            continue;
        unsigned short id;
        memcpy(&id, ev, sizeof(id));               /* host byte order */
        if (id == ZMQ_EVENT_CONNECTED)
            peers++;
        else if (id == ZMQ_EVENT_DISCONNECTED && peers > 0)
            peers--;
    }
}

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

    /* Linger is set again at close, based on whether a consumer is
     * connected (zmq_publisher_destroy). */
    int linger = 2000;
    zmq_setsockopt(zmq_sock, ZMQ_LINGER, &linger, sizeof(linger));

    /* Bounded blocking send timeout: a retry without ZMQ_DONTWAIT
     * waits up to this long for the IPC handshake to complete. */
    int sndtimeo = 200;
    zmq_setsockopt(zmq_sock, ZMQ_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

    /* Watch connect/disconnect events so shutdown knows whether a
     * consumer is attached (see zmq_publisher_destroy). */
    if (zmq_socket_monitor(zmq_sock, MON_ENDPOINT,
                           ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED) == 0) {
        zmq_mon = zmq_socket(zmq_ctx, ZMQ_PAIR);
        if (zmq_mon && zmq_connect(zmq_mon, MON_ENDPOINT) != 0) {
            zmq_close(zmq_mon);
            zmq_mon = NULL;
        }
    }

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

static int degraded = 0;   /* set after a drop; cleared by the next success */

int zmq_publisher_send(const char *json_str, int patience_ms)
{
    if (!zmq_sock || !json_str)
        return -1;

    size_t len = strlen(json_str);
    if (zmq_send(zmq_sock, json_str, len, ZMQ_DONTWAIT) >= 0) {
        degraded = 0;
        return 0;
    }
    if (zmq_errno() != EAGAIN)
        return -1;

    /* Queue full (consumer slow) or peer not attached yet. Each blocking
     * attempt waits up to ZMQ_SNDTIMEO (200 ms). After a drop, until a
     * send succeeds again: PCAP replay tries once, live capture (patience
     * <= 200 ms) does not wait at all, so a stopped consumer cannot stall
     * the capture loop for 200 ms on every flow. */
    int attempts = (patience_ms + 199) / 200;
    if (attempts < 1)
        attempts = 1;
    if (degraded)
        attempts = patience_ms > 200 ? 1 : 0;
    for (int i = 0; i < attempts; i++) {
        if (zmq_send(zmq_sock, json_str, len, 0) >= 0) {
            degraded = 0;
            return 0;
        }
        if (zmq_errno() != EAGAIN)
            return -1;
    }
    degraded = 1;
    return -1;
}

/* ── Teardown ────────────────────────────────────────────────────── */

void zmq_publisher_destroy(int drain_ms)
{
    if (zmq_sock) {
        /* Linger decides what happens to messages still queued at close.
         * A consumer is connected -> wait up to drain_ms for it to take
         * them (a slow consumer used to lose the tail of every replay at
         * the old fixed 2 s). Nobody connected -> nothing can drain, so
         * give up after 500 ms instead of hanging. */
        poll_monitor();
        int linger = peers > 0 ? drain_ms : 500;
        zmq_setsockopt(zmq_sock, ZMQ_LINGER, &linger, sizeof(linger));
        fprintf(stderr, "[zmq] closing: %d consumer(s) connected, linger %d ms\n",
                peers, linger);
        if (zmq_mon) {
            zmq_socket_monitor(zmq_sock, NULL, 0);
            int zero = 0;
            zmq_setsockopt(zmq_mon, ZMQ_LINGER, &zero, sizeof(zero));
            zmq_close(zmq_mon);
            zmq_mon = NULL;
        }
        zmq_close(zmq_sock);
        zmq_sock = NULL;
    }
    if (zmq_ctx) {
        zmq_ctx_destroy(zmq_ctx);   /* blocks until linger expires or drained */
        zmq_ctx = NULL;
    }
    fprintf(stderr, "[zmq] publisher destroyed\n");
}
