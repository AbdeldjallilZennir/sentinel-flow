/*
 * ndpi_wrapper.c — nDPI 6.x initialization, JA4 & risk extraction
 *
 * Wraps the nDPI detection module lifecycle and provides convenience
 * functions for protocol name formatting, JA4 retrieval, and risk
 * bitmask stringification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ndpi_wrapper.h"

/* ── Module-level state ──────────────────────────────────────────── */

static struct ndpi_detection_module_struct *ndpi_module = NULL;

/* ── Initialization ──────────────────────────────────────────────── */

int ndpi_wrapper_init(void)
{
    if (ndpi_module) {
        fprintf(stderr, "[ndpi] already initialized\n");
        return 0;
    }

    /*
     * ndpi_init_detection_module(global_ctx, license_type)
     * Pass NULL for global context (single-threaded sensor).
     * Use NOT_FOR_PROFIT license for open-source / academic use.
     */
    ndpi_module = ndpi_init_detection_module(NULL,
                                             NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
    if (!ndpi_module) {
        fprintf(stderr, "[ndpi] ndpi_init_detection_module() failed\n");
        return -1;
    }

    /*
     * Finalize: loads all internal dissectors and protocol tables.
     * Must be called before any ndpi_detection_process_packet().
     */
    if (ndpi_finalize_initialization(ndpi_module) != 0) {
        fprintf(stderr, "[ndpi] ndpi_finalize_initialization() failed\n");
        ndpi_exit_detection_module(ndpi_module);
        ndpi_module = NULL;
        return -1;
    }

    fprintf(stderr, "[ndpi] detection module initialized (nDPI %s)\n",
            ndpi_revision());
    return 0;
}

/* ── Teardown ────────────────────────────────────────────────────── */

void ndpi_wrapper_destroy(void)
{
    if (ndpi_module) {
        ndpi_exit_detection_module(ndpi_module);
        ndpi_module = NULL;
        fprintf(stderr, "[ndpi] detection module destroyed\n");
    }
}

/* ── Access ──────────────────────────────────────────────────────── */

struct ndpi_detection_module_struct *ndpi_wrapper_get_module(void)
{
    return ndpi_module;
}

/* ── Flow Allocation ─────────────────────────────────────────────── */

struct ndpi_flow_struct *ndpi_wrapper_alloc_flow(void)
{
    struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)
        ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flow) {
        memset(flow, 0, SIZEOF_FLOW_STRUCT);
    }
    return flow;
}

void ndpi_wrapper_free_flow(struct ndpi_flow_struct *flow)
{
    if (flow) {
        /*
         * Just call ndpi_flow_free() to free the struct memory.
         * nDPI examples don't call ndpi_free_flow_data() for simple
         * cases where metadata is managed by nDPI internally.
         */
        ndpi_flow_free(flow);
    }
}

/* ── Protocol Name ───────────────────────────────────────────────── */

char *ndpi_wrapper_protocol_name(ndpi_protocol proto,
                                 char *buf, size_t buflen)
{
    if (!ndpi_module || !buf || buflen == 0) {
        if (buf && buflen > 0) buf[0] = '\0';
        return buf;
    }

    char *name = ndpi_protocol2name(ndpi_module, proto.proto, buf, (u_int)buflen);
    return name ? name : buf;
}

/* ── JA4 Fingerprint ─────────────────────────────────────────────── */

const char *ndpi_wrapper_get_ja4(const struct ndpi_flow_struct *flow)
{
    if (!flow)
        return "N/A";

    /*
     * ja4_client is stored in the TLS/QUIC metadata section.
     * It's a 36-char fingerprint string.
     */
    const char *ja4 = flow->metadata.protos.tls_quic.ja4_client;
    if (ja4[0] != '\0')
        return ja4;

    return "N/A";
}

/* ── Risk Bitmask ────────────────────────────────────────────────── */

ndpi_risk ndpi_wrapper_get_risk(const struct ndpi_flow_struct *flow)
{
    if (!flow)
        return 0;
    return flow->core.risk;
}

char *ndpi_wrapper_risk_to_str(ndpi_risk risk, char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return buf;

    buf[0] = '\0';
    if (risk == 0)
        return buf;

    size_t offset = 0;

    for (int i = 0; i < 64 && offset < buflen - 1; i++) {
        if (risk & ((ndpi_risk)1 << i)) {
            const char *name = ndpi_risk2str((ndpi_risk_enum)i);
            if (name) {
                int written = snprintf(buf + offset, buflen - offset,
                                       "%s%s",
                                       (offset > 0) ? ", " : "",
                                       name);
                if (written > 0)
                    offset += (size_t)written;
            }
        }
    }

    return buf;
}
