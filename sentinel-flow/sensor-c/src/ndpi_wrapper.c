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

/* TLS-family protocols whose dissector fills metadata.protos.tls_quic. */
static int is_tls_family(uint16_t id)
{
    switch (id) {
    case NDPI_PROTOCOL_TLS:        case NDPI_PROTOCOL_DTLS:
    case NDPI_PROTOCOL_QUIC:       case NDPI_PROTOCOL_DOH_DOT:
    case NDPI_PROTOCOL_MAIL_IMAPS: case NDPI_PROTOCOL_MAIL_POPS:
    case NDPI_PROTOCOL_MAIL_SMTPS: case NDPI_PROTOCOL_FTPS:
        return 1;
    default:
        return 0;
    }
}

/* JA4 = JA4_a "_" JA4_b "_" JA4_c, e.g. t13d1516h2_8daaf6152771_e5627efa2ab1
 * JA4_a: [tqd] + 2-char version + [di] + 2-digit ciphers + 2-digit
 * extensions + 2-char ALPN; JA4_b/JA4_c: 12 lowercase hex chars each. */
static int is_valid_ja4(const char *s)
{
    if (strnlen(s, 37) != 36   /* ja4_client is char[37] */ || s[10] != '_' || s[23] != '_')
        return 0;
    if (s[0] != 't' && s[0] != 'q' && s[0] != 'd')
        return 0;
    if (s[3] != 'd' && s[3] != 'i')
        return 0;
    for (int i = 4; i < 8; i++)
        if (s[i] < '0' || s[i] > '9') return 0;
    for (int i = 1; i < 36; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x21 || ch > 0x7e) return 0;          /* printable ASCII */
    }
    for (int i = 11; i < 36; i++) {
        if (i == 23) continue;
        char ch = s[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return 0;
    }
    return 1;
}

const char *ndpi_wrapper_get_ja4(const struct ndpi_flow_struct *flow,
                                 ndpi_protocol proto)
{
    if (!flow)
        return "N/A";

    /*
     * metadata.protos is a UNION shared by every dissector. Reading
     * tls_quic.ja4_client on e.g. an SSDP flow returns SSDP state as
     * if it were a string (observed: invalid UTF-8 in the JSON). Only
     * read it for TLS-family flows, and validate the format anyway.
     */
    if (!is_tls_family(proto.proto.master_protocol) &&
        !is_tls_family(proto.proto.app_protocol))
        return "N/A";

    const char *ja4 = flow->metadata.protos.tls_quic.ja4_client;
    return is_valid_ja4(ja4) ? ja4 : "N/A";
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
