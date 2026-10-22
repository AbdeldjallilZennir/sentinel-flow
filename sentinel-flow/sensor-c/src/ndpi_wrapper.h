/*
 * ndpi_wrapper.h — nDPI 6.x initialization & per-packet dissection API
 */

#ifndef NDPI_WRAPPER_H
#define NDPI_WRAPPER_H

#include <ndpi_api.h>

/* ── Lifecycle ───────────────────────────────────────────────────── */

/*
 * Initialize the nDPI detection module with all protocol dissectors.
 * Returns 0 on success, -1 on failure (logs the error).
 */
int ndpi_wrapper_init(void);

/*
 * Tear down the nDPI module and free resources.
 */
void ndpi_wrapper_destroy(void);

/* ── Access ──────────────────────────────────────────────────────── */

/*
 * Return the global detection module pointer (needed for per-flow
 * calls like ndpi_detection_process_packet).
 */
struct ndpi_detection_module_struct *ndpi_wrapper_get_module(void);

/*
 * Allocate a fresh ndpi_flow_struct (zeroed).
 * The caller is responsible for freeing it with ndpi_wrapper_free_flow().
 */
struct ndpi_flow_struct *ndpi_wrapper_alloc_flow(void);

/*
 * Free an ndpi_flow_struct previously allocated with alloc_flow().
 */
void ndpi_wrapper_free_flow(struct ndpi_flow_struct *flow);

/*
 * Format the detected protocol as a human-readable string into buf.
 * Returns buf.
 */
char *ndpi_wrapper_protocol_name(ndpi_protocol proto, char *buf, size_t buflen);

/*
 * Retrieve the JA4 client fingerprint from a completed flow.
 * Returns a pointer to an internal static/flow buffer, or "N/A".
 */
const char *ndpi_wrapper_get_ja4(const struct ndpi_flow_struct *flow);

/*
 * Retrieve the risk bitmask from a completed flow.
 */
ndpi_risk ndpi_wrapper_get_risk(const struct ndpi_flow_struct *flow);

/*
 * Format risk bitmask as a human-readable comma-separated string.
 * Returns buf (empty string if no risks).
 */
char *ndpi_wrapper_risk_to_str(ndpi_risk risk, char *buf, size_t buflen);

#endif /* NDPI_WRAPPER_H */
