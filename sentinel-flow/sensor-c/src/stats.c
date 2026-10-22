/*
 * stats.c — Welford's online algorithm implementation
 *
 * The core logic is fully inlined in stats.h.  This translation unit
 * exists so the build system has a .c for the module and to provide
 * a non-inline fallback if LTO is disabled.
 */

#include "stats.h"

/* Intentionally empty — all functions are static inline in stats.h */
