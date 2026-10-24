/*
 * cJSON — Minimal JSON library for C99
 * Compact reimplementation of the DaveGamble/cJSON API surface.
 *
 * Supports: create, parse, print (compact), and free JSON trees.
 */

#ifndef CJSON_H
#define CJSON_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── JSON type flags ─────────────────────────────────────────────── */
#define cJSON_Invalid  0
#define cJSON_False    (1 << 0)
#define cJSON_True     (1 << 1)
#define cJSON_NULL     (1 << 2)
#define cJSON_Number   (1 << 3)
#define cJSON_String   (1 << 4)
#define cJSON_Array    (1 << 5)
#define cJSON_Object   (1 << 6)
#define cJSON_Raw      (1 << 7)

/* Convenience mask: strips reference / string-is-const bits. */
#define cJSON_IsReference  256
#define cJSON_StringIsConst 512

/* ── Core structure ──────────────────────────────────────────────── */
typedef struct cJSON {
    struct cJSON *next;        /* sibling linked-list next           */
    struct cJSON *prev;        /* sibling linked-list prev           */
    struct cJSON *child;       /* head of child list (object/array)  */

    int    type;               /* one of the cJSON_ type flags       */

    char  *valuestring;        /* string value, if type == cJSON_String */
    int    valueint;           /* integer value (legacy)             */
    double valuedouble;        /* floating-point value               */

    char  *string;             /* key name when this item is a child
                                  of an object                       */
} cJSON;

/* ── Construction ────────────────────────────────────────────────── */
cJSON *cJSON_CreateObject(void);
cJSON *cJSON_CreateArray(void);
cJSON *cJSON_CreateString(const char *string);
cJSON *cJSON_CreateNumber(double num);
cJSON *cJSON_CreateBool(int boolean);
cJSON *cJSON_CreateNull(void);
cJSON *cJSON_CreateRaw(const char *raw);

/* ── Tree mutation ───────────────────────────────────────────────── */
void   cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);
void   cJSON_AddItemToArray(cJSON *array, cJSON *item);

/* Convenience helpers (return the added item, or NULL on failure). */
cJSON *cJSON_AddStringToObject(cJSON *object, const char *name, const char *value);
cJSON *cJSON_AddNumberToObject(cJSON *object, const char *name, double value);
cJSON *cJSON_AddRawToObject(cJSON *object, const char *name, const char *raw);
cJSON *cJSON_AddBoolToObject(cJSON *object, const char *name, int boolean);

/* ── Querying ────────────────────────────────────────────────────── */
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *object, const char *string);

/* ── Serialisation ───────────────────────────────────────────────── */
char  *cJSON_PrintUnformatted(const cJSON *item);

/* ── Parsing ─────────────────────────────────────────────────────── */
cJSON *cJSON_Parse(const char *value);

/* ── Cleanup ─────────────────────────────────────────────────────── */
void   cJSON_Delete(cJSON *item);
void   cJSON_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* CJSON_H */
