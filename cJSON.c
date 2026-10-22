/*
 * cJSON — Minimal JSON library for C99  (implementation)
 *
 * Compact reimplementation covering: create, mutate, query, parse,
 * serialise (compact / unformatted), and free.
 */

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <ctype.h>

/* ================================================================
 *  Internal helpers
 * ================================================================ */

/* Portable strdup (not in C99). */
static char *cJSON_strdup(const char *s)
{
    size_t len;
    char  *copy;
    if (!s) return NULL;
    len  = strlen(s) + 1;
    copy = (char *)malloc(len);
    if (copy) memcpy(copy, s, len);
    return copy;
}

/* Allocate a zeroed cJSON node. */
static cJSON *cJSON_New_Item(void)
{
    cJSON *node = (cJSON *)calloc(1, sizeof(cJSON));
    return node;
}

/* ================================================================
 *  Cleanup
 * ================================================================ */

void cJSON_Delete(cJSON *item)
{
    cJSON *next;
    while (item) {
        next = item->next;
        /* Recurse into children (objects & arrays). */
        if (item->child) {
            cJSON_Delete(item->child);
        }
        if (item->valuestring) free(item->valuestring);
        if (item->string)      free(item->string);
        free(item);
        item = next;
    }
}

void cJSON_free(void *ptr)
{
    free(ptr);
}

/* ================================================================
 *  Construction
 * ================================================================ */

cJSON *cJSON_CreateObject(void)
{
    cJSON *item = cJSON_New_Item();
    if (item) item->type = cJSON_Object;
    return item;
}

cJSON *cJSON_CreateArray(void)
{
    cJSON *item = cJSON_New_Item();
    if (item) item->type = cJSON_Array;
    return item;
}

cJSON *cJSON_CreateString(const char *string)
{
    cJSON *item = cJSON_New_Item();
    if (item) {
        item->type        = cJSON_String;
        item->valuestring = cJSON_strdup(string ? string : "");
        if (!item->valuestring) { cJSON_Delete(item); return NULL; }
    }
    return item;
}

cJSON *cJSON_CreateNumber(double num)
{
    cJSON *item = cJSON_New_Item();
    if (item) {
        item->type        = cJSON_Number;
        item->valuedouble = num;
        item->valueint    = (num >= INT_MAX) ? INT_MAX
                          : (num <= INT_MIN) ? INT_MIN
                          : (int)num;
    }
    return item;
}

cJSON *cJSON_CreateBool(int boolean)
{
    cJSON *item = cJSON_New_Item();
    if (item) {
        item->type = boolean ? cJSON_True : cJSON_False;
    }
    return item;
}

cJSON *cJSON_CreateNull(void)
{
    cJSON *item = cJSON_New_Item();
    if (item) item->type = cJSON_NULL;
    return item;
}

/* ================================================================
 *  Tree mutation
 * ================================================================ */

/* Append `item` to the end of `child`'s sibling list inside `array`. */
static void suffix_object(cJSON *prev, cJSON *item)
{
    prev->next = item;
    item->prev = prev;
}

void cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
    cJSON *child;
    if (!array || !item) return;

    child = array->child;
    if (!child) {
        /* First element. */
        array->child = item;
        item->prev = item;  /* circular for quick tail access */
        item->next = NULL;
    } else {
        /* Append after the tail.  child->prev always points to tail. */
        cJSON *tail = child->prev;
        suffix_object(tail, item);
        child->prev = item;  /* keep head->prev == tail */
    }
}

void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)
{
    if (!object || !item || !string) return;
    /* Free any existing key name. */
    if (item->string) { free(item->string); }
    item->string = cJSON_strdup(string);
    cJSON_AddItemToArray(object, item);
}

cJSON *cJSON_AddStringToObject(cJSON *object, const char *name, const char *value)
{
    cJSON *str = cJSON_CreateString(value);
    if (!str) return NULL;
    cJSON_AddItemToObject(object, name, str);
    return str;
}

cJSON *cJSON_AddNumberToObject(cJSON *object, const char *name, double value)
{
    cJSON *num = cJSON_CreateNumber(value);
    if (!num) return NULL;
    cJSON_AddItemToObject(object, name, num);
    return num;
}

cJSON *cJSON_AddBoolToObject(cJSON *object, const char *name, int boolean)
{
    cJSON *b = cJSON_CreateBool(boolean);
    if (!b) return NULL;
    cJSON_AddItemToObject(object, name, b);
    return b;
}

/* ================================================================
 *  Querying
 * ================================================================ */

cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *object, const char *string)
{
    cJSON *cur;
    if (!object || !string) return NULL;
    cur = object->child;
    while (cur) {
        if (cur->string && strcmp(cur->string, string) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

/* ================================================================
 *  Serialisation  (compact / unformatted)
 * ================================================================ */

/*
 * A simple dynamic buffer used while printing.
 */
typedef struct {
    char  *buf;
    size_t len;     /* bytes written (excluding NUL) */
    size_t cap;     /* allocated capacity             */
} printbuf;

static printbuf *printbuf_new(void)
{
    printbuf *p = (printbuf *)malloc(sizeof(*p));
    if (!p) return NULL;
    p->cap = 256;
    p->buf = (char *)malloc(p->cap);
    if (!p->buf) { free(p); return NULL; }
    p->len = 0;
    p->buf[0] = '\0';
    return p;
}

/* (Kept for potential future use by formatted printing.)
static void printbuf_free(printbuf *p)
{
    if (p) { free(p->buf); free(p); }
}
*/

/* Ensure room for `need` more bytes (plus NUL). */
static int printbuf_ensure(printbuf *p, size_t need)
{
    if (p->len + need + 1 <= p->cap) return 1;
    size_t newcap = p->cap * 2;
    while (newcap < p->len + need + 1) newcap *= 2;
    char *tmp = (char *)realloc(p->buf, newcap);
    if (!tmp) return 0;
    p->buf = tmp;
    p->cap = newcap;
    return 1;
}

static void printbuf_append(printbuf *p, const char *s, size_t slen)
{
    if (!printbuf_ensure(p, slen)) return;
    memcpy(p->buf + p->len, s, slen);
    p->len += slen;
    p->buf[p->len] = '\0';
}

static void printbuf_append_str(printbuf *p, const char *s)
{
    printbuf_append(p, s, strlen(s));
}

/* Print a JSON-escaped string (with surrounding quotes). */
static void print_string(printbuf *p, const char *s)
{
    const char *ptr;
    printbuf_append(p, "\"", 1);
    if (s) {
        for (ptr = s; *ptr; ptr++) {
            switch (*ptr) {
                case '\"': printbuf_append_str(p, "\\\""); break;
                case '\\': printbuf_append_str(p, "\\\\"); break;
                case '\b': printbuf_append_str(p, "\\b");  break;
                case '\f': printbuf_append_str(p, "\\f");  break;
                case '\n': printbuf_append_str(p, "\\n");  break;
                case '\r': printbuf_append_str(p, "\\r");  break;
                case '\t': printbuf_append_str(p, "\\t");  break;
                default:
                    if ((unsigned char)*ptr < 0x20) {
                        char esc[8];
                        snprintf(esc, sizeof(esc), "\\u%04x",
                                 (unsigned char)*ptr);
                        printbuf_append_str(p, esc);
                    } else {
                        printbuf_append(p, ptr, 1);
                    }
                    break;
            }
        }
    }
    printbuf_append(p, "\"", 1);
}

/* Forward declaration. */
static void print_value(printbuf *p, const cJSON *item);

static void print_number(printbuf *p, const cJSON *item)
{
    char buf[64];
    double d = item->valuedouble;

    if (d == 0.0) {
        /* Avoid -0. */
        snprintf(buf, sizeof(buf), "0");
    } else if (fabs(d) < 1.0e-6 || fabs(d) > 1.0e9) {
        snprintf(buf, sizeof(buf), "%e", d);
    } else if (floor(d) == d && fabs(d) < 1.0e15) {
        snprintf(buf, sizeof(buf), "%.0f", d);
    } else {
        snprintf(buf, sizeof(buf), "%g", d);
    }
    printbuf_append_str(p, buf);
}

static void print_array(printbuf *p, const cJSON *item)
{
    cJSON *child = item->child;
    printbuf_append(p, "[", 1);
    while (child) {
        print_value(p, child);
        if (child->next) printbuf_append(p, ",", 1);
        child = child->next;
    }
    printbuf_append(p, "]", 1);
}

static void print_object(printbuf *p, const cJSON *item)
{
    cJSON *child = item->child;
    printbuf_append(p, "{", 1);
    while (child) {
        print_string(p, child->string);
        printbuf_append(p, ":", 1);
        print_value(p, child);
        if (child->next) printbuf_append(p, ",", 1);
        child = child->next;
    }
    printbuf_append(p, "}", 1);
}

static void print_value(printbuf *p, const cJSON *item)
{
    if (!item) { printbuf_append_str(p, "null"); return; }

    switch (item->type & 0xFF) {
        case cJSON_False:  printbuf_append_str(p, "false"); break;
        case cJSON_True:   printbuf_append_str(p, "true");  break;
        case cJSON_NULL:   printbuf_append_str(p, "null");  break;
        case cJSON_Number: print_number(p, item);           break;
        case cJSON_String: print_string(p, item->valuestring); break;
        case cJSON_Array:  print_array(p, item);            break;
        case cJSON_Object: print_object(p, item);           break;
        case cJSON_Raw:
            printbuf_append_str(p, item->valuestring ? item->valuestring : "");
            break;
        default:
            break;
    }
}

char *cJSON_PrintUnformatted(const cJSON *item)
{
    printbuf *p = printbuf_new();
    char *out;
    if (!p) return NULL;
    print_value(p, item);
    out = p->buf;
    /* Detach buffer before freeing the wrapper. */
    p->buf = NULL;
    free(p);
    return out;
}

/* ================================================================
 *  Parsing
 * ================================================================ */

/* Skip whitespace. */
static const char *skip_ws(const char *s)
{
    if (!s) return NULL;
    while (*s && (unsigned char)*s <= 0x20) s++;
    return s;
}

static const char *parse_value(cJSON *item, const char *value);

/* Parse a 4-hex-digit unicode escape into a UTF-8 sequence. Returns
   pointer past the 4 hex digits, or NULL on error.  `out` must have
   room for up to 3 bytes; *outlen receives the count written. */
static unsigned parse_hex4(const char *str)
{
    unsigned h = 0;
    for (int i = 0; i < 4; i++) {
        char c = str[i];
        h <<= 4;
        if      (c >= '0' && c <= '9') h |= (unsigned)(c - '0');
        else if (c >= 'A' && c <= 'F') h |= (unsigned)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') h |= (unsigned)(c - 'a' + 10);
        else return 0;
    }
    return h;
}

/* Parse a JSON string (expects `value` pointing at the opening '"'). */
static const char *parse_string(cJSON *item, const char *str)
{
    const char *ptr = str + 1; /* skip opening quote */
    size_t alloc = 64;
    size_t len   = 0;
    char *out    = (char *)malloc(alloc);
    if (!out) return NULL;

    while (*ptr && *ptr != '\"') {
        if (len + 6 >= alloc) {
            alloc *= 2;
            char *tmp = (char *)realloc(out, alloc);
            if (!tmp) { free(out); return NULL; }
            out = tmp;
        }
        if (*ptr == '\\') {
            ptr++;
            switch (*ptr) {
                case '\"': out[len++] = '\"'; break;
                case '\\': out[len++] = '\\'; break;
                case '/':  out[len++] = '/';  break;
                case 'b':  out[len++] = '\b'; break;
                case 'f':  out[len++] = '\f'; break;
                case 'n':  out[len++] = '\n'; break;
                case 'r':  out[len++] = '\r'; break;
                case 't':  out[len++] = '\t'; break;
                case 'u': {
                    unsigned uc = parse_hex4(ptr + 1);
                    ptr += 4;
                    /* Basic BMP encoding to UTF-8. */
                    if (uc < 0x80) {
                        out[len++] = (char)uc;
                    } else if (uc < 0x800) {
                        out[len++] = (char)(0xC0 | (uc >> 6));
                        out[len++] = (char)(0x80 | (uc & 0x3F));
                    } else {
                        out[len++] = (char)(0xE0 | (uc >> 12));
                        out[len++] = (char)(0x80 | ((uc >> 6) & 0x3F));
                        out[len++] = (char)(0x80 | (uc & 0x3F));
                    }
                    break;
                }
                default: out[len++] = *ptr; break;
            }
        } else {
            out[len++] = *ptr;
        }
        ptr++;
    }
    out[len] = '\0';
    if (*ptr == '\"') ptr++;

    item->type        = cJSON_String;
    item->valuestring = out;
    return ptr;
}

/* Parse a number. */
static const char *parse_number(cJSON *item, const char *num)
{
    double n = 0;
    int    sign = 1;
    int    scale = 0;
    int    subscale = 0;
    int    signsubscale = 1;

    if (*num == '-') { sign = -1; num++; }
    if (*num == '0') { num++; }
    else { while (*num >= '0' && *num <= '9') { n = n * 10.0 + (*num - '0'); num++; } }
    if (*num == '.') {
        num++;
        while (*num >= '0' && *num <= '9') {
            n = n * 10.0 + (*num - '0');
            scale--;
            num++;
        }
    }
    if (*num == 'e' || *num == 'E') {
        num++;
        if (*num == '+') num++;
        else if (*num == '-') { signsubscale = -1; num++; }
        while (*num >= '0' && *num <= '9') {
            subscale = subscale * 10 + (*num - '0');
            num++;
        }
    }

    /* Combine: number = +/- n * 10^(scale + subscale*sign) */
    n = sign * n * pow(10.0, scale + subscale * signsubscale);

    item->type        = cJSON_Number;
    item->valuedouble = n;
    item->valueint    = (n >= INT_MAX) ? INT_MAX
                      : (n <= INT_MIN) ? INT_MIN
                      : (int)n;
    return num;
}

/* Parse an array. */
static const char *parse_array(cJSON *item, const char *value)
{
    cJSON *child;
    item->type = cJSON_Array;
    value = skip_ws(value + 1); /* skip '[' */
    if (*value == ']') return value + 1; /* empty array */

    child = cJSON_New_Item();
    if (!child) return NULL;
    item->child = child;
    value = skip_ws(parse_value(child, skip_ws(value)));
    if (!value) return NULL;

    while (*value == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip_ws(parse_value(child, skip_ws(value + 1)));
        if (!value) return NULL;
    }

    /* Maintain head->prev == tail for append consistency. */
    item->child->prev = child;

    if (*value == ']') return value + 1;
    return NULL; /* malformed */
}

/* Parse an object. */
static const char *parse_object(cJSON *item, const char *value)
{
    cJSON *child;
    item->type = cJSON_Object;
    value = skip_ws(value + 1); /* skip '{' */
    if (*value == '}') return value + 1; /* empty object */

    child = cJSON_New_Item();
    if (!child) return NULL;
    item->child = child;

    /* Parse key string. */
    value = skip_ws(value);
    if (*value != '\"') return NULL;
    {
        /* Temporarily use `child` to hold the parsed key string. */
        value = parse_string(child, value);
        if (!value) return NULL;
        child->string      = child->valuestring;
        child->valuestring = NULL;
        child->type        = cJSON_Invalid;
    }

    value = skip_ws(value);
    if (*value != ':') return NULL;
    value = skip_ws(parse_value(child, skip_ws(value + 1)));
    if (!value) return NULL;

    while (*value == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next    = new_item;
        new_item->prev = child;
        child          = new_item;

        value = skip_ws(value + 1);
        if (*value != '\"') return NULL;
        value = parse_string(child, value);
        if (!value) return NULL;
        child->string      = child->valuestring;
        child->valuestring = NULL;
        child->type        = cJSON_Invalid;

        value = skip_ws(value);
        if (*value != ':') return NULL;
        value = skip_ws(parse_value(child, skip_ws(value + 1)));
        if (!value) return NULL;
    }

    item->child->prev = child; /* head->prev == tail */

    if (*value == '}') return value + 1;
    return NULL;
}

/* Parse any JSON value. */
static const char *parse_value(cJSON *item, const char *value)
{
    if (!value) return NULL;

    if (strncmp(value, "null", 4) == 0) {
        item->type = cJSON_NULL;
        return value + 4;
    }
    if (strncmp(value, "false", 5) == 0) {
        item->type = cJSON_False;
        return value + 5;
    }
    if (strncmp(value, "true", 4) == 0) {
        item->type = cJSON_True;
        return value + 4;
    }
    if (*value == '\"') {
        return parse_string(item, value);
    }
    if (*value == '[') {
        return parse_array(item, value);
    }
    if (*value == '{') {
        return parse_object(item, value);
    }
    if (*value == '-' || (*value >= '0' && *value <= '9')) {
        return parse_number(item, value);
    }

    return NULL; /* unrecognised token */
}

cJSON *cJSON_Parse(const char *value)
{
    cJSON *c;
    const char *end;
    if (!value) return NULL;

    c = cJSON_New_Item();
    if (!c) return NULL;

    end = parse_value(c, skip_ws(value));
    if (!end) {
        cJSON_Delete(c);
        return NULL;
    }
    return c;
}
