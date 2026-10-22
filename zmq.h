/*
 * Minimal ZeroMQ C API header (compatible with libzmq 4.3.5)
 *
 * Provides declarations for PUSH/PULL/PUB/SUB sockets over IPC/TCP.
 * Link against -lzmq to resolve symbols.
 */

#ifndef __ZMQ_H_INCLUDED__
#define __ZMQ_H_INCLUDED__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Version
 * -------------------------------------------------------------------------- */

#define ZMQ_VERSION_MAJOR 4
#define ZMQ_VERSION_MINOR 3
#define ZMQ_VERSION_PATCH 5

/* --------------------------------------------------------------------------
 * Socket types
 * -------------------------------------------------------------------------- */

#define ZMQ_PUB     1
#define ZMQ_SUB     2
#define ZMQ_PULL    7
#define ZMQ_PUSH    8

/* --------------------------------------------------------------------------
 * Socket options
 * -------------------------------------------------------------------------- */

#define ZMQ_SUBSCRIBE   6
#define ZMQ_LINGER     17
#define ZMQ_SNDHWM     23
#define ZMQ_RCVHWM     24

/* --------------------------------------------------------------------------
 * Send/recv flags
 * -------------------------------------------------------------------------- */

#define ZMQ_DONTWAIT    1
#define ZMQ_SNDMORE     2

/* --------------------------------------------------------------------------
 * Context
 * -------------------------------------------------------------------------- */

void *zmq_ctx_new (void);
int   zmq_ctx_term (void *context);
int   zmq_ctx_destroy (void *context);

/* --------------------------------------------------------------------------
 * Sockets
 * -------------------------------------------------------------------------- */

void *zmq_socket (void *context, int type);
int   zmq_close (void *socket);

int   zmq_bind (void *socket, const char *endpoint);
int   zmq_connect (void *socket, const char *endpoint);

int   zmq_setsockopt (void *socket, int option_name,
                      const void *option_value, size_t option_len);

/* --------------------------------------------------------------------------
 * Message I/O
 * -------------------------------------------------------------------------- */

int   zmq_send (void *socket, const void *buf, size_t len, int flags);
int   zmq_recv (void *socket, void *buf, size_t len, int flags);

/* --------------------------------------------------------------------------
 * Error handling
 * -------------------------------------------------------------------------- */

int         zmq_errno (void);
const char *zmq_strerror (int errnum);

#ifdef __cplusplus
}
#endif

#endif /* __ZMQ_H_INCLUDED__ */
