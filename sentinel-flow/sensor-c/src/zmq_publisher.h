/*
 * zmq_publisher.h — Non-blocking ZeroMQ PUSH socket for flow export
 */

#ifndef ZMQ_PUBLISHER_H
#define ZMQ_PUBLISHER_H

/*
 * Initialize the ZeroMQ context and PUSH socket bound to endpoint.
 * Returns 0 on success, -1 on failure.
 */
int zmq_publisher_init(const char *endpoint);

/*
 * Send a JSON string (non-blocking).  Returns 0 on success, -1 on
 * failure or EAGAIN (message dropped).
 */
int zmq_publisher_send(const char *json_str);

/*
 * Gracefully close the socket and destroy the context.
 */
void zmq_publisher_destroy(void);

#endif /* ZMQ_PUBLISHER_H */
