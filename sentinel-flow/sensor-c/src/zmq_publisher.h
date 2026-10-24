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
 * Send a JSON string. Tries non-blocking first; if the queue is full,
 * keeps retrying for up to patience_ms (in 200 ms steps). Returns 0 on
 * success, -1 if the message was dropped.
 */
int zmq_publisher_send(const char *json_str, int patience_ms);

/*
 * Close the socket and destroy the context. If a consumer is connected,
 * wait up to drain_ms for queued messages to be delivered; otherwise
 * give up after 500 ms.
 */
void zmq_publisher_destroy(int drain_ms);

#endif /* ZMQ_PUBLISHER_H */
