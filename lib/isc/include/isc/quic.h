/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/sockaddr.h>
#include <isc/tls.h>

/* 1 hour in nanoseconds */
#define ISC_QUIC_SESSION_REGULAR_TOKEN_VALIDITY_PERIOD \
	((uint64_t)3600 * 1000000000)

/*
 * Here you can find a general overview of the ISC QUIC session
 * (connection) management framework.
 *
 * ### Core Design Philosophy
 *
 * This framework provides an implementation of a QUIC connection
 * object, referred to as `isc_quic_session_t`. It is built upon the
 * `ngtcp2` library to handle the core QUIC protocol logic, but it
 * introduces an abstraction layer that decouples the QUIC
 * connection's state management from direct network I/O operations.
 *
 * The central design is based on an explicit **state machine**. A
 * QUIC session progresses through a series of states, such as
 * `INITIAL`, `HANDSHAKE`, `CONNECTED`, and `CLOSING`. Transitions
 * between these states are driven by specific events, which are
 * triggered either by the user calling an API function (e.g.,
 * processing an incoming packet) or by internal mechanisms like
 * timers (e.g., detecting a handshake timeout).
 *
 * This deliberate separation from networking code is a key
 * feature. The framework does not create sockets, send or receive
 * packets, or manage timers on its own.  Instead, it relies on a
 * comprehensive set of callbacks provided by the user during session
 * creation (`isc_quic_session_interface_t`). This design simplifies
 * unit testing. By controlling the inputs (incoming packets, timer
 * events) and observing the outputs (outgoing packets, callback
 * invocations), it is possible to deterministically simulate a wide
 * range of network conditions and connection scenarios without
 * requiring an actual network or using a networking stack.
 *
 * ### Asynchronous Operation and Packet Generation
 *
 * A fundamental principle of this framework is its asynchronous,
 * event-driven nature. Most API functions, particularly those related
 * to sending data, do not immediately result in the generation of an
 * outgoing network packet. Instead, these functions typically queue
 * an operation or modify the internal state of the session
 * object. For example, `isc_quic_session_send_data()` adds data to a
 * send queue for a specific stream but does not attempt to packetize
 * or transmit it.
 *
 * Actual packet generation is confined to a small, well-defined set
 * of functions.  The user must explicitly call these functions to
 * process the internal queues and state changes, which may then
 * produce a packet to be sent on the network.
 *
 * The primary functions that can generate outgoing packets are:
 *
 * - `isc_quic_session_connect()`: Initiates a client connection and
 * creates the * initial packet.
 *
 * - `isc_quic_session_read_pkt()`: Processes an incoming packet. This
 * can result in an immediate response packet (e.g., an
 * acknowledgment, a handshake message, or a connection close frame).
 *
 * - `isc_quic_session_write_pkt()`: Attempts to drain the pending
 * data queues (from `isc_quic_session_send_data()` calls) and other
 * pending frames (like `ACKs` or `STREAM` control frames) into one or
 * more packets. This is the main function for sending application
 * data.
 *
 * - `isc_quic_session_on_expiry_timer()`: Handles timer-based events,
 * such as retransmissions, path validation probes, or idle
 * timeouts. This call is critical for a functioning connection and
 * frequently generates packets.
 *
 * - `isc_quic_session_update_expiry_timer()`: Recalculates and
 *   restarts the expiry timer on reads and writes.
 *
 * - `isc_quic_session_shutdown()`: Initiates a graceful connection
 * termination and generates a `CONNECTION_CLOSE` packet.
 *
 * ### Typical Usage Flow
 *
 * 1.  **Initialization**: The user creates a session object using
 * `isc_quic_session_create()`, providing a set of callbacks,
 * cryptographic secrets, and transport parameters.
 *
 * 2.  **Driving the Connection**: The user is responsible for the
 * main event loop.
 *
 * - **Receiving Data**: When a UDP datagram arrives from the network,
 * the user decodes its header to identify the target QUIC session
 * (via CID) and then passes the packet to
 * `isc_quic_session_read_pkt()` for processing. This function may
 * populate the provided `isc_quic_out_pkt_t` structure with a
 * response packet that the user must then send.
 *
 * - **Sending Data**: To send data, the user first opens a stream
 * with `isc_quic_session_open_stream()` and then queues data using
 * `isc_quic_session_send_data()`. To get this data onto the wire, the
 * user must periodically call `isc_quic_session_write_pkt()`, which
 * will create packets from the queued data as permitted by QUIC's
 * flow and congestion control mechanisms.
 *
 * - **Handling Timers**: The framework will invoke the
 * `expiry_timer_start` callback to request a timer. The user must
 * manage this timer and, upon its expiration, must call
 * `isc_quic_session_on_expiry_timer()`. This handles time-sensitive
 * protocol logic like retransmissions and is essential for connection
 * health. The call may also produce a packet to be
 * sent. `isc_quic_session_update_expiry_timer()` must be called on
 * data reads and writes.
 *
 * 3.  **Connection Shutdown**: To close the connection, the user
 * calls `isc_quic_session_shutdown()`, which generates a final
 * packet. The session then enters a closing/draining period, managed
 * via the `on_conn_close` callback, before it can be fully destroyed.
 *
 * ### The Callback Interface
 *
 * The `isc_quic_session_interface_t` structure is the cornerstone of
 * this framework's design. It defines a contract that the
 * higher-level code must fulfil. By providing a set of function
 * pointers, the higher level code gives the QUIC session object the
 * tools it needs to interact with the outside world, such as getting
 * the current time, managing timers, and, most importantly, routing
 * packets.
 *
 * The callbacks can be grouped by function:
 *
 * - **System and Timer Integration**:
 *
 * - `get_current_ts`: Must return a high-resolution (nanosecond
 * precision), * monotonic timestamp. This is fundamental for all
 * time-based QUIC mechanisms, including RTT estimation, packet
 * retransmission, and idle detection.
 *
 * - `expiry_timer_start` / `expiry_timer_stop`: The QUIC session does
 * not manage timers itself. It uses these callbacks to ask the
 * application to start or stop a single expiry timer. The application
 * is responsible for calling `isc_quic_session_on_expiry_timer()`
 * when the timer fires.
 *
 * -   **Connection ID (CID) Management**:
 *
 * - `gen_unique_cid`: Called when the session needs to generate a new
 * CID for its own use. The application must ensure this CID is
 * globally unique across all active connections.
 *
 * - `assoc_conn_cid` / `deassoc_conn_cid`: These callbacks are
 * central to packet routing. The application must maintain a global
 * table that maps all active CIDs to their corresponding
 * `isc_quic_session_t` objects. These callbacks are used to add and
 * remove entries from that table as CIDs are created and retired by
 * the session.
 *
 * - **High-Level Connection and Stream Events**: These callbacks
 * notify the application about significant events in the session's
 * lifecycle, allowing it to manage application state accordingly.
 *
 * - `on_handshake`: Notifies the the application that the QUIC and
 * TLS handshakes have successfully completed and the connection is
 * ready for application data.
 *
 * - `on_remote_stream_open`: Informs the application that the peer
 * has opened a new stream.
 *
 * - `on_recv_stream_data`: Delivers incoming application data from a
 * specific stream.
 *
 * - `on_stream_close`: Signals that a stream has been fully closed.
 *
 * - `on_conn_close`: Signals that the entire connection has been
 * terminated and will soon be de-allocated.
 *
 * - `on_new_regular_token` (client-only): Delivers a new token from
 * the server that can be used to accelerate future connection
 * establishment.
 *
 * ### Connection ID (CID) Management
 *
 * In QUIC, CIDs are used to route packets to the correct connection,
 * even if the client's network address changes (in the case of
 * connection migration). This framework implements a two-level
 * management system for CIDs.
 *
 * 1.  **Session-Local Management**: Each `isc_quic_session_t` object
 * keeps track of the CIDs that it has issued and the CIDs issued by
 * its peer for this specific connection.
 *
 * 2.  **Application-Global Management**: The framework delegates the
 * responsibility for global CID-to-session mapping to the application
 * via the `assoc_conn_cid` and `deassoc_conn_cid` callbacks. When a
 * packet arrives, the application is expected to parse the
 * destination CID, look it up in its global table, and forward the
 * packet to the correct session object.
 *
 * The `isc_quic_cid_t` object represents a CID. These objects are
 * reference-counted, and their lifecycle is managed by the paired
 * `isc_quic_cid_attach()` and `isc_quic_cid_detach()` functions.
 *
 * ### Stream Management
 *
 * Streams are the primary abstraction for sending and receiving
 * application data over a QUIC connection. They provide reliable,
 * ordered byte-stream delivery.  Streams can be unidirectional or
 * bidirectional.
 *
 * - **Opening a Local Stream**: An application initiates a new local
 * stream by calling `isc_quic_session_open_stream()`. This returns a
 * unique stream ID that is used in subsequent
 * calls. Application-specific context can be associated with a stream
 * using `isc_quic_session_set_stream_user_data()`.
 *
 * - **Receiving a Remote Stream**: When the peer opens a stream, the
 * `on_remote_stream_open` callback is invoked, informing the
 * application of the new stream's ID.
 *
 * - **Sending Data**: Data is sent by calling
 * `isc_quic_session_send_data()`.  This is an asynchronous operation
 * that queues the data for sending. The `fin` flag can be set to
 * signal the end of the stream from the local side. The success or
 * failure of the send operation is eventually reported through the
 * provided `isc_quic_send_cb_t` callback, which is invoked after the
 * data has been acknowledged by the peer.
 *
 * - **Receiving Data**: Incoming data is delivered to the application
 * via the `on_recv_stream_data` callback. The data may arrive in
 * multiple chunks. The `fin` flag in this callback indicates that the
 * peer has finished sending data on this stream.
 *
 * - **Closing a Stream**: A stream can be shut down gracefully by
 * sending data with the `fin` flag set. For an abrupt termination,
 * `isc_quic_session_shutdown_stream()` can be used. In all cases, the
 * `on_stream_close` callback provides the final notification that the
 * stream is no longer active.
 *
 * ### The Expiry Timer Concept
 *
 * The QUIC protocol is heavily dependent on timers to manage its
 * state, detect packet loss, and ensure the connection remains
 * healthy. This framework consolidates all time-based logic into a
 * single, crucial mechanism known as the **expiry timer**. It is the
 * primary "heartbeat" that drives the connection forward in the
 * absence of network activity.
 *
 * A fundamental design choice of this framework is that it does not
 * implement any timers itself. Instead, it offloads this
 * responsibility entirely to the application through a set of
 * callbacks. The session object calculates *when* the next
 * time-sensitive event should occur and instructs the application to
 * notify it when that time has arrived.
 *
 * #### What the Expiry Timer Manages
 *
 * The expiry timer is not for a single purpose; it represents the
 * deadline for the *next scheduled event*, whichever comes
 * first. These events include:
 *
 * - **Packet Loss Detection and Retransmission**: When the session
 * sends a packet containing data that requires acknowledgment, it
 * sets a Packet Loss Timeout (PTO). If an acknowledgment is not
 * received within this period, the packet is considered lost. The
 * expiry timer is set to this deadline. When the timer fires, the
 * framework marks the packet as lost and queues its contents for
 * retransmission.
 *
 * - **Idle Timeout**: To prevent defunct connections from consuming
 * resources indefinitely, both endpoints agree on a maximum idle
 * timeout. If no packets are exchanged within this period, the
 * connection is silently closed. The expiry timer ensures this
 * deadline is met. Any network activity (sending or receiving a
 * packet) resets the idle timer.
 *
 * - **Handshake Timeout**: During the initial connection setup, a
 * shorter timeout is enforced. If the handshake does not complete
 * within this window, the connection attempt is aborted.
 *
 * ### Connection Migration and Path Validation
 *
 * A key advantage of QUIC is its ability to maintain a connection
 * even when a client's network address changes (e.g., switching from
 * Wi-Fi to a cellular network). This framework provides full support
 * for client-side connection migration.
 *
 * The process is initiated by the application calling
 * `isc_quic_session_update_localaddr()` with the new local socket
 * address. This triggers QUIC's path validation mechanism, where
 * `PATH_CHALLENGE` frames are sent to the peer's address from the new
 * path, and `PATH_RESPONSE` frames are expected back.
 *
 * The `ngtcp2` core handles the frame exchange. During this process,
 * the application can query `isc_quic_session_path_migrating()` to
 * determine if a migration is in progress. This allows the
 * application to handle network I/O correctly, potentially sending
 * packets over both the old and new paths until the new one is
 * validated.
 *
 * ### Resource Management and Object Lifecycles
 *
 * The framework employs a strict reference counting model to manage the memory
 * of its primary objects, `isc_quic_session_t` and `isc_quic_cid_t`.
 *
 * This model requires careful and consistent use of the attach/detach
 * functions to prevent memory leaks or use-after-free
 * bugs. Internally, the framework uses memory pools for frequently
 * allocated small objects, such as stream data containers and send
 * requests, to enhance performance and reduce memory fragmentation.
 *
 * ### Conclusion
 *
 * In conclusion, the `isc_quic_session` framework provides a
 * high-level abstraction for managing the lifecycle of a single QUIC
 * connection. The framework operates as an engine that the
 * application must actively drive. Its design is deliberately
 * centered on a state machine that is completely decoupled from
 * direct network I/O and system timers. This separation is achieved
 * through a comprehensive callback interface,
 * `isc_quic_session_interface_t`, which places the responsibility for
 * all external interactions - from sending UDP datagrams to managing
 * the critical expiry timer - firmly on the application.
 */

typedef struct isc_quic_session isc_quic_session_t;
/*!<
 * \brief Representation of a QUIC session (aka QUIC connection)
 */

typedef struct isc_quic_cid isc_quic_cid_t;
/*!
 * \brief Representation of a QUIC CID.
 */

typedef uint64_t (*isc_quic_get_current_ts_cb_t)(void *restrict cbarg);
/*!<
 * \brief Callback that returns a monotonic current timestamp value
 * with nanosecond resolution. See: 'isc_time_monotonic()'.
 */

typedef void (*isc_quic_expiry_timer_start_cb_t)(
	isc_quic_session_t *restrict session, const uint32_t timeout_ms,
	void *cbarg);
/*!<
 * \brief Callback that starts an expiry timer expected to fire after
 * 'timeout_ms' milliseconds. The callback must call
 * 'isc_quic_session_on_expiry_timer()' and send any outgoing data.
 */

typedef void (*isc_quic_expiry_timer_stop_cb_t)(
	isc_quic_session_t *restrict session, void *cbarg);
/*!<
 * \brief The callback that stops the expiry timer.
 */

typedef bool (*isc_quic_gen_unique_cid_cb_t)(
	isc_quic_session_t *restrict session, const size_t cidlen,
	const bool source, void *restrict cbarg,
	isc_quic_cid_t **restrict pcid);
/*!<
 * \brief The callback that generates a new, unique CID and
 * registers it globally so that when a QUIC packet containing the CID
 * arrives, it can be passed to the corresponding QUIC session object.
 *
 * The QUIC object is attached to 'pcid' (see 'isc_quic_cid_attach()').
 */

typedef bool (*isc_quic_assoc_conn_cid_cb_t)(
	isc_quic_session_t *restrict session, isc_region_t *restrict cid_data,
	const bool source, void *cbarg, isc_quic_cid_t **restrict pcid);
/*!<
 * \brief Registers the given CID data globally so that when a QUIC
 * packet containing the CID arrives, it can be passed to the corresponding
 * QUIC session object.
 *
 * The QUIC object is attached to 'pcid' (see 'isc_quic_cid_attach()').
 */

typedef void (*isc_quic_deassoc_conn_cid_cb_t)(
	isc_quic_session_t *restrict session, const bool source, void *cbarg,
	isc_quic_cid_t **restrict pcid);
/*!<
 * \brief Removes the global association between the given CID and
 * the given QUIC session.
 *
 * The QUIC object is detached from 'pcid' (see 'isc_quic_cid_detach()').
 */

typedef bool (*isc_quic_on_handshake_cb_t)(isc_quic_session_t *restrict session,
					   void *cbarg);
/*!<
 * \brief The callback that is called upon successful QUIC handshake completion.
 */

typedef bool (*isc_quic_on_new_regular_token_cb_t)(
	isc_quic_session_t *restrict session, isc_region_t *restrict token_data,
	isc_sockaddr_t *restrict local, const isc_sockaddr_t *restrict peer,
	void *cbarg);
/*!<
 * \brief The callback that is called upon new regular token arrival.
 *
 * The 'token_data' refers to the new token itself, while 'local' and
 * 'peer' together represent the related QUIC path.
 */

typedef bool (*isc_quic_on_remote_stream_open_cb_t)(
	isc_quic_session_t *restrict session, const int64_t streamd_id,
	void *cbarg);
/*!<
 * \brief The callback that is called when a new remote stream has been opened.
 *
 * The 'stream_id' argument represents the stream identifier.
 */

typedef bool (*isc_quic_on_stream_close_cb_t)(
	isc_quic_session_t *restrict session, const int64_t streamd_id,
	const bool app_error_set, const uint64_t app_error_code, void *cbarg,
	void *stream_user_data);
/*!<
 * \brief The callback that is called when a stream has been closed.
 *
 * Notable arguments:
 *\li	'stream_id' - represents the stream identifier;
 *\li	'app_error_set' - is set to true if there is an application error code;
 *\li	'app_error_code' - the application error code (if any).
 */

typedef bool (*isc_quic_on_recv_stream_data_cb_t)(
	isc_quic_session_t *restrict session, const int64_t streamd_id,
	const bool fin, const uint64_t		 offset,
	const isc_region_t *restrict data, void *cbarg, void *stream_user_data);
/*!<
 * \brief The callback that is called when a chunk of stream has arrived.
 *
 * Notable arguments:
 *\li	'stream_id' - represents the stream identifier;
 *\li	'fun' - is set to true if that is the last chunk of data for the stream;
 *\li	'offset' - the arrived data offset within the stream.
 */

typedef void (*isc_quic_on_conn_close_cb_t)(isc_quic_session_t *restrict session,
					    const uint32_t closing_timeout_ms,
					    const bool ver_neg, void *cbarg);
/*!<
 * \brief The callback that is called when the QUIC session is closed.
 *
 * The session should be kept for 'closing_timeout_ms' milliseconds in
 * case any data arrives after the connection has been closed (think
 * of TCP TIME_WAIT state mechanism). When 'closing_timeout_ms' equals
 * zero, it means that the connection must be dropped immediately.
 *
 * If 'ver_neg' is 'true' it means that the connection is being
 * dropped due to protocol version mismatch. In that case the session
 * object still remains usable (mostly for unit-testing purposes).
 */

typedef struct isc_quic_session_interface {
	/*
	 * Low-level system interaction callbacks. These provide the
	 * foundation for the session object itself.
	 */
	isc_quic_get_current_ts_cb_t	 get_current_ts;
	isc_quic_expiry_timer_start_cb_t expiry_timer_start;
	isc_quic_expiry_timer_stop_cb_t	 expiry_timer_stop;
	/*
	 * CID management callbacks. These are required to manage the
	 * global table of CIDs in order to pass incoming QUIC packets to
	 * the corresponding QUIC sessions.
	 */
	isc_quic_gen_unique_cid_cb_t   gen_unique_cid;
	isc_quic_assoc_conn_cid_cb_t   assoc_conn_cid;
	isc_quic_deassoc_conn_cid_cb_t deassoc_conn_cid;
	/*
	 * High-level callbacks. These provide the services for the higher
	 * level code and can be used to build a transport.
	 */
	isc_quic_on_handshake_cb_t	   on_handshake;
	isc_quic_on_new_regular_token_cb_t on_new_regular_token; /* client only,
	    optional */
	isc_quic_on_remote_stream_open_cb_t on_remote_stream_open;
	isc_quic_on_stream_close_cb_t	    on_stream_close;
	isc_quic_on_recv_stream_data_cb_t   on_recv_stream_data;
	isc_quic_on_conn_close_cb_t	    on_conn_close;
} isc_quic_session_interface_t;
/*!<
 * \brief The set of callbacks using which a QUIC session
 * interacts with the rest of the system.
 */

typedef void (*isc_quic_send_cb_t)(isc_quic_session_t *restrict session,
				   const int64_t      stream_id,
				   const isc_result_t result, void *cbarg,
				   void *stream_user_data);
/*!<
 * \brief QUIC send callback.
 *
 * Notable arguments:
 *\li	'stream_id' - represents the corresponding stream identifier;
 *\li	'result' - send operation status;
 *\li	'cbarg' - a pointer that is passed alongside the callback.
 */

typedef struct isc_quic_out_pkt {
	/*
	 * Refers to a chunk of memory where the QUIC packet is going to be
	 * stored. The chunk should be at least NGTCP2_MAX_UDP_PAYLOAD_SIZE.
	 */
	isc_region_t pktbuf;
	/* The size of the packet. */
	size_t pktsz;
	/* QUIC path - where the packet is supposed to be sent. */
	isc_sockaddr_t local;
	isc_sockaddr_t peer;
} isc_quic_out_pkt_t;
/*!<
 * \brief An outgoing QUIC packet representation. The QUIC session
 * API returns outgoing packets exclusively via this object.
 */

void
isc_quic_out_pkt_init(isc_quic_out_pkt_t *restrict out_pkt, uint8_t *buf,
		      const size_t buflen);
/*!<
 * \brief Initializes an outgoing QUIC packet representation.
 *
 * Requires:
 *\li	'out_pkt' is not NULL;
 *\li	'buf' is not NULL;
 *\li	'buflen' is greater or equal to `NGTCP2_MAX_UDP_PAYLOAD_SIZE`.
 */

void
isc_quic_session_create(
	isc_mem_t *mctx, isc_tlsctx_t *tlsctx, const char *sni_hostname,
	isc_tlsctx_client_session_cache_t *client_sess_cache,
	const isc_quic_session_interface_t *restrict cb, void *cbarg,
	const isc_sockaddr_t *restrict local,
	const isc_sockaddr_t *restrict peer,
	const uint32_t handshake_timeout_ms, const uint32_t idle_timeout_ms,
	const size_t max_uni_streams, const size_t max_bidi_streams,
	const uint32_t	client_chosen_version,
	const uint32_t *available_versions, const size_t available_versions_len,
	const isc_region_t *secret, const bool is_server,
	const isc_region_t *regular_token, isc_quic_session_t **sessionp);
/*!<
 * \brief Initializes a new QUIC session with the given settings.
 *
 * Arguments:
 *\li	'tlsctx' is a TLS context used for the connection;
 *\li	'sni_hostname' is a server name indication hostname (client only);
 *\li	'client_sess_cache' TLS client session resumption cache;
 *\li	'cb' is a set of callbacks on which a QUIC session relies. All callbacks
 * are required (except 'on_new_regular_token()' - which is used only on the
 * client side if set);
 *\li	'cbarg' is the argument passed to the callbacks;
 *\li	'local' is the local interface address;
 *\li	'peer' is the remote address;
 *\li	'handshake_timeout_ms' is the handshake timeout (in milliseconds);
 *\li	'idle_timeout_ms' is the idle timeout (in milliseconds);
 *\li	'max_uni_streams' is the maximum allowed number of unidirectional
 * streams (set to 0 to disable them altogether);
 *\li	'max_bidi_streams' is the maximum allowed number of bidirectional
 * streams (set to 0 to disable them altogether);
 *\li	'client_chosen_version' is the QUIC version the client has chosen to
 * use (client only);
 *\li	'available_versions' is the pointer to the array that contains supported
 * QUIC versions;
 *\li	'available_versions_len' is the length of the array (the number of
 * versions);
 *\li	'secret' is a pointer to a memory region that contains a crypto secret;
 *\li	'is_server' is a flag that represents whether the QUIC session is going
 * to be used on the side of the server or a client;
 *\li	'regular_token' is a pointer to a memory region that contains a regular
 * token used by the client to reestablish the connection without extra checks
 * from the server side;
 *\li	'sessionp' is a pointer to a pointer that is going to contain the
 * reference to the newly created QUIC session object.
 *
 * Requires:
 *\li	'mctx' is not NULL;
 *\li	'tlsctx' is not NULL;
 *\li	'cb' is not NULL (and is properly filled);
 *\li	'local' is not NULL;
 *\li	'peer' is not NULL;
 *\li	'handshake_timeout_ms' is more than zero;
 *\li	'idle_timeout_ms' is more than zero;
 *\li	Any of 'max_uni_streams' or 'max_bidi_streams' should be more than zero;
 *\li	'secret' is not NULL and points to a valid non-zero-size chunk of
 * memory;
 *\li	'regular_token' is either NULL or points to a valid non-zero-size chunk
 * of memory (for client sessions);
 *\li	'sessionp' is not NULL and contains a pointer to a non-NULL pointer.
 */

void
isc_quic_session_attach(isc_quic_session_t *restrict source,
			isc_quic_session_t **targetp);
/*!<
 * \brief Creates a new QUIC session object reference and sets 'targetp'
 * accordingly.
 *
 * Requires:
 *\li	'source' is a valid QUIC session object;
 *\li	'targetp' is not NULL and points to a nullified pointer.
 */

void
isc_quic_session_finish(isc_quic_session_t *session);
/*!<
 * \brief Finishes the session, ensuring that most of the associated
 * resources are freed and the close callback is called. Leaves a
 * mostly empty, reference counted object shell.
 *
 * Use this function when you are sure that the associated QUIC
 * connection is not going to be used anymore.
 *
 * Requires:
 *\li	'source' is a valid QUIC session object;
 *\li	'targetp' is not NULL and points to a nullified pointer.
 */

void
isc_quic_session_detach(isc_quic_session_t **sessionp);
/*!<
 * \brief Removes a QUIC session object reference and then nullifies 'sessionp'.
 * Destroys the object upon the last reference removal.
 *
 * Requires:
 *\li	'sessionp' is not NULL and points to a pointer that points to a valid
 * QUIC session object.
 */

isc_result_t
isc_quic_session_connect(isc_quic_session_t *restrict session,
			 isc_quic_out_pkt_t *restrict out_pkt);
/*!<
 * \brief Initiates a new outgoing (client) QUIC connection. The initial packet
 * is returned via 'out_pkt' on success (when the function returns
 * 'ISC_R_SUCCESS').
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 *\li	'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 */

isc_result_t
isc_quic_session_write_pkt(isc_quic_session_t *restrict session,
			   isc_quic_out_pkt_t *restrict out_pkt);
/*!<
 * \brief Attempts to create a new outgoing packet containing pending data. The
 * packet is returned via 'out_pkt' on success if there is anything to send.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 *\li	'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 *
 * The function returns 'ISC_R_SUCCESS' on success.
 */

isc_result_t
isc_quic_session_on_expiry_timer(isc_quic_session_t *restrict session,
				 isc_quic_out_pkt_t *restrict out_pkt);
/*!< \brief
 * The function that is called when the expiry time fires. It processes the
 * expiry timer status and attempts to create a new outgoing packet containing
 * pending data. The packet is returned via 'out_pkt' on success if there is
 * anything to send.
 *
 * This function is very similar to 'isc_quic_session_write_pkt()' and
 * can be considered a specialized version of it. It plays a crucial
 * role in congestion management and flow control.
 *
 * Requires:
 *\li 'session' is a valid QUIC session object;
 *\li 'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 *
 * The function returns 'ISC_R_SUCCESS' on success.
 */

void
isc_quic_session_update_expiry_timer(isc_quic_session_t *restrict session);
/*!< \brief
 * The function that is called on successful I/O (from read and write
 * callbacks). It recalculates, and, if necessary, restart the expiry
 * timer of the connection.
 *
 * It plays a crucial role in congestion management and flow control.
 *
 * Requires:
 *\li 'session' is a valid QUIC session object.
 */

isc_result_t
isc_quic_session_read_pkt(isc_quic_session_t *restrict session,
			  const isc_sockaddr_t *restrict local,
			  const isc_sockaddr_t *restrict peer,
			  const uint32_t version,
			  const isc_region_t *restrict pkt_dcid,
			  const isc_region_t *restrict pkt_scid,
			  const bool token_verified,
			  const isc_region_t *restrict retry_token_odcid,
			  const isc_region_t *restrict pkt_data,
			  isc_quic_out_pkt_t *restrict out_pkt);
/*!<
 * \brief Reads an incoming QUIC packet from the given QUIC path represented by
 * 'local' and 'peer'. The incoming packet is supposed to be pre-processed by
 * 'isc_ngtcp2_decode_pkt_header()' first. It will provide the values for most
 *of the arguments for the function, namely:
 *\li	'version' is the QUIC protocol version extracted from the packet
 * header;
 *\li	'pkt_dcid' is the Destination CID as extracted from the packet
 * header;
 *\li	'pkt_scid' is the Source CID as extracted from the packet
 * header;
 *\li	'token_verified' specifies whether the Retry or Regular token found in
 * the packet has been verified already;
 *\li	'retry_token_odcid' is the Original Destination CID extracted from the
 * Retry token (optional);
 *\li	'pkt_data' is the reference to the complete QUIC packet.
 *
 * During an incoming packet processing the QUIC session might generate an
 * outgoing packet (which is later returned by 'out_pkt').
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 *\li	'local' is not NULL;
 *\li	'peer' is not NULL;
 *\li	'pkt_dcid' is not NULL and is not empty;
 *\li	'pkt_scid' is not NULL and is not empty;
 *\li	'pkt_data' is not NULL and is not empty;
 *\li	'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 *
 * The function returns 'ISC_R_SUCCESS' on success.
 */

isc_result_t
isc_quic_session_shutdown(isc_quic_session_t *restrict session,
			  isc_quic_out_pkt_t *restrict out_pkt);
/*!<
 * \brief Closes the QUIC session and writes a packet which contains
 * CONNECTION_CLOSE frame(s), that is - attempts to close the QUIC connection
 * gracefully. Might write a connection reset packet if the handshake has not
 * been completed.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 *\li	'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 *
 * The function returns 'ISC_R_SUCCESS' on success.
 */

isc_result_t
isc_quic_session_update_localaddr(isc_quic_session_t *restrict session,
				  const isc_sockaddr_t *restrict local);
/*!<
 * \brief Initiates immediate client connection migration to a new QUIC path
 * where the local address has changed. The QUIC path validation procedure
 * is started, but the function does not wait for its completion.
 *
 * Requires:
 *\li	'session' is a valid client QUIC session object;
 *\li	'local' is not NULL.
 *
 * The function returns 'ISC_R_SUCCESS' on success.
 */

bool
isc_quic_session_path_migrating(isc_quic_session_t *restrict session);
/*!<
 * \brief Indicates whether a client path migration is currently in progress for
 * the given QUIC session.
 *
 * Requires:
 *\li	'session' is a valid client QUIC session object.
 *
 * Returns:
 *\li	'true' if a client path migration is in progress;
 *\li	'false' otherwise.
 */

bool
isc_quic_session_is_server(isc_quic_session_t *restrict session);
/*!<
 * \brief Determines whether the QUIC session is operating as a server.
 *
 * Requires:
 *\li	'session' is a valid client QUIC session object.
 *
 * Returns:
 *\li	'true' if the session is operating as a server;
 *\li	'false' if the session is operating as a client.
 */

void
isc_quic_session_set_regular_token(isc_quic_session_t *restrict session,
				   const isc_region_t *regular_token);
/*!<
 * \brief Sets the regular token for a client QUIC session, which is used for
 * connection reestablishment without additional server-side verification.
 *
 * Requires:
 *\li	'session' is a valid client QUIC session object;
 *\li	'regular_token' is not NULL and points to a valid non-zero-sized
 * memory region.
 *
 * Note: This function is used for client sessions to enable
 * connection reestablishment with reduced verification requirements.
 */

isc_sockaddr_t
isc_quic_session_peeraddr(isc_quic_session_t *restrict session);
/*!<
 * \brief Return the peer address for the given QUIC session.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 */

isc_sockaddr_t
isc_quic_session_localaddr(isc_quic_session_t *restrict session);
/*!<
 * \brief Return the local address for the given QUIC session.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 */

isc_result_t
isc_quic_session_open_stream(isc_quic_session_t *restrict session,
			     const bool bidi, void *stream_user_data,
			     int64_t *restrict pstream_id);
/*!<
 * \brief Opens a new local QUIC stream within the specified session.
 *
 * This function creates either a bidirectional or unidirectional stream
 * depending on the 'bidi' parameter. The newly created stream ID is returned
 * via 'pstream_id'.
 *
 * Parameters:
 *\li	'bidi' specifies whether to create a bidirectional (true) or
 * unidirectional (false) stream;
 *\li	'stream_user_data' provides application-specific data to be associated
 * with the stream;
 *\li	'pstream_id' will receive the newly created stream ID on success.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 *\li	'pstream_id' is not NULL and points to a valid memory location.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' on successful stream creation;
 *\li	Appropriate error code if the operation fails.
 *
 * Note: The created stream can immediately be used for data transmission.
 */

isc_result_t
isc_quic_session_send_data(isc_quic_session_t *restrict session,
			   const int64_t stream_id,
			   const isc_region_t *restrict data, const bool fin,
			   isc_quic_send_cb_t cb, void *cbarg);
/*!<
 * \brief Sends data through an existing QUIC stream within the specified
 * session.
 *
 * This function transmits data through a specified QUIC stream and optionally
 * marks the end of the stream with the 'fin' parameter. The operation is
 * asynchronous, with results reported through the provided callback function.
 *
 * Parameters:
 *\li	'stream_id' identifies the target QUIC stream for data transmission;
 *\li	'data' contains the data to be sent (can be NULL if 'fin' is true);
 *\li	'fin' indicates whether this is the final data segment for the stream;
 *\li	'cb' specifies the callback function to be invoked when the operation
 * completes;
 *\li 'cbarg' provides user-defined data to be passed to the callback function.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object;
 *\li	Either:
 *		- 'data' is NULL and 'fin' is true, or
 *		- 'data' is not NULL, has a positive length, and points to valid
 * memory;
 *\li	'cb' is not NULL.
 *
 * Behavior:
 *\li	If the specified stream does not exist or the session is in a terminal
 * state, the callback is immediately invoked with an appropriate error code;
 *\li	If the stream is already marked as finished, the callback is invoked
 * with 'ISC_R_UNEXPECTED';
 *\li	The function creates a send request structure and adds it to both the
 * session's and stream's pending send queues;
 *\li	The data length is added to the pending data counters for both the
 * session and the stream.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if the send request was successfully queued;
 *\li	Appropriate error code if the operation cannot be performed.
 *
 * Note: The actual data transmission occurs asynchronously through the QUIC
 * protocol engine.
 */

isc_result_t
isc_quic_session_shutdown_stream(isc_quic_session_t *restrict session,
				 const int64_t stream_id, bool abrupt);
/*!<
 * \brief Shuts down a QUIC stream within the specified session.
 *
 * This function initiates the shutdown process for a specific QUIC stream,
 * either gracefully or abruptly, depending on the 'abrupt' parameter.
 *
 * Parameters:
 *\li	'stream_id' identifies the target QUIC stream to be shut down;
 *\li	'abrupt' specifies whether to perform an abrupt ('true') or graceful
 * ('false') shutdown of the stream.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object.
 *
 * Behavior:
 *\li	For abrupt shutdowns, uses 'NGTCP2_INTERNAL_ERROR' as the error code;
 *\li	For graceful shutdowns, uses 'NGTCP2_NO_ERROR' as the error code.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if the stream shutdown was successfully initiated;
 *\li	'ISC_R_NOTFOUND' if the specified stream does not exist;
 *\li	'ISC_R_FAILURE' if the stream shutdown operation failed.
 */

isc_result_t
isc_quic_session_set_stream_user_data(isc_quic_session_t *restrict session,
				      const int64_t stream_id,
				      void	   *stream_user_data);
/*!<
 * \brief Sets application-specific user data for a QUIC stream within the
 * specified session.
 *
 * This function associates user-defined data with a specific QUIC stream,
 * allowing applications to maintain stream-specific context information.
 *
 * Parameters:
 *\li	'stream_id' identifies the target QUIC stream for which to set user
 * data;
 *\li	'stream_user_data' provides the application-specific data to be
 * associated with the stream.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if the user data was successfully set;
 *\li	'ISC_R_NOTFOUND' if the specified stream does not exist;
 *\li	'ISC_R_FAILURE' if the operation failed.
 */

void *
isc_quic_session_get_stream_user_data(isc_quic_session_t *restrict session,
				      const int64_t stream_id);
/*!<
 * \brief Retrieves application-specific user data associated with a QUIC
 * stream.
 *
 * This function provides access to user-defined data previously set for a
 * specific QUIC stream using 'isc_quic_session_set_stream_user_data()'.
 *
 * Parameters:
 *\li	'stream_id' identifies the target QUIC stream for which to retrieve user
 * data.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object.
 *
 * Behavior:
 *\li	Returns NULL if the specified stream does not exist;
 *\li	Returns the previously set user data for the stream if it exists.
 *
 * Returns:
 *\li	The user data associated with the specified stream, or NULL if the
 * stream does not exist or has no associated user data.
 */

bool
isc_quic_session_is_bidi_stream(isc_quic_session_t *restrict session,
				const int64_t stream_id);
/*!<
 * \brief Determines whether a QUIC stream is bidirectional.
 *
 * This function checks if a specified QUIC stream is bidirectional, which means
 * that data can flow in both directions between the client and server.
 *
 * Parameters:
 *\li	'stream_id' identifies the target QUIC stream to check.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object.
 *
 * Returns:
 *\li	'true' if the specified stream is bidirectional;
 *\li	'false' if the specified stream does not exist or is unidirectional.
 */

void
isc_quic_session_set_user_data(isc_quic_session_t *restrict session,
			       void *user_data);
/*!<
 * \brief Sets application-specific user data for a QUIC session.
 *
 * This function associates user-defined data with a specific QUIC session,
 * allowing applications to maintain session-specific context information.
 *
 * Parameters:
 *\li	'user_data' provides the application-specific data to be
 * associated with the session.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object.
 */

void *
isc_quic_session_get_user_data(isc_quic_session_t *restrict session);
/*!<
 * \brief Retrieves application-specific user data associated with a QUIC
 * session.
 *
 * This function provides access to user-defined data previously set for a
 * specific QUIC session using 'isc_quic_session_set_user_data()'.
 *
 * Requires:
 *\li	'session' is a valid QUIC session object.
 *
 * Returns:
 *\li	The user data associated with the specified stream.
 */

/* CID management */
void
isc_quic_cid_create(isc_mem_t *mctx, const isc_region_t *restrict cid_data,
		    isc_quic_cid_t **cidp);
/*!<
 * \brief Creates a new QUIC Connection ID (CID) object.
 *
 * This function allocates and initializes a new QUIC Connection ID object with
 * the specified data and source flag. The created CID object is returned
 * through the output parameter.
 *
 * Parameters:
 *\li	'mctx' is the memory context to use for allocation;
 *\li	'cid_data' contains the connection ID data to be used;
 *\li	'cidp' will receive the newly created CID object.
 *
 * Requires:
 *\li	'cid_data' is not NULL and contains valid, non-empty data;
 *\li	'cidp' is not NULL and points to a NULL value.
 */

void
isc_quic_cid_data(const isc_quic_cid_t *restrict cid,
		  isc_region_t *restrict cid_data);
/*!<
 * \brief Returns the CID object data reference.
 *
 * Requires:
 *\li	'cid' is a valid QUIC CID object;
 *\li	'cid_data' is not NULL.
 */

void
isc_quic_cid_attach(isc_quic_cid_t *restrict source, isc_quic_cid_t **targetp);
/*!<
 * \brief Creates an additional reference to an existing QUIC Connection ID
 * object.
 *
 * This function increments the reference count of an existing CID object and
 * returns it through the output parameter.
 *
 * Parameters:
 *\li	'source' is the existing CID object to reference;
 *\li	'targetp' will receive the referenced CID object.
 *
 * Requires:
 *\li	'source' is a valid QUIC CID object;
 *\li	'targetp' is not NULL and points to a NULL value.
 *
 * Behavior:
 *\li	Increments the reference count of the source CID object;
 *\li	Returns the same CID object through the output parameter.
 */

void
isc_quic_cid_detach(isc_quic_cid_t **cidp);
/*!<
 * \brief Releases a reference to a QUIC Connection ID object.
 *
 * This function decrements the reference count of a CID object and, if the
 * count reaches zero, deallocates the object. This is used to properly clean up
 * CID objects when they are no longer needed.
 *
 * Parameters:
 *\li	'cidp' points to the CID object reference to be released.
 *
 * Requires:
 *\li	'cidp' points to a valid QUIC CID object.
 */

/*
 * QUIC Connection ID (CID) Map
 *
 * The `isc_quic_cid_map` provides a thread-safe, lock-free hash table
 * for globally mapping QUIC Connection IDs (CIDs) to their
 * corresponding QUIC session objects (`isc_quic_session_t`). This is
 * a critical component for any QUIC implementation, as it allows a
 * server or client to route incoming packets to the correct session
 * based on the Destination CID in the packet s header.
 *
 * This implementation is designed for high-concurrency environments
 * and relies on Read-Copy-Update (RCU) for managing the lifecycle of
 * its internal entries. Consequently, its use requires that the
 * `liburcu` library is properly integrated into the project and that
 * the calling threads are registered with the RCU subsystem (e.g., by
 * calling `rcu_register_thread()` and `rcu_unregister_thread()`).
 *
 * The API follows the standard ISC attach/detach model for reference
 * counting, ensuring that the map is not destroyed while it is still
 * in use.
 */

typedef struct isc_quic_cid_map isc_quic_cid_map_t;
/*!<
 * \brief A thread-safe map for associating CIDs with QUIC sessions.
 */

void
isc_quic_cid_map_create(isc_mem_t *mctx, isc_quic_cid_map_t **pmap);
/*!<
 * \brief Creates and initialises a new, empty CID map.
 *
 * This function allocates the necessary memory for a new CID map and
 * initialises its internal hash table.
 *
 * Requires:
 *\li	'mctx' is a valid memory context;
 *\li	'pmap' is not NULL and points to a NULL pointer.
 */

void
isc_quic_cid_map_attach(isc_quic_cid_map_t *restrict source,
			isc_quic_cid_map_t **targetp);
/*!<
 * \brief Creates an additional reference to an existing CID map object.
 *
 * This function increments the reference count of the map object.
 *
 * Requires:
 *\li	'source' is a valid CID map object;
 *\li	'targetp' is not NULL and points to a NULL pointer.
 */

void
isc_quic_cid_map_detach(isc_quic_cid_map_t **mapp);
/*!<
 * \brief Releases a reference to a CID map object.
 *
 * This function decrements the reference count of the map. If the count
 * reaches zero, the destruction of the map and its contained entries is
 * scheduled to occur after an RCU grace period has passed, ensuring that no
 * readers are still accessing the data.
 *
 * Requires:
 *\li	'mapp' is not NULL and points to a valid CID map object.
 */

isc_result_t
isc_quic_cid_map_find(const isc_quic_cid_map_t *restrict map,
		      const isc_region_t *restrict cid_data,
		      isc_quic_session_t **sessionp, isc_tid_t *restrict tidp);
/*!<
 * \brief Finds a QUIC session and task ID associated with a given CID.
 *
 * This function performs a lock-free lookup in the map for the given CID.
 * If a mapping is found, pointers to the associated session and task ID
 * are returned.
 *
 * If a session is found then it is attached to 'sessionp'.
 *
 * Requires:
 *\li	'map' is a valid CID map object;
 *\li	'cid_data' is not NULL and points to a valid region containing the CID;
 *\li	'sessionp' is not NULL and points to a NULL pointer. The session will
 *	NOT be attached; the caller is responsible for synchronisation;
 *\li	'tidp' is not NULL.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if the CID was found;
 *\li	'ISC_R_NOTFOUND' if the CID is not in the map.
 */

isc_result_t
isc_quic_cid_map_add(isc_quic_cid_map_t *restrict map,
		     isc_quic_cid_t *restrict cid,
		     isc_quic_session_t *restrict session, const isc_tid_t tid);
/*!<
 * \brief Adds a new CID-to-session mapping to the map.
 *
 * This function creates an association between a CID, a QUIC session, and a
 * task ID. The function will fail if a mapping for the given CID already
 * exists in the map.
 *
 * Requires:
 *\li	'map' is a valid CID map object;
 *\li	'cid' is a valid CID object to be added;
 *\li	'session' is a valid QUIC session object to be associated with the CID.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if the mapping was added successfully;
 *\li	'ISC_R_EXISTS' if a mapping for this CID already exists.
 */

void
isc_quic_cid_map_gen_unique(isc_quic_cid_map_t *restrict map,
			    isc_quic_session_t *restrict session,
			    const isc_tid_t tid, const size_t cidlen,
			    isc_quic_cid_t **cidp);
/*!<
 * \brief Generates a new, unique CID and adds it to the map.
 *
 * This function repeatedly generates a random CID of length 'cidlen' until
 * one is found that does not already exist in the map. It then atomically
 * adds the new CID to the map, associating it with the given session and
 * task ID. The newly created and attached CID object is returned via 'cidp'.
 *
 * Requires:
 *\li	'map' is a valid CID map object;
 *\li	'session' is a valid QUIC session object;
 *\li	'cidlen' >= NGTCP2_MIN_CIDLEN && 'cidlen' <= NGTCP2_MAX_CIDLEN;
 *\li	'cidp' is not NULL and points to a NULL pointer.
 */

void
isc_quic_cid_map_gen_unique_buf(const isc_quic_cid_map_t *restrict map,
				void *restrict cidbuf, const size_t cidlen);
/*!<
 * \brief Generates a new, unique CID data.
 *
 * This function repeatedly generates a random CID data inside of the
 * buffer 'cidbuf 'of length 'cidlen' until one is found that does not
 * already exist in the map.
 *
 * The function is intended to generate short lived Retry CIDs.
 *
 * Requires:
 *\li	'map' is a valid CID map object;
 *\li	'cidlen' >= NGTCP2_MIN_CIDLEN && 'cidlen' <= NGTCP2_MAX_CIDLEN;
 *\li	'cidbuf' is a non-NULL pointer.
 */

void
isc_quic_cid_map_remove(isc_quic_cid_map_t *restrict map,
			const isc_quic_cid_t *restrict cid);
/*!<
 * \brief Removes a CID and its association from the map.
 *
 * This function finds the entry corresponding to the given CID and removes it
 * from the map. The memory for the internal map entry is reclaimed safely
 * after an RCU grace period.
 *
 * Requires:
 *\li	'map' is a valid CID map object;
 *\li	'cid' is a valid CID object to be removed.
 */

isc_result_t
isc_quic_route_pkt(const isc_region_t *restrict pkt,
		   const isc_quic_cid_map_t *map,
		   const isc_region_t *restrict server_secret,
		   const uint32_t *available_versions,
		   const size_t	   available_versions_len,
		   const isc_sockaddr_t *restrict local,
		   const isc_sockaddr_t *restrict peer,
		   const isc_region_t *restrict pkt_dcid,
		   const isc_region_t *restrict pkt_scid,
		   const uint32_t version, const bool is_server,
		   const uint64_t retry_token_timeout_ns,
		   const uint64_t timestamp, isc_quic_session_t **sessionp,
		   isc_tid_t *tidp, isc_buffer_t *token_odcid_buf,
		   isc_quic_out_pkt_t *restrict out_pkt);
/*!<
 * \brief Routes an incoming QUIC packet to an existing session or handles
 * initial connection logic for a server.
 *
 * If a session is found then it is attached to 'sessionp'.
 *
 * This function serves as the primary dispatcher for incoming QUIC packets.
 * It first attempts to locate an existing QUIC session by looking up the
 * packet's Destination CID in the global CID map. If a match is found, it
 * returns a pointer to the session. If no session is found, its behavior
 * is determined by the 'is_server' flag.
 *
 * Behavior:
 *\li	**Client-Side ('is_server' is false):** The function performs a simple
 *	lookup in the CID map. If a session corresponding to 'pkt_dcid' is
 *	found, it is returned via 'sessionp'. If not found, the function
 *	returns 'ISC_R_NOTFOUND' without taking any further action.
 *
 *\li	**Server-Side ('is_server' is true):** If the CID lookup fails for a
 *	long-header packet (indicating a potential new connection), the
 *	function engages QUIC's anti-spoofing mechanism:
 *	1.  **No Token:** If the client's Initial packet contains no token, the
 *	    server considers the client's address unvalidated. It generates a
 *	    Retry packet, containing a cryptographic token and a new CID, and
 *	    returns it via 'out_pkt'. The function returns 'ISC_R_NOTFOUND'.
 *	2.  **Retry Token:** If the packet contains a Retry token, the server
 *	    validates it. If valid, the function extracts the client's original
 *	    DCID from the token and writes it to 'token_odcid_buf' for the
 *	    caller to use when creating a new session. If invalid, it generates
 *	    a new Retry packet as in case #1.
 *	3.  **Regular Token:** If the packet contains a regular token,
 *	    the server validates it. If valid, the caller can proceed to
 *	    create a new session. If invalid, a new Retry packet is generated.
 *	4.  **Version Negotiation:** If the packet contains an unsupported
 *	    version(from the server perspective), a Version Negotiation packet
 *	    is generated.
 *
 * In summary, on the server, this function either finds an existing session,
 * prepares a Retry packet to send back, or validates a token to allow the
 * caller to create a new session.
 *
 * Arguments:
 *\li	'pkt' is the complete incoming QUIC packet;
 *\li	'map' is the global CID-to-session map;
 *\li	'server_secret' is the secret key used for generating and validating
 *	tokens (server only);
 *\li	'available_versions' is available versions array pointer;
 *\li	'available_versions_len' is available versions array length;
 *\li	'local' is the local address the packet was received on;
 *\li	'peer' is the remote address the packet was received from;
 *\li	'pkt_dcid' is the Destination CID from the packet header;
 *\li	'pkt_scid' is the Source CID from the packet header;
 *\li	'version' is the QUIC protocol version from the packet header;
 *\li	'is_server' is true if running in server mode, false for client mode;
 *\li	'retry_token_timeout_ns' is the validity period for Retry tokens
 *	(server only);
 *\li	'timestamp' is the current monotonic timestamp in nanoseconds;
 *\li	'sessionp' is an output parameter that will point to the found session;
 *\li	'tidp' is an output parameter that will contain the thread ID associated
 *	with the found session;
 *\li	'token_odcid_buf' is an output buffer where the original DCID from a
 *	valid Retry token is stored (server only);
 *\li	'out_pkt' is an output structure that will contain a generated Retry
 *	packet, if any (server only).
 *
 * Requires:
 *\li	'map', 'pkt', 'local', 'peer', 'pkt_dcid', and 'sessionp' are not NULL;
 *\li	If 'is_server' is true, 'server_secret', 'token_odcid_buf', and
 *	'out_pkt' must be valid and initialized.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if a session was found. '*sessionp' and '*tidp' are
 *	populated.
 *\li	'ISC_R_NOTFOUND' if no session was found. On the server, this
 *	can mean either that a Retry or a Version negotiation packet was
 *	generated in 'out_pkt',or that a token was successfully validated
 *	and the caller should now create a new * session. The caller must
 *	check 'out_pkt->pktsz' and 'token_odcid_buf' * to distinguish
 *	these cases.
 *\li	'ISC_R_FAILURE' or 'ISC_R_UNEXPECTED' on packet parsing or other
 *	internal errors.
 */

/*
 * QUIC Regular Token Cache
 *
 * The 'isc_quic_token_cache' provides a client-side, thread-safe,
 * Least Recently Used (LRU) cache for QUIC regular tokens. These
 * tokens, issued by servers, allow clients to accelerate future
 * connection establishment, for instance by bypassing address
 * validation mechanisms.
 *
 * By caching tokens per server address, a client application can significantly
 * reduce latency for subsequent connections to servers it has recently
 * communicated with.
 *
 * This implementation is designed for high-concurrency environments and
 * relies on Read-Copy-Update (RCU) for lookups. Its use requires that the
 * `liburcu` library is properly integrated and that calling threads are
 * registered with the RCU subsystem.
 *
 * The API follows the standard ISC attach/detach model for reference
 * counting.
 */

typedef struct isc_quic_token_cache isc_quic_token_cache_t;
/*!<
 * \brief A cache for QUIC regular (session resumption) tokens.
 *
 * This object implements a client-side, thread-safe, LRU cache for QUIC
 * regular tokens received from servers. Caching these tokens allows clients
 * to resume sessions or bypass address validation on subsequent connections
 * to the same server, which can significantly reduce connection establishment
 * latency.
 *
 * The cache is indexed by the server's (peer) socket address and has a
 * fixed capacity. When the cache is full, the least recently used token is
 * evicted to make space for a new one.
 *
 * It is designed for high-concurrency environments, using a lock-free hash
 * table with Read-Copy-Update (RCU) for lookups and a mutex to serialize
 * updates. The API follows the standard ISC attach/detach model for
 * reference counting.
 */

void
isc_quic_token_cache_create(isc_mem_t *mctx, const size_t max_size,
			    isc_quic_token_cache_t **pcache);
/*!<
 * \brief Creates and initialises a new, empty token cache.
 *
 * This function allocates and initialises a new cache for storing QUIC
 * regular tokens with a specified maximum capacity.
 *
 * Arguments:
 *\li	'mctx' is a valid memory context to use for all allocations.
 *\li	'max_size' is the maximum number of tokens the cache can hold. It must
 *     be greater than zero.
 *\li	'pcache' is an output parameter that will point to the newly created
 *     token cache object on success.
 *
 * Requires:
 *\li	'mctx' is not NULL;
 *\li	'max_size' is greater than zero;
 *\li	'pcache' is not NULL and points to a NULL pointer.
 */

void
isc_quic_token_cache_attach(isc_quic_token_cache_t  *source,
			    isc_quic_token_cache_t **ptarget);
/*!<
 * \brief Creates an additional reference to an existing token cache object.
 *
 * This function increments the reference count of the token cache object,
 * preventing it from being destroyed while still in use.
 *
 * Arguments:
 *\li	'source' is the existing token cache object to reference.
 *\li	'ptarget' is an output parameter that will point to the 'source' object.
 *
 * Requires:
 *\li	'source' is a valid token cache object;
 *\li	'ptarget' is not NULL and points to a NULL pointer.
 */

void
isc_quic_token_cache_detach(isc_quic_token_cache_t **pcache);
/*!<
 * \brief Releases a reference to a token cache object.
 *
 * This function decrements the reference count of the cache. If the count
 * reaches zero, the destruction of the cache and all its contained entries
 * is scheduled to occur after an RCU grace period has passed, ensuring that
 * no readers are still accessing its data.
 *
 * Arguments:
 *\li	'pcache' points to the token cache object reference to be released. The
 *     pointer will be nullified upon return.
 *
 * Requires:
 *\li	'pcache' is not NULL and points to a valid token cache object.
 */

isc_result_t
isc_quic_token_cache_reuse(isc_quic_token_cache_t *restrict cache,
			   const isc_sockaddr_t *restrict remote_peer,
			   isc_quic_session_t *restrict session);
/*!<
 * \brief Attempts to find and apply a cached token to a new QUIC session.
 *
 * This function performs a lock-free lookup in the cache for a token
 * associated with the specified remote peer address. If a token is found, it
 * is set on the provided QUIC session object using
 * 'isc_quic_session_set_regular_token()'. This enables the client to attempt
 * session resumption on its next connection attempt.
 *
 * Arguments:
 *\li	'cache' is the token cache to search.
 *\li	'remote_peer' is the address of the server (peer) for which to find a
 *     token.
 *\li	'session' is the new client QUIC session to which the token will be
 *     applied if found.
 *
 * Requires:
 *\li	'cache' is a valid token cache object.
 *\li	'remote_peer' is not NULL.
 *\li	'session' is a valid client QUIC session object.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if a token was found and successfully set on the
 *session.
 *\li	'ISC_R_NOTFOUND' if no token for the specified peer was found in the
 *     cache.
 */

void
isc_quic_token_cache_keep(isc_quic_token_cache_t *restrict cache,
			  const isc_sockaddr_t *restrict remote_peer,
			  const isc_region_t *token_data);
/*!<
 * \brief Adds a new token to the cache or updates an existing one.
 *
 * This function stores a token received from a server, associating it with
 * the server's address. If an entry for this peer already exists, its token
 * is updated with the new one, and the entry is marked as most recently
 * used.
 *
 * If no entry exists, a new one is created. If the cache is at its maximum
 * capacity, the least recently used token is evicted to make room for the new
 * one.
 *
 * Arguments:
 *\li	'cache' is the token cache where the token will be stored.
 *\li	'remote_peer' is the address of the server (peer) that issued the token.
 *\li	'token_data' is a memory region containing the token to be cached.
 *
 * Requires:
 *\li	'cache' is a valid token cache object.
 *\li	'remote_peer' is not NULL.
 *\li	'token_data' is not NULL and points to a valid, non-empty memory region.
 */

/*
 * QUIC Session Manager
 *
 * The `isc_quic_sm` (Session Manager) is a high-level abstraction that
 * simplifies the management of multiple QUIC sessions (`isc_quic_session_t`).
 * It acts as a central factory and router, handling the entire lifecycle of
 * QUIC connections for either a client or a server application.
 *
 * The primary responsibilities of the Session Manager are:
 *
 * - **Session Creation**: It provides `isc_quic_sm_connect()` for clients
 *   to initiate new connections and handles the logic for creating new server-
 *   side sessions from initial client packets within `isc_quic_sm_route_pkt()`.
 *
 * - **Packet Routing**: `isc_quic_sm_route_pkt()` is the main entry point for
 *   all incoming QUIC packets. It uses an internal CID map to look up the
 *   correct session and thread context for a packet.
 *
 * - **Lifecycle Management**: It automates the setup of session callbacks,
 *   timer management (expiry and closing timers), and CID association/
 *   de-association. When a session is closed, the manager ensures its
 *   resources are cleaned up correctly.
 *
 * - **Thread Affinity**: It is designed for multi-threaded environments. It
 *   associates each session with the thread that created it.
 *   `isc_quic_sm_route_pkt()` will report the correct thread ID for a found
 *   session, allowing the application to re-dispatch packet processing to the
 *   appropriate thread if necessary.
 *
 * By using the Session Manager, an application is shielded from the low-level
 * details of managing individual session objects, CID maps, and timers.
 * The application interacts with the manager through a simplified high-level
 * interface (`isc_quic_sm_interface_t`) for connection and stream events.
 */

typedef struct isc_quic_sm isc_quic_sm_t;
/*!<
 * \brief A high-level manager for multiple QUIC sessions.
 */

typedef bool (*isc_quic_sm_on_handshake_cb_t)(
	isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	void *cbarg);
/*!<
 * \brief The callback that is called upon successful QUIC handshake completion.
 *
 * Corresponds to 'isc_quic_session_interface_t::on_handshake'.
 */

typedef bool (*isc_quic_sm_on_expiry_timer_cb_t)(
	isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	const isc_result_t expiry_result, isc_sockaddr_t *restrict local,
	const isc_sockaddr_t *restrict peer,
	const isc_region_t *restrict pkt_data, void *cbarg);
/*!<
 * \brief The callback that is called when an expiry timer fires and generates
 * a packet to be sent. The user is responsible for sending the packet.
 *
 * Notable arguments:
 *\li	'expiry_result' - the result of 'isc_quic_session_on_expiry_timer()'.
 *\li	'local' - the local address to send from.
 *\li	'peer' - the remote address to send to.
 *\li	'pkt_data' - the generated packet data.
 */

typedef bool (*isc_quic_sm_on_remote_stream_open_cb_t)(
	isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	const int64_t streamd_id, void *cbarg);
/*!<
 * \brief The callback that is called when a new remote stream has been opened.
 *
 * Corresponds to 'isc_quic_session_interface_t::on_remote_stream_open'.
 */

typedef bool (*isc_quic_sm_on_stream_close_cb_t)(
	isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	const int64_t streamd_id, const bool app_error_set,
	const uint64_t app_error_code, void *cbarg, void *stream_user_data);
/*!<
 * \brief The callback that is called when a stream has been closed.
 *
 * Corresponds to 'isc_quic_session_interface_t::on_stream_close'.
 */

typedef bool (*isc_quic_sm_on_recv_stream_data_cb_t)(
	isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	const int64_t streamd_id, const bool fin, const uint64_t offset,
	const isc_region_t *restrict data, void *cbarg, void *stream_user_data);
/*!<
 * \brief The callback that is called when a chunk of stream has arrived.
 *
 * Corresponds to 'isc_quic_session_interface_t::on_recv_stream_data'.
 */

typedef void (*isc_quic_sm_on_conn_close_cb_t)(
	isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	void *cbarg);
/*!<
 * \brief The callback that is called when the QUIC session is closed.
 *
 * This callback signals that the session has entered the closing state.
 * The session manager will handle the draining period internally. The
 * application can use this to clean up any state associated with the
 * closing session.
 */

typedef struct isc_quic_sm_interface {
	isc_quic_sm_on_handshake_cb_t	       on_handshake;
	isc_quic_sm_on_expiry_timer_cb_t       on_expiry_timer;
	isc_quic_sm_on_remote_stream_open_cb_t on_remote_stream_open;
	isc_quic_sm_on_stream_close_cb_t       on_stream_close;
	isc_quic_sm_on_recv_stream_data_cb_t   on_recv_stream_data;
	isc_quic_sm_on_conn_close_cb_t	       on_conn_close;
} isc_quic_sm_interface_t;
/*!<
 * \brief The set of high-level callbacks used by the QUIC Session Manager.
 *
 * This interface allows an application to react to significant events
 * across all managed sessions, such as handshake completion, new streams,
 * and incoming data.
 */

void
isc_quic_sm_create(isc_mem_t *mctx, const size_t nworkers, isc_tlsctx_t *tlsctx,
		   isc_tlsctx_client_session_cache_t *client_sess_cache,
		   isc_quic_sm_interface_t *restrict cb, void *cbarg,
		   const uint32_t handshake_timeout_ms,
		   const uint32_t idle_timeout_ms, const size_t max_uni_streams,
		   const size_t	   max_bidi_streams,
		   const uint32_t  client_chosen_version,
		   const uint32_t *available_versions,
		   const size_t available_versions_len, const bool is_server,
		   const size_t client_token_cache_size, isc_quic_sm_t **mgrp);
/*!<
 * \brief Creates a new QUIC Session Manager.
 *
 * This function initialises a session manager that will act as a factory and
 * dispatcher for multiple QUIC sessions. The provided parameters serve as
 * templates for all sessions created by this manager.
 *
 * Arguments:
 *\li	'mctx' is the memory context for all allocations.
 *\li	'nworkers' is the number of worker threads the manager supports.
 *\li	'tlsctx' is the TLS context to be used for all sessions.
 *\li	'client_sess_cache' is the TLS client session resumption cache
 *	(client-side only).
 *\li	'cb' is a set of high-level callbacks for session events.
 *\li	'cbarg' is the user-defined argument passed to the callbacks.
 *\li	'handshake_timeout_ms' is the default handshake timeout for new
 *	sessions.
 *\li	'idle_timeout_ms' is the default idle timeout for new sessions.
 *\li	'max_uni_streams' is the default maximum number of unidirectional
 *	streams.
 *\li	'max_bidi_streams' is the default maximum number of bidirectional
 *	streams.
 *\li	'client_chosen_version' is the QUIC version a client will use
 *	(client-side only).
 *\li	'available_versions' is a pointer to an array of supported QUIC
 *	versions.
 *\li	'available_versions_len' is the number of versions in the array.
 *\li	'is_server' is a flag indicating whether the manager operates in server
 *	or client mode.
 *\li	'client_token_cache_size' is the max number of regular tokens to cache
 *	(client-side only, set to 0 to disable).
 *\li	'mgrp' is a pointer that will receive the new session manager object.
 *
 * Requires:
 *\li	'mctx' is a valid memory context.
 *\li	'tlsctx' is a valid TLS context.
 *\li	'cb' is not NULL and all of its function pointers must be non-NULL.
 *\li	'handshake_timeout_ms' is greater than zero.
 *\li	'idle_timeout_ms' is greater than zero.
 *\li	At least one of 'max_uni_streams' or 'max_bidi_streams' is greater
 *	than zero.
 *\li	If 'is_server' is false, 'client_token_cache_size' can be zero or
 *	more. If 'is_server' is true, 'client_token_cache_size' must be zero.
 *\li	'mgrp' is not NULL and points to a NULL pointer.
 */

void
isc_quic_sm_attach(isc_quic_sm_t *source, isc_quic_sm_t **targetp);
/*!<
 * \brief Creates an additional reference to an existing session manager object.
 *
 * This function increments the reference count of the manager object.
 *
 * Requires:
 *\li	'source' is a valid session manager object.
 *\li	'targetp' is not NULL and points to a NULL pointer.
 */

void
isc_quic_sm_detach(isc_quic_sm_t **targetp);
/*!<
 * \brief Releases a reference to a session manager object.
 *
 * This function decrements the reference count. If the count reaches zero, the
 * manager and all its associated resources (including any remaining sessions)
 * are destroyed.
 *
 * Requires:
 *\li	'targetp' is not NULL and points to a pointer that points to a valid
 *	session manager object.
 */

isc_result_t
isc_quic_sm_connect(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid,
		    const isc_sockaddr_t *restrict local,
		    const isc_sockaddr_t *restrict peer,
		    const char *sni_hostname, isc_quic_out_pkt_t *out_pkt,
		    isc_quic_session_t **sessionp);
/*!<
 * \brief Initiates a new outgoing (client) QUIC connection via the manager.
 *
 * This function creates a new QUIC session, associates it with the manager,
 * and generates the initial connection packet. If the manager was configured
 * with a token cache, it will attempt to reuse a token for this peer.
 *
 * Arguments:
 *\li	'mgr' is the session manager.
 *\li	'local' is the local socket address to use.
 *\li	'peer' is the remote server address to connect to.
 *\li	'sni_hostname' is the Server Name Indication for the TLS handshake.
 *\li	'out_pkt' will receive the initial outgoing packet.
 *\li	'sessionp' will receive the newly created session object on success.
 *
 * Requires:
 *\li	'mgr' is a valid session manager object created in client mode.
 *\li	'local' is not NULL.
 *\li	'peer' is not NULL.
 *\li	'sni_hostname' is either NULL or points to a non-empty string.
 *\li	'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 *\li	'sessionp' is not NULL and points to a NULL pointer.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' on success. 'out_pkt' contains the packet to send, and
 *	'sessionp' points to the new session.
 *\li	An error code on failure.
 */

isc_result_t
isc_quic_sm_route_pkt(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid,
		      const bool server_over_quota,
		      const isc_region_t *restrict pkt,
		      const isc_sockaddr_t *restrict local,
		      const isc_sockaddr_t *restrict peer,
		      isc_quic_out_pkt_t *restrict out_pkt,
		      bool *restrict new_connp,
		      isc_tid_t *restrict session_tidp,
		      isc_quic_session_t **sessionp);
/*!<
 * \brief Routes an incoming QUIC packet, potentially creating a new session.
 *
 * This is the primary entry point for processing all incoming QUIC packets.
 * It performs the following actions:
 *
 * 1.  Decodes the packet header to extract the Destination CID.
 * 2.  Looks up the CID in its internal map to find an existing session.
 * 3.  **If a session is found:**
 *     - It returns the session via 'sessionp' and its associated thread ID
 *       via 'session_tidp'.
 *     - If the found session's thread ID matches 'current_tid', it proceeds
 *       to process the packet by calling `isc_quic_session_read_pkt()`. Any
 *       resulting response packet is returned in 'out_pkt'.
 *     - If the thread IDs do *not* match, the packet is *not* read. The
 *       function returns 'ISC_R_SUCCESS', and the caller is responsible for
 *       re-dispatching the packet for processing in the correct thread, as
 *       indicated by 'session_tidp'.
 * 4.  **If no session is found (and in server mode):**
 *     - It handles initial packet logic, which may involve validating a
 *       token, generating a Retry or Version Negotiation packet (returned in
 *       'out_pkt'), or creating a new session if the packet is valid for
 *       doing so.
 *     - If a new session is created, it is associated with 'current_tid',
 *       processed, and returned via 'sessionp' and 'session_tidp'. The value to
 *       which the 'new_connp' points is set to 'true' in this case.
 *
 * Arguments:
 *\li	'mgr' is the session manager.
 *\li	'current_tid' is the ID of the thread currently processing the packet.
 *\li	'server_over_quota' indicates if the server is at capacity (server
 *	mode only).
 *\li	'pkt' is the complete incoming QUIC packet.
 *\li	'local' is the local address the packet was received on.
 *\li	'peer' is the remote address the packet came from.
 *\li	'out_pkt' is an output parameter for any generated response packets.
 *\li	'session_tidp' is an output parameter for the session's thread ID.
 *\li	'sessionp' is an output parameter for the found or created session.
 *
 * Requires:
 *\li	'mgr' is a valid session manager object.
 *\li	'pkt' is not NULL and points to a valid, non-empty region
 *	containing the packet data.
 *\li	'local' is not NULL.
 *\li	'peer' is not NULL.
 *\li	'out_pkt' is not NULL and is initialized via 'isc_quic_out_pkt_init()'.
 *\li	'session_tidp' is not NULL.
 *\li	'new_connp' is not NULL and points to a 'false' value.
 *\li	'sessionp' is not NULL and points to a NULL pointer.
 *
 * Returns:
 *\li	'ISC_R_SUCCESS' if a session was found or created and (if thread IDs
 *	matched) the packet was processed. The caller must check 'sessionp'
 *	and 'session_tidp' to determine the outcome and next steps.
 *\li	'ISC_R_NOTFOUND' if no session was found and one could not be created
 *	(e.g., on client-side, or a Retry packet was generated on server-side).
 *	The caller should check 'out_pkt->pktsz' to see if a packet was
 *	generated that needs to be sent.
 *\li	An error code on packet parsing or other failures.
 */

void
isc_quic_sm_finish(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid);
/*!<
 * \brief Initiates an orderly shutdown of all sessions managed by this manager.
 *
 * This function should be called before the final `isc_quic_sm_detach()` call
 * that would lead to the destruction of the session manager. It ensures that
 * all active QUIC sessions are properly terminated and their associated
 * resources, especially timers, are cleaned up safely across all worker
 * threads.
 *
 * The function operates by dispatching shutdown tasks to each worker thread
 * that has active sessions. It then waits for all tasks to complete before
 * returning. This process prevents race conditions where session timers might
 * fire after the manager itself has been deallocated.
 *
 * Arguments:
 *\li	'mgr' is the session manager to shut down.
 *\li	'current_tid' is the ID of the thread calling this function.
 *
 * Requires:
 *\li	'mgr' is a valid session manager object.
 */

bool
isc_quic_sm_is_server(isc_quic_sm_t *restrict mgr);
/*!<
 * \brief Returns 'true' if the given session manager object is a server one.
 *
 * Requires:
 *\li	'mgr' is a valid session manager object.
 */
