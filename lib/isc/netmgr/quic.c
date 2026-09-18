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

#include <stdint.h>

#include <isc/async.h>
#include <isc/attributes.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/quic.h>
#include <isc/tid.h>
#include <isc/util.h>

#include "netmgr-int.h"

typedef struct quic_awaiting_packet quic_awaiting_packet_t;
typedef struct push_packet_job push_packet_job_t;

struct quic_awaiting_packet {
	isc_mem_t *mctx;
	uint32_t len;
	uint8_t data[] ISC_ATTR_COUNTED_BY(len);
};

struct isc__nm_quic_stream {
	int64_t id;

	isc_nm_recv_cb_t recv_cb;
	void *recv_arg;

	isc_nm_cb_t stream_open_cb;
	void *stream_open_cbarg;

	union {
		isc_nm_cb_t send_cb;
		isc_nm_accept_cb_t accept_cb;
	};

	union {
		void *send_arg;
		void *accept_arg;
	};
};

struct isc_nm_quiclistener {
	uint32_t magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	isc_quic_router_t *router;
	isc_quic_conn_options_t *options;
	isc_nm_udplistener_t *udp_listener;
	isc_nm_accept_cb_t accept_cb;
	void *accept_cb_arg;
	isc_nm_cb_t stream_open_cb;
	void *stream_open_cb_arg;
	isc_nm_recv_cb_t recv_cb;
	void *recv_arg;
	bool closing;
	uint32_t nchildren;
	isc_nmsocket_t *children[] ISC_ATTR_COUNTED_BY(nchildren);
};

struct push_packet_job {
	isc_mem_t *mctx;
	isc_quic_conn_t *conn;
	isc_nmhandle_t *udphandle;
	uint32_t len;
	uint8_t data[] ISC_ATTR_COUNTED_BY(len);
};

constexpr uint32_t listener_magic = ISC_MAGIC('N', 'M', 'q', 'c');

static void
listener_handshake_completed_cb(void *cbarg);

static isc_result_t
stream_opened_cb(isc_quic_conn_t *conn, void *cbarg, void **stream_data,
		 int64_t stream_id);

static isc_result_t
data_read_cb(isc_quic_conn_t *conn, void *cbarg,
	     isc_quic_stream_data_info_t info, isc_constregion_t data);

static void
udp_send_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg);

static isc_quic_conn_callbacks_t listener_cb = {
	.handshake_completed = listener_handshake_completed_cb,
	.stream_opened = stream_opened_cb,
	.data_read = data_read_cb,
};

static void
async_push_packet(void *cbarg) {
	quic_awaiting_packet_t *packet;
	push_packet_job_t *job = cbarg;
	isc_nmhandle_t *handle;
	uint8_t buf[1200];
	size_t written;

	handle = isc_quic_conn_get_callback_arg(job->conn);

	isc_quic_conn_push_packet(job->conn,
				  (isc_constregion_t){ job->data, job->len },
				  &handle->local, &handle->peer);

	written = 0;
	if (isc_quic_conn_pull_packet(
		    job->conn, (isc_region_t){ buf, sizeof(buf) }, &written,
		    &handle->local, &handle->peer) == ISC_R_SUCCESS)
	{
		packet = isc_mem_get(job->mctx,
				     STRUCT_FLEX_SIZE(packet, data, written));
		*packet = (quic_awaiting_packet_t){
			.mctx = isc_mem_ref(job->mctx),
			.len = written,
		};
		memmove(packet->data, buf, written);

		isc_nm_send(handle->parent_handle,
			    &(isc_region_t){ buf, written }, udp_send_cb,
			    packet);
	}

	isc_quic_conn_unref(job->conn);
	isc_mem_putanddetach(&job->mctx, job,
			     STRUCT_FLEX_SIZE(job, data, job->len));
}

static void
listener_handshake_completed_cb(void *cbarg) {
	isc_nmhandle_t *handle = cbarg;

	REQUIRE(handle->quic.stream->id == -1);

	(void)handle->quic.stream->accept_cb(handle, ISC_R_SUCCESS,
					     handle->quic.stream->accept_arg);
}

static isc_result_t
stream_opened_cb(isc_quic_conn_t *conn, void *cbarg, void **stream_data,
		 int64_t stream_id) {
	isc_nmhandle_t *conn_handle, *stream_handle;

	conn_handle = cbarg;

	stream_handle = isc__nmhandle_get(conn_handle->sock, &conn_handle->peer,
					  &conn_handle->local);
	stream_handle->quic.conn = isc_quic_conn_ref(conn);
	stream_handle->quic.stream =
		isc_mem_get(conn_handle->sock->worker->mctx,
			    sizeof(*stream_handle->quic.stream));
	*stream_handle->quic.stream = (isc__nm_quic_stream_t){
		.id = stream_id,
		.recv_cb = conn_handle->quic.stream->recv_cb,
		.recv_arg = conn_handle->quic.stream->recv_arg,
	};
	isc_nmhandle_attach(conn_handle->parent_handle,
			    &stream_handle->parent_handle);

	*stream_data = stream_handle;

	conn_handle->quic.stream->stream_open_cb(
		stream_handle, ISC_R_SUCCESS,
		conn_handle->quic.stream->stream_open_cbarg);

	isc_nmhandle_unref(stream_handle);

	return ISC_R_SUCCESS;
}

static isc_result_t
data_read_cb(isc_quic_conn_t *conn ISC_ATTR_UNUSED, void *cbarg ISC_ATTR_UNUSED,
	     isc_quic_stream_data_info_t info, isc_constregion_t data) {
	isc_nmhandle_t *handle = info.stream_data;
	isc_region_t region = { UNCONST(data.base), data.length };

	INSIST(handle->quic.stream->id != -1);

	handle->quic.stream->recv_cb(handle, ISC_R_SUCCESS, &region,
				     handle->quic.stream->recv_arg);

	return ISC_R_SUCCESS;
}

static void
udp_send_cb(isc_nmhandle_t *handle ISC_ATTR_UNUSED,
	    isc_result_t result ISC_ATTR_UNUSED, void *cbarg) {
	quic_awaiting_packet_t *packet = cbarg;

	isc_mem_putanddetach(&packet->mctx, packet,
			     STRUCT_FLEX_SIZE(packet, data, packet->len));
}

static void
listener_udp_recv_cb(isc_nmhandle_t *udphandle, isc_result_t eresult,
		     isc_region_t *region, void *cbarg) {
	quic_awaiting_packet_t *awaiting;
	isc_nm_quiclistener_t *listener;
	isc_constregion_t dcid, scid;
	isc_quic_version_t version;
	push_packet_job_t *job;
	isc__networker_t *worker;
	isc_quic_conn_t *conn;
	isc_nmhandle_t *handle;
	isc_nmsocket_t *sock;
	isc_result_t result;
	isc_tid_t tid;
	uint8_t buf[1200];
	size_t written;

	isc_constregion_t packet = { region->base, region->length };
	isc_region_t out = { buf, sizeof(buf) };

	isc_sockaddr_t local, peer;

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	listener = cbarg;

	local = isc_nmhandle_localaddr(udphandle);
	sock = listener->children[isc_tid()];
	sock->peer = isc_nmhandle_peeraddr(udphandle);

	conn = NULL;
	result = isc_quic_router_handle_packet(
		listener->router, packet, &version, &dcid, &scid, &tid, &conn);
	switch (result) {
	case ISC_R_SUCCESS:
		if (tid != udphandle->sock->tid) {
			job = isc_mem_get(
				listener->mctx,
				STRUCT_FLEX_SIZE(job, data, packet.length));
			*job = (push_packet_job_t){
				.mctx = isc_mem_ref(listener->mctx),
				/*
				 * cheekly re-use the refcount increased by the
				 * router
				 */
				.conn = conn,
				.udphandle = isc_nmhandle_ref(udphandle),
				.len = packet.length,
			};
			memmove(job->data, packet.base, packet.length);

			worker = isc__networker_get(tid);
			isc_async_run(worker->loop, async_push_packet, job);
			return;
		}
		break;
	case ISC_R_NOTFOUND:
		worker = udphandle->sock->worker;

		handle = isc__nmhandle_get(sock, &sock->peer, &local);

		result = isc_quic_conn_server_create(
			listener->mctx, listener->router, &listener_cb, handle,
			listener->options, version, dcid, scid, &sock->iface,
			&sock->peer, &conn);
		if (result != ISC_R_SUCCESS) {
			isc__nmsocket_log(
				sock, ISC_LOG_ERROR,
				"QUIC server connection creation failed %s",
				isc_result_totext(result));
			isc_nmhandle_unref(handle);
			return;
		}

		isc_nmhandle_attach(udphandle, &handle->parent_handle);
		handle->quic.conn = conn;
		handle->quic.stream = isc_mem_get(worker->mctx,
						  sizeof(*handle->quic.stream));
		*handle->quic.stream = (isc__nm_quic_stream_t){
			.id = -1,
			.recv_cb = listener->recv_cb,
			.recv_arg = listener->recv_arg,
			.accept_cb = listener->accept_cb,
			.accept_arg = listener->accept_cb_arg,
			.stream_open_cb = listener->stream_open_cb,
			.stream_open_cbarg = listener->stream_open_cb_arg,
		};
		break;
	default:
		return;
	}

	result = isc_quic_conn_push_packet(conn, packet, &local, &sock->peer);
	if (result != ISC_R_SUCCESS) {
		isc_quic_conn_unref(conn);
		return;
	}

	written = 0;
	result = isc_quic_conn_pull_packet(conn, out, &written, &local, &peer);
	if (result != ISC_R_SUCCESS) {
		isc_quic_conn_unref(conn);
		return;
	}

	awaiting = isc_mem_get(sock->worker->mctx,
			       STRUCT_FLEX_SIZE(awaiting, data, written));
	*awaiting = (quic_awaiting_packet_t){
		.mctx = isc_mem_ref(sock->worker->mctx),
		.len = written,
	};
	memmove(awaiting->data, buf, written);

	isc_nm_send(udphandle, &(isc_region_t){ buf, written }, udp_send_cb,
		    awaiting);
}

static void
destroy(isc_nm_quiclistener_t *listener) {
	// size_t i;

	listener->magic = 0x00;

	isc_refcount_destroy(&listener->references);
}

ISC_REFCOUNT_IMPL(isc_nm_quiclistener, destroy);

void
isc__nmhandle_quic_destroy(isc_nmhandle_t *handle, uint64_t application_code) {
	isc__nm_quic_stream_t *stream;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(handle->quic.stream != NULL);

	if (handle->quic.conn == NULL) {
		return;
	}

	stream = MOVE_OWNERSHIP(handle->quic.stream);

	if (stream->id != -1) {
		(void)isc_quic_conn_shutdown_stream(
			handle->quic.conn, stream->id, application_code);
	}

	isc_quic_conn_detach(&handle->quic.conn);
}

void
isc__nmsocket_quic_timer_stop(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_quicsocket);

	if (sock->outerhandle != NULL) {
		INSIST(VALID_NMHANDLE(sock->outerhandle));
		REQUIRE(VALID_NMSOCK(sock->outerhandle->sock));
		isc__nmsocket_timer_stop(sock->outerhandle->sock);
	}
}

void
isc__nm_quic_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
		  void *cbarg) {
	quic_awaiting_packet_t *packet;
	isc__nm_uvreq_t *uvreq;
	isc_nmsocket_t *sock;
	isc_result_t result;
	uint8_t buf[1200];
	size_t written;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->tid == isc_tid() &&
		handle->sock->type == isc_nm_quicsocket);

	/*
	 * Stream has been shut down before.
	 */
	if (handle->quic.stream == NULL) {
		cb(handle, ISC_R_CANCELED, cbarg);
	}

	REQUIRE(handle->quic.stream->id != -1);

	sock = handle->sock;
	if (isc__nm_closing(sock->worker)) {
		uvreq = isc__nm_uvreq_get(sock);
		isc_nmhandle_attach(handle, &uvreq->handle);
		uvreq->cb.send = cb;
		uvreq->cbarg = cbarg;
		isc__nm_failed_send_cb(sock, uvreq, ISC_R_SHUTTINGDOWN, true);
		return;
	}

	result = isc_quic_conn_push_stream_data(handle->quic.conn,
						handle->quic.stream->id,
						region->base, region->length);
	if (result != ISC_R_SUCCESS) {
		cb(handle, result, cbarg);
		return;
	}

	written = 0;
	result = isc_quic_conn_pull_packet(handle->quic.conn,
					   (isc_region_t){ buf, sizeof(buf) },
					   &written, &sock->iface, &sock->peer);
	if (result != ISC_R_SUCCESS) {
		cb(handle, result, cbarg);
		return;
	}

	handle->quic.stream->send_cb = cb;
	handle->quic.stream->send_arg = cbarg;

	packet = isc_mem_get(sock->worker->mctx,
			     STRUCT_FLEX_SIZE(packet, data, written));
	*packet = (quic_awaiting_packet_t){
		.mctx = isc_mem_ref(sock->worker->mctx),
		.len = written,
	};
	memmove(packet->data, buf, written);

	isc_nm_send(handle->parent_handle, &(isc_region_t){ buf, written },
		    udp_send_cb, packet);
}

void
isc__nm_quic_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->recv_handle == NULL);
	REQUIRE(handle->sock->tid == isc_tid());

	sock = handle->sock;

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;
	sock->reading = true;

	if (isc__nm_closing(sock->worker)) {
		cb(handle, ISC_R_SHUTTINGDOWN, NULL, cbarg);
		return;
	}

	// isc_nm_read(sock->outerhandle, listener_udp_recv_cb, sock);
}

void
isc__nm_quic_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_quicsocket && sock->tid == isc_tid());

	sock->closing = true;

	isc__nmsocket_timer_stop(sock);
	if (sock->outerhandle != NULL) {
		isc__nm_stop_reading(sock->outerhandle->sock);
		isc_nmhandle_close(sock->outerhandle);
		isc_nmhandle_detach(&sock->outerhandle);
	}
	sock->active = false;
	sock->closed = true;
	sock->reading = false;
}

isc_result_t
isc_nm_listenquic(uint32_t workers, isc_sockaddr_t *iface,
		  isc_quic_conn_options_t *options,
		  isc_nm_accept_cb_t accept_cb, void *accept_cb_arg,
		  isc_nm_cb_t stream_open_cb, void *stream_open_cb_arg,
		  isc_nm_recv_cb_t recv_cb, void *recv_cb_arg,
		  isc_nm_quiclistener_t **listenerp) {
	isc_nm_quiclistener_t *listener;
	isc__networker_t *worker;
	isc_result_t result;
	uint32_t i, len;

	REQUIRE(isc_tid() == 0);
	REQUIRE(listenerp != NULL && *listenerp == NULL);

	worker = isc__networker_current();
	if (isc__nm_closing(worker)) {
		return ISC_R_SHUTTINGDOWN;
	}

	len = (workers == ISC_NM_LISTEN_ALL) ? (uint32_t)isc_loopmgr_nloops()
					     : workers;
	INSIST(len > 0 && len <= isc_loopmgr_nloops());

	listener = isc_mem_get(worker->mctx,
			       STRUCT_FLEX_SIZE(listener, children, len));
	*listener = (isc_nm_quiclistener_t){
		.magic = listener_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(worker->mctx),
		.options = isc_mem_get(worker->mctx, sizeof(*options)),
		.accept_cb = accept_cb,
		.accept_cb_arg = accept_cb_arg,
		.stream_open_cb = stream_open_cb,
		.stream_open_cb_arg = stream_open_cb_arg,
		.recv_cb = recv_cb,
		.recv_arg = recv_cb_arg,
		.nchildren = len,
	};

	*listener->options = *options;

	isc_quic_router_create(worker->mctx, ISC_QUIC_CID_MAX_LENGTH,
			       &listener->router);

	for (i = 0; i < len; i++) {
		worker = isc__networker_get(i);
		listener->children[i] = isc_mempool_get(worker->nmsocket_pool);
		isc__nmsocket_init(listener->children[i], worker,
				   isc_nm_quicsocket, iface, NULL);
	}

	CHECK(isc_nm_listenudp(workers, iface, listener_udp_recv_cb, listener,
			       &listener->udp_listener));

	*listenerp = listener;

	return ISC_R_SUCCESS;

cleanup:
	listener->closing = true;
	isc_nm_quiclistener_unref(listener);
	return result;
}

void
isc_nm_quiclistener_stop(isc_nm_quiclistener_t *listener) {
	REQUIRE(listener != NULL && listener->magic == listener_magic);
	REQUIRE(!listener->closing);
	REQUIRE(isc_tid() == 0);

	listener->closing = true;
	isc_nm_udplistener_stop(listener->udp_listener);
	isc_nm_udplistener_detach(&listener->udp_listener);
}
