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

typedef struct udp_send_packet udp_send_packet_t;

struct udp_send_packet {
	uint32_t len;
	uint8_t *packet;
	isc_mem_t *mctx;
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
	bool closing;
	uint32_t sockets_len;
	isc_nmsocket_t *sockets[] ISC_ATTR_COUNTED_BY(sockets_len);
};

typedef struct quic_push_packet_job {
	isc_tid_t tid;
	uint32_t len;
	uint8_t *data ISC_ATTR_COUNTED_BY_PTR(len);
	isc_nmhandle_t *handle;
	isc_nm_quiclistener_t *listener;
	isc_quic_conn_t *conn;
} quic_push_packet_job_t;

typedef struct quic_stop_child_socket_job {
	isc_tid_t tid;
	isc_nm_quiclistener_t *listener;
} quic_stop_child_socket_job_t;

constexpr uint32_t listener_magic = ISC_MAGIC('N', 'M', 'q', 'c');

static void
listener_handshake_completed_cb(void *cbarg);

static isc_result_t
data_read_cb(isc_quic_conn_t *conn, void *cbarg,
	     isc_quic_stream_data_info_t info, isc_constregion_t data);

static void
udp_send_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg);

static isc_quic_conn_callbacks_t server_cb = {
	.handshake_completed = listener_handshake_completed_cb,
	.data_read = data_read_cb,
};

static void
async_push_packet(void *cbarg) {
	quic_push_packet_job_t *job = cbarg;
	isc_mem_t *mctx = job->listener->mctx;
	isc_sockaddr_t local, peer;

	local = isc_nmhandle_localaddr(job->handle);
	peer = isc_nmhandle_peeraddr(job->handle);

	isc_quic_conn_push_packet(job->conn,
				  (isc_constregion_t){ job->data, job->len },
				  &local, &peer);

	isc_region_t *out = isc_mem_get(isc_g_mctx, sizeof(*out));
	*out = (isc_region_t){ isc_mem_get(isc_g_mctx, 1200), 1200 };
	size_t written;

	if (isc_quic_conn_pull_packet(job->conn, *out, &written, &local,
				      &peer) == ISC_R_SUCCESS)
	{
		out->length = written;
		isc_nm_send(job->handle, out, udp_send_cb, out);
	} else {
		isc_mem_put(isc_g_mctx, out->base, 1200);
		isc_mem_put(isc_g_mctx, out, sizeof(*out));
	}

	isc_nmhandle_unref(job->handle);
	isc_nm_quiclistener_unref(job->listener);
	isc_quic_conn_unref(job->conn);
	isc_mem_put(mctx, job->data, job->len);
	isc_mem_put(mctx, job, sizeof(*job));
}

static void
async_quic_stop_child_socket(void *arg) {
	quic_stop_child_socket_job_t *job = arg;
	isc_nm_quiclistener_t *listener = job->listener;
	isc_nmsocket_t *sock = job->listener->sockets[job->tid];
	isc_mem_t *mctx = listener->mctx;

	isc__nmsocket_timer_stop(sock);
	if (sock->outerhandle != NULL) {
		isc__nm_stop_reading(sock->outerhandle->sock);
		isc_nmhandle_detach(&sock->outerhandle);
	}

	isc__nmsocket_prep_destroy(sock);
	isc__nmsocket_detach(&listener->sockets[job->tid]);
	isc_mem_put(mctx, job, sizeof(*job));
	isc_nm_quiclistener_unref(listener);
}

static void
listener_handshake_completed_cb(void *cbarg) {
	isc_nmsocket_t *sock = cbarg;
	isc_nmhandle_t *handle;

	handle = isc__nmhandle_get(sock, &sock->peer, &sock->iface);
	sock->accept_cb(handle, ISC_R_SUCCESS, handle->sock->accept_cbarg);
	isc_nmhandle_unref(handle);
}

static isc_result_t
data_read_cb(isc_quic_conn_t *conn ISC_ATTR_UNUSED, void *cbarg,
	     isc_quic_stream_data_info_t info, isc_constregion_t data) {
	isc_nmhandle_t *handle = cbarg;
	isc_region_t region = { UNCONST(data.base), data.length };

	UNUSED(info);
	handle->sock->recv_cb(handle, ISC_R_SUCCESS, &region,
			      handle->sock->recv_cbarg);

	return ISC_R_SUCCESS;
}

static void
udp_send_cb(isc_nmhandle_t *handle ISC_ATTR_UNUSED,
	    isc_result_t result ISC_ATTR_UNUSED, void *cbarg) {
	isc_region_t *out = cbarg;
	isc_mem_put(isc_g_mctx, out->base, 1200);
	isc_mem_put(isc_g_mctx, out, sizeof(*out));
}

static void
listener_udp_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		     isc_region_t *region, void *cbarg) {
	isc_nm_quiclistener_t *listener;
	quic_push_packet_job_t *job;
	isc_constregion_t dcid, scid;
	isc__networker_t *worker;
	isc_quic_conn_t *conn;
	isc_nmsocket_t *sock;
	isc_result_t result;
	bool attached = false;
	isc_tid_t tid;

	isc_constregion_t packet = { region->base, region->length };

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	listener = cbarg;
	sock = listener->sockets[handle->sock->tid];
	if (sock->outerhandle == NULL) {
		isc_nmhandle_attach(handle, &sock->outerhandle);
		attached = true;
	}

	sock->iface = isc_nmhandle_localaddr(handle);
	sock->peer = isc_nmhandle_peeraddr(handle);

	result = isc_quic_router_handle_packet(listener->router, packet, NULL,
					       &dcid, &scid, &tid, &conn);
	switch (result) {
	case ISC_R_SUCCESS:
		if (tid == handle->sock->tid) {
			isc_quic_conn_push_packet(conn, packet, &sock->iface,
						  &sock->peer);
		} else {
			job = isc_mem_get(listener->mctx, sizeof(*job));
			*job = (quic_push_packet_job_t){
				.tid = tid,
				.len = packet.length,
				.data = isc_mem_get(listener->mctx,
						    packet.length),
				.handle = isc_nmhandle_ref(handle),
				.listener = isc_nm_quiclistener_ref(listener),
				/*
				 * cheekly re-use the refcount increased by the
				 * router
				 */
				.conn = conn,
			};
			memmove(job->data, packet.base, packet.length);

			if (attached) {
				isc_nmhandle_detach(&sock->outerhandle);
			}

			worker = isc__networker_get(tid);
			isc_async_run(worker->loop, async_push_packet, job);
			return;
		}
		break;
	case ISC_R_NOTFOUND:
		result = isc_quic_conn_server_create(
			listener->mctx, listener->router, &server_cb, sock,
			listener->options, dcid, scid, &sock->iface,
			&sock->peer, &conn);
		if (result != ISC_R_SUCCESS) {
			isc__nmsocket_log(
				sock, ISC_LOG_ERROR,
				"QUIC server connection creation failed %s",
				isc_result_totext(result));
			return;
		}

		result = isc_quic_conn_push_packet(conn, packet, &sock->iface,
						   &sock->peer);
		if (result != ISC_R_SUCCESS) {
			isc__nmsocket_log(sock, ISC_LOG_ERROR,
					  "QUIC failed to push packet %s",
					  isc_result_totext(result));
			isc_quic_conn_unref(conn);
			return;
		}
		break;
	default:
		return;
	}

	isc_region_t *out = isc_mem_get(isc_g_mctx, sizeof(*out));
	*out = (isc_region_t){ isc_mem_get(isc_g_mctx, 1200), 1200 };
	size_t written;

	result = isc_quic_conn_pull_packet(conn, *out, &written, &sock->iface,
					   &sock->peer);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(isc_g_mctx, out->base, 1200);
		isc_mem_put(isc_g_mctx, out, sizeof(*out));
		isc_quic_conn_unref(conn);
		return;
	}

	out->length = written;

	isc_nm_send(handle, out, udp_send_cb, out);
	isc_quic_conn_unref(conn);
}

static void
destroy(isc_nm_quiclistener_t *listener) {
	size_t i;

	listener->magic = 0x00;

	for (i = 0; i < listener->sockets_len; i++) {
		INSIST(listener->sockets[i] == NULL);
	}

	isc_refcount_destroy(&listener->references);
	isc_mem_putanddetach(
		&listener->mctx, listener,
		STRUCT_FLEX_SIZE(listener, sockets, listener->sockets_len));
}

ISC_REFCOUNT_IMPL(isc_nm_quiclistener, destroy);

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
isc__nm_quic_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock;

	REQUIRE(VALID_NMHANDLE(handle));

	sock = handle->sock;

	if (isc__nm_closing(sock->worker)) {
		cb(handle, ISC_R_SHUTTINGDOWN, NULL, cbarg);
		return;
	}

	sock->recv_cb = cb;
	sock->recv_cbarg = cbarg;
	sock->reading = true;
}

void
isc__nm_quic_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_quicsocket);
	REQUIRE(sock->tid == isc_tid());

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
		  isc_nm_quiclistener_t **listenerp) {
	isc_nm_quiclistener_t *listener;
	isc__networker_t *worker;
	isc_result_t result;
	uint32_t len;
	size_t i;

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
			       STRUCT_FLEX_SIZE(listener, sockets, len));
	*listener = (isc_nm_quiclistener_t){
		.magic = listener_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(worker->mctx),
		.options = isc_mem_get(worker->mctx, sizeof(*options)),
		.accept_cb = accept_cb,
		.accept_cb_arg = accept_cb_arg,
		.sockets_len = len,
	};

	*listener->options = *options;

	isc_quic_router_create(worker->mctx, ISC_QUIC_CID_MAX_LENGTH,
			       &listener->router);

	for (i = 0; i < len; i++) {
		worker = isc__networker_get(i);
		listener->sockets[i] = isc_mempool_get(worker->nmsocket_pool);
		isc__nmsocket_init(listener->sockets[i], worker,
				   isc_nm_quicsocket, iface, NULL);
		listener->sockets[i]->read_timeout = isc_nm_getinitialtimeout();
		listener->sockets[i]->accept_cb = accept_cb;
		listener->sockets[i]->accept_cbarg = accept_cb_arg;
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
	quic_stop_child_socket_job_t *job;
	size_t i;

	REQUIRE(listener != NULL && listener->magic == listener_magic);
	REQUIRE(!listener->closing);
	REQUIRE(isc_tid() == 0);

	listener->closing = true;
	isc_nm_udplistener_stop(listener->udp_listener);
	isc_nm_udplistener_detach(&listener->udp_listener);

	for (i = 0; i < listener->sockets_len; i++) {
		job = isc_mem_get(listener->mctx, sizeof(*job));
		*job = (quic_stop_child_socket_job_t){
			.tid = i,
			.listener = isc_nm_quiclistener_ref(listener),
		};

		isc_async_run(listener->sockets[i]->worker->loop,
			      async_quic_stop_child_socket, job);
	}
}
