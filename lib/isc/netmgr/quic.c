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
#include <isc/magic.h>
#include <isc/quic.h>

#include "netmgr-int.h"

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

constexpr uint32_t listener_magic = ISC_MAGIC('N', 'M', 'q', 'c');

static void
listener_handshake_completed_cb(void *cbarg);

static isc_result_t
data_read_cb(isc_quic_conn_t *conn, void *cbarg,
	     isc_quic_stream_data_info_t info, isc_constregion_t data);

static isc_quic_conn_callbacks_t server_cb = {
	.handshake_completed = listener_handshake_completed_cb,
	.data_read = data_read_cb,
};

static void
listener_handshake_completed_cb(void *cbarg) {
	isc_nmhandle_t *handle, *inner;

	handle = cbarg;
	inner = isc__nmhandle_get(handle->sock, &handle->sock->peer,
				  &handle->sock->iface);
	handle->sock->accept_cb(inner, ISC_R_SUCCESS,
				handle->sock->accept_cbarg);
	isc_nmhandle_unref(inner);
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
async_push_packet_job(void *cbarg) {
	quic_push_packet_job_t *job = cbarg;
	isc_mem_t *mctx = job->listener->mctx;
	isc_sockaddr_t local, peer;

	local = isc_nmhandle_localaddr(job->handle);
	peer = isc_nmhandle_peeraddr(job->handle);

	isc_quic_conn_push_packet(job->conn,
				  (isc_constregion_t){ job->data, job->len },
				  &local, &peer);

	isc_nmhandle_unref(job->handle);
	isc_nm_quiclistener_unref(job->listener);

	isc_mem_put(mctx, job->data, job->len);
	isc_mem_put(mctx, job, sizeof(*job));
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
	isc_tid_t tid;

	isc_constregion_t packet = { region->base, region->length };

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	listener = cbarg;
	sock = listener->sockets[handle->sock->tid];
	if (sock->outerhandle == NULL) {
		isc_nmhandle_attach(handle, &sock->outerhandle);
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
			isc_quic_conn_unref(conn);
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

			worker = isc__networker_get(tid);
			isc_async_run(worker->loop, async_push_packet_job, job);
		}

		break;
	case ISC_R_NOTFOUND:
		isc_quic_conn_server_create(listener->mctx, listener->router,
					    &server_cb, sock, listener->options,
					    dcid, scid, &sock->iface,
					    &sock->peer, &conn);
		break;
	default:
		break;
	}
}

static void
client_connect_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmhandle_t *quic_handle;
	isc_nmsocket_t *sock = cbarg;

	REQUIRE(VALID_NMHANDLE(handle));

	if (result != ISC_R_SUCCESS) {
		return;
	}

	UNUSED(quic_handle);

	sock->tid = isc_tid();
	isc_nmhandle_attach(handle, &sock->outerhandle);
	sock->iface = isc_nmhandle_localaddr(handle);
	sock->peer = isc_nmhandle_peeraddr(handle);

	quic_handle = isc__nmhandle_get(sock, &sock->peer, &sock->iface);
}

// static void
// quic_io_step_cb(void *arg) {
// 	isc_nmsocket_t *sock = arg;
//
// 	isc__nmsocket_detach(&sock);
// }

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

isc_result_t
isc_nm_listenquic(uint32_t workers, isc_sockaddr_t *iface,
		  isc_quic_conn_options_t *options,
		  isc_nm_accept_cb_t accept_cb, void *accept_cb_arg,
		  isc_nm_quiclistener_t **listenerp) {
	isc_nm_quiclistener_t *listener;
	isc__networker_t *worker = NULL;
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
		.options = options,
		.accept_cb = accept_cb,
		.accept_cb_arg = accept_cb_arg,
		.sockets_len = len,
	};

	isc_quic_router_create(worker->mctx, ISC_QUIC_CID_MAX_LENGTH,
			       &listener->router);

	for (i = 0; i < len; i++) {
		listener->sockets[i] = isc_mempool_get(worker->nmsocket_pool);
		isc__nmsocket_init(listener->sockets[i], worker,
				   isc_nm_quicsocket, iface, NULL);
		listener->sockets[i]->result = ISC_R_UNSET;
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
	return result;
}

void
isc_nm_quicconnect(isc_sockaddr_t *local, isc_sockaddr_t *peer,
		   isc_quic_conn_options_t *options, isc_nm_cb_t cb,
		   void *cbarg) {
	isc__networker_t *worker;
	isc_nmsocket_t *sock;

	worker = isc__networker_current();
	if (isc__nm_closing(worker)) {
		cb(NULL, ISC_R_SHUTTINGDOWN, cbarg);
		return;
	}

	sock = isc_mempool_get(worker->nmsocket_pool);
	isc__nmsocket_init(sock, worker, isc_nm_quicsocket, local, NULL);
	sock->read_timeout = isc_nm_getinitialtimeout();
	sock->connect_cb = cb;
	sock->connect_cbarg = cbarg;
	sock->client = true;
	sock->connecting = true;

	isc_nm_udpconnect(local, peer, client_connect_cb, sock,
			  options->idle_timeout);
}
