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
#include <isc/quic.h>

#include "netmgr-int.h"

static void
handshake_completed_cb(void *cbarg);

static isc_result_t
data_read_cb(void *cbarg, isc_quic_stream_data_info_t info,
	     isc_constregion_t data);

static isc_quic_conn_callbacks_t server_cb = {
	.handshake_completed = handshake_completed_cb,
	.data_read = data_read_cb,
};

static void
handshake_completed_cb(void *cbarg) {
	isc_nmhandle_t *handle = cbarg;

	handle->sock->accept_cb(handle, ISC_R_SUCCESS,
				handle->sock->accept_cbarg);
}

static isc_result_t
data_read_cb(void *cbarg, isc_quic_stream_data_info_t info,
	     isc_constregion_t data) {
	isc_nmhandle_t *handle = cbarg;
	isc_region_t region = { UNCONST(data.base), data.length };

	UNUSED(info);
	handle->sock->recv_cb(handle, ISC_R_SUCCESS, &region,
			      handle->sock->recv_cbarg);

	return ISC_R_SUCCESS;
}

static void
server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
	       isc_region_t *region, void *cbarg) {
	isc_quic_version_t version;
	isc_constregion_t dcid, scid;
	isc_constregion_t packet;
	isc_quic_conn_t *conn = NULL;
	isc_nmsocket_t *sock = cbarg;
	isc_result_t result;
	uint8_t *reset;
	void *found = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	packet = (isc_constregion_t){
		.base = region->base,
		.length = region->length,
	};

	result = isc_quic_router_handle_packet(sock->quic.router, packet,
					       &version, &dcid, &scid, &found);

	switch (result) {
	case ISC_R_SUCCESS:
		isc_quic_conn_push_packet(found, packet, &sock->iface,
					  &sock->peer);
		break;
	case ISC_R_UNSET:
		reset = region->base + region->length -
			ISC_QUIC_STATELESS_TOKEN_LENGTH;
		isc_quic_router_del_stateless_reset(sock->quic.router, reset);
		break;
	case ISC_R_NOTFOUND:
		isc_quic_conn_server_create(
			sock->worker->mctx, sock->quic.router, &server_cb, NULL,
			NULL, dcid, scid, NULL, NULL, &conn);
		break;
	case ISC_R_INVALIDPROTO:
	case ISC_R_UNEXPECTED:
	case ISC_R_IGNORE:
		break;
	default:
		UNREACHABLE();
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
		  isc_quic_server_options_t *options,
		  isc_nm_accept_cb_t accept_cb, void *accept_cb_arg,
		  isc_nmsocket_t **sockp) {
	isc__networker_t *worker = NULL;
	isc_nmsocket_t *sock = NULL;
	isc_result_t result;

	REQUIRE(isc_tid() == 0);
	REQUIRE(sockp != NULL && *sockp == NULL);

	worker = isc__networker_current();
	if (isc__nm_closing(worker)) {
		return ISC_R_SHUTTINGDOWN;
	}

	sock = isc_mempool_get(worker->nmsocket_pool);
	isc__nmsocket_init(sock, worker, isc_nm_quiclistener, iface, NULL);
	sock->accept_cb = accept_cb;
	sock->accept_cbarg = accept_cb_arg;

	isc_quic_router_create(worker->mctx, &sock->quic.router);
	sock->quic.options.server = options;

	CHECK(isc_nm_listenudp(workers, iface, server_recv_cb, sock,
			       &sock->outer));

	return ISC_R_SUCCESS;

cleanup:
	isc_quic_router_detach(&sock->quic.router);

	return result;
}

void
isc_nm_quicconnect(isc_sockaddr_t *local, isc_sockaddr_t *peer,
		   isc_quic_client_options_t *options, isc_nm_cb_t cb,
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
