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

#include <isc/quic.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "netmgr-int.h"

static void
process_udp(isc_nmhandle_t *handle, isc_region_t *packet, isc_quic_sm_t *sm) {
	isc_quic_session_t *session = NULL;
	isc_result_t result;
	isc_sockaddr_t local, peer;
	isc_tid_t self_tid, session_tid;
	bool is_new_connection;

	self_tid = isc_tid();

	local = isc_nmhandle_localaddr(handle);
	peer = isc_nmhandle_peeraddr(handle);

	result = isc_quic_sm_route_pkt(sm, self_tid, false, packet, &local,
				       &peer, NULL, &is_new_connection,
				       &session_tid, &session);

	if (result != ISC_R_SUCCESS) {
		return;
	}

	if (is_new_connection) {
	}
}

static void
listenquic_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	isc_quic_sm_t *sm = cbarg;

	switch (eresult) {
	case ISC_R_SUCCESS:
		process_udp(handle, region, sm);
	default:
		break;
	}
}

static bool
on_handshake(isc_quic_sm_t *restrict mgr, isc_quic_session_t *restrict session,
	     void *cbarg) {
	(void)mgr;
	(void)session;
	(void)cbarg;
	return true;
}

static isc_quic_sm_interface_t callbacks = {
	.on_handshake = on_handshake,
};

isc_result_t
isc_nm_listenquic(uint32_t workers, isc_sockaddr_t *iface,
		  isc_nm_accept_cb_t accept_cb, void *accept_cbarg, int backlog,
		  isc_quota_t *quota, isc_tlsctx_t *tlsctx,
		  isc_nmsocket_t **sockp) {
	isc_nmsocket_t *listener = NULL;
	isc_quic_sm_t *manager = NULL;
	isc__networker_t *worker;
	isc_result_t result;

	UNUSED(sockp);
	UNUSED(accept_cb);
	UNUSED(accept_cbarg);
	UNUSED(backlog);
	UNUSED(quota);
	UNUSED(tlsctx);

	REQUIRE(isc_tid() == 0);
	REQUIRE(sockp != NULL && *sockp == NULL);

	worker = isc__networker_current();
	if (isc__nm_closing(worker)) {
		return ISC_R_SHUTTINGDOWN;
	}

	listener = isc_mempool_get(worker->nmsocket_pool);
	// isc__nmsocket_init(listener, worker, isc_nm_quiclistener, iface,
	// NULL);

	constexpr uint32_t handshake_timeout = 32;
	constexpr uint32_t idle_timeout = 32;
	constexpr size_t max_uni_streams = 32;
	constexpr size_t max_bidi_streams = 32;
	constexpr size_t client_chosen = 32;

	isc_quic_sm_create(worker->mctx, workers, tlsctx, NULL, &callbacks,
			   NULL, handshake_timeout, idle_timeout,
			   max_uni_streams, max_bidi_streams, client_chosen,
			   NULL, 0, true, 32, &manager);

	result = isc_nm_listenudp(workers, iface, listenquic_recv_cb, listener,
				  &listener->outer);
	if (result != ISC_R_SUCCESS) {
		listener->closed = true;
		isc__nmsocket_detach(&listener);
		return result;
	}

	return result;
}
