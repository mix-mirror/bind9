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
listenquic_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	(void)handle;
	(void)eresult;
	(void)region;
	(void)cbarg;
}

isc_result_t
isc_nm_listenquic(uint32_t workers, isc_sockaddr_t *iface,
		  isc_nm_accept_cb_t accept_cb, void *accept_cbarg, int backlog,
		  isc_quota_t *quota, isc_tlsctx_t *sslctx,
		  isc_nmsocket_t **sockp) {
	isc_nmsocket_t *listener = NULL;
	isc__networker_t *worker;
	isc_result_t result;

	UNUSED(sockp);
	UNUSED(accept_cb);
	UNUSED(accept_cbarg);
	UNUSED(backlog);
	UNUSED(quota);
	UNUSED(sslctx);

	REQUIRE(isc_tid() == 0);
	REQUIRE(sockp != NULL && *sockp == NULL);

	worker = isc__networker_current();
	if (isc__nm_closing(worker)) {
		return ISC_R_SHUTTINGDOWN;
	}

	listener = isc_mempool_get(worker->nmsocket_pool);
	//isc__nmsocket_init(listener, worker, isc_nm_quiclistener, iface, NULL);

	result = isc_nm_listenudp(workers, iface, listenquic_recv_cb, listener,
				  &listener->outer);

	if (result != ISC_R_SUCCESS) {
		listener->closed = true;
		isc__nmsocket_detach(&listener);
		return result;
	}

	return result;
}
