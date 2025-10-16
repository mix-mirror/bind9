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

/*! \file */

#include <isc/result.h>

#include <dns/notify.h>

void
dns_notify_create(isc_mem_t *mctx, unsigned int flags, dns_notify_t **notifyp) {
	dns_notify_t *notify;

	REQUIRE(notifyp != NULL && *notifyp == NULL);

	notify = isc_mem_get(mctx, sizeof(*notify));
	*notify = (dns_notify_t){
		.flags = flags,
	};

	isc_mem_attach(mctx, &notify->mctx);
	isc_sockaddr_any(&notify->src);
	isc_sockaddr_any(&notify->dst);
	dns_name_init(&notify->ns);
	ISC_LINK_INIT(notify, link);
	notify->magic = NOTIFY_MAGIC;
	*notifyp = notify;
}
