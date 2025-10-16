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

/*! \file dns/notify.h */

#include <isc/sockaddr.h>

#include <dns/name.h>
#include <dns/types.h>

#define NOTIFY_MAGIC		 ISC_MAGIC('N', 't', 'f', 'y')
#define DNS_NOTIFY_VALID(notify) ISC_MAGIC_VALID(notify, NOTIFY_MAGIC)

/*%
 * Hold notify contxt.
 */
struct dns_notifyctx {
	dns_zone_t *zone;
	dns_acl_t  *notify_acl;

	isc_sockaddr_t	 notifyfrom;
	dns_notifylist_t notifies;

	/* Configuration data. */
	dns_notifytype_t notifytype;
	isc_sockaddr_t	 notifysrc4;
	isc_sockaddr_t	 notifysrc6;
};

/*%
 * Hold notify state.
 */
struct dns_notify {
	unsigned int	 magic;
	unsigned int	 flags;
	isc_mem_t	*mctx;
	dns_zone_t	*zone;
	dns_adbfind_t	*find;
	dns_request_t	*request;
	dns_name_t	 ns;
	isc_sockaddr_t	 src;
	isc_sockaddr_t	 dst;
	dns_tsigkey_t	*key;
	dns_transport_t *transport;
	ISC_LINK(dns_notify_t) link;
	isc_rlevent_t *rlevent;
};

typedef enum dns_notify_flags {
	DNS_NOTIFY_NOSOA = 1 << 0,
	DNS_NOTIFY_STARTUP = 1 << 1,
	DNS_NOTIFY_TCP = 1 << 2,
} dns_notify_flags_t;

void
dns_notify_create(isc_mem_t *mctx, unsigned int flags, dns_notify_t **notifyp);
/*%<
 *	Create a notify structure to maintain state.
 *
 *	Requires:
 *		'mctx' is not NULL.
 *		'notifyp' is not NULL and '*notifyp' is NULL.
 */
