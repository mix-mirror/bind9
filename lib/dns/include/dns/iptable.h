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

#include <inttypes.h>
#include <stdbool.h>

#include <isc/magic.h>
#include <isc/radix.h>
#include <isc/refcount.h>

#include <dns/types.h>

struct dns_iptable {
	unsigned int	  magic;
	isc_mem_t	 *mctx;
	isc_refcount_t	  references;
	isc_radix_tree_t *radix;
	ISC_LINK(dns_iptable_t) nextincache;
};

#define DNS_IPTABLE_MAGIC    ISC_MAGIC('T', 'a', 'b', 'l')
#define DNS_IPTABLE_VALID(a) ISC_MAGIC_VALID(a, DNS_IPTABLE_MAGIC)

/***
 *** Functions
 ***/

void
dns_iptable_create(isc_mem_t *mctx, dns_iptable_t **target);
/*
 * Create a new IP table and the underlying radix structure
 */

void
dns_iptable_addprefix(dns_iptable_t *tab, const isc_netaddr_t *addr,
		      uint16_t bitlen, isc_radix_match_t match);
/*
 * Add an IP prefix to an existing IP table.
 */

void
dns_iptable_merge(dns_iptable_t *tab, dns_iptable_t *source, bool negate);
/*
 * Merge one IP table into another one, optionally negating allow entries.
 */

ISC_REFCOUNT_DECL(dns_iptable);
