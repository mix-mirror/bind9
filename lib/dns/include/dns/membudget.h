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

#include <stdint.h>

#include <isc/mem.h>
#include <isc/types.h>

#include <dns/types.h>

/*
 * Shared cache memory budget.
 *
 * The configured max-cache-size is a single budget shared by several caches
 * (qpcache, ADB, delegdb).  Each cache registers itself as a tenant.  On
 * every insert, the cache asks the budget for a cleaning probability that
 * combines two signals:
 *
 *   - Global pressure from the cleaning ramp evaluated against the sum of
 *     every tenant's isc_mem_inuse(), projected to include the new insert.
 *   - The tenant's share of the global in-use total, scaled by the number
 *     of active tenants, so the tenant holding the most memory cleans
 *     hardest.
 *
 * No static per-tenant weights or reserved shares; an idle tenant is never
 * asked to clean what it doesn't hold, and a hot tenant naturally absorbs
 * unused capacity from idle peers.
 *
 * Lifetime:
 *   - dns_membudget_create()/dns_membudget_attach()/dns_membudget_detach()
 *     are refcounted; named_cache_t owns the initial reference and each
 *     tenant registration takes another.
 *   - Tenant registration/unregistration runs from the configuration path
 *     under loop-manager exclusive mode (rndc reconfig / view destruction);
 *     readers run concurrently from worker loops via the cleaning hot path.
 *     Tenant slots are atomic pointers so the hot path is lock-free.
 */

#define DNS_MEMBUDGET_MAX_TENANTS 8

typedef struct dns_membudget_tenant dns_membudget_tenant_t;

struct dns_membudget_tenant {
	const char	*name;	 /* short label used in stats */
	isc_mem_t	*mctx;	 /* tenant accounting mctx */
	dns_membudget_t *budget; /* attached budget (refcounted) */
	int		 slot;	 /* index in budget->tenants[] */
};

void
dns_membudget_create(isc_mem_t *mctx, uint64_t max_size,
		     dns_membudget_t **outp);
void
dns_membudget_attach(dns_membudget_t *src, dns_membudget_t **dstp);
void
dns_membudget_detach(dns_membudget_t **bp);
void
dns_membudget_resize(dns_membudget_t *b, uint64_t new_size);

/*
 * Register/unregister a tenant.  Must be called from the configuration
 * path (loop-manager exclusive mode).  The tenant struct is owned by the
 * caller and must outlive the registration.
 */
void
dns_membudget_register(dns_membudget_t *b, dns_membudget_tenant_t *t,
		       const char *name, isc_mem_t *tenant_mctx);
void
dns_membudget_unregister(dns_membudget_tenant_t *t);

/*
 * Hot path: return 0..255 cleaning probability for this tenant given a
 * projected additional allocation of `purgesize` bytes.  Returns 0 if
 * the budget has not been sized, has no tenants, or global utilisation
 * is below the cleaning ramp's lo threshold.
 */
uint8_t
dns_membudget_cleaning_prob(dns_membudget_tenant_t *t, size_t purgesize);

/*
 * Stats accessors for rndc/XML/JSON.
 */
uint64_t
dns_membudget_max(const dns_membudget_t *b);
uint64_t
dns_membudget_inuse(const dns_membudget_t *b);
uint64_t
dns_membudget_tenant_inuse(const dns_membudget_tenant_t *t);
unsigned int
dns_membudget_tenant_count(const dns_membudget_t *b);
