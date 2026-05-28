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

#include <inttypes.h>
#include <stdint.h>

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/membudget.h>

#include "size_p.h"

#define DNS_MEMBUDGET_MAGIC    ISC_MAGIC('m', 'b', 'u', 'd')
#define DNS_MEMBUDGET_VALID(b) ISC_MAGIC_VALID(b, DNS_MEMBUDGET_MAGIC)

struct dns_membudget {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;

	dns_size_t ramp; /* shared 75%->87.5% ramp on max_size */

	atomic_ptr(dns_membudget_tenant_t) tenants[DNS_MEMBUDGET_MAX_TENANTS];
};

void
dns_membudget_create(isc_mem_t *mctx, uint64_t max_size,
		     dns_membudget_t **outp) {
	REQUIRE(mctx != NULL);
	REQUIRE(outp != NULL && *outp == NULL);

	dns_membudget_t *b = isc_mem_get(mctx, sizeof(*b));
	*b = (dns_membudget_t){
		.magic = DNS_MEMBUDGET_MAGIC,
	};
	isc_mem_attach(mctx, &b->mctx);
	isc_refcount_init(&b->references, 1);

	for (size_t i = 0; i < DNS_MEMBUDGET_MAX_TENANTS; i++) {
		atomic_init(&b->tenants[i], NULL);
	}

	if (max_size != 0) {
		dns_size_init(&b->ramp, max_size);
	}

	*outp = b;
}

void
dns_membudget_attach(dns_membudget_t *src, dns_membudget_t **dstp) {
	REQUIRE(DNS_MEMBUDGET_VALID(src));
	REQUIRE(dstp != NULL && *dstp == NULL);

	isc_refcount_increment(&src->references);
	*dstp = src;
}

void
dns_membudget_detach(dns_membudget_t **bp) {
	REQUIRE(bp != NULL && DNS_MEMBUDGET_VALID(*bp));

	dns_membudget_t *b = *bp;
	*bp = NULL;

	if (isc_refcount_decrement(&b->references) == 1) {
		isc_refcount_destroy(&b->references);
		b->magic = 0;
		isc_mem_putanddetach(&b->mctx, b, sizeof(*b));
	}
}

void
dns_membudget_resize(dns_membudget_t *b, uint64_t new_size) {
	REQUIRE(DNS_MEMBUDGET_VALID(b));
	REQUIRE(new_size != 0);

	dns_size_init(&b->ramp, new_size);
}

void
dns_membudget_register(dns_membudget_t *b, dns_membudget_tenant_t *t,
		       const char *name, isc_mem_t *tenant_mctx) {
	REQUIRE(DNS_MEMBUDGET_VALID(b));
	REQUIRE(t != NULL);
	REQUIRE(t->budget == NULL);
	REQUIRE(tenant_mctx != NULL);

	t->name = name;
	t->mctx = tenant_mctx;
	t->slot = -1;
	dns_membudget_attach(b, &t->budget);

	for (size_t i = 0; i < DNS_MEMBUDGET_MAX_TENANTS; i++) {
		if (!atomic_compare_exchange_strong(
			    &b->tenants[i], &(dns_membudget_tenant_t *){ NULL },
			    t))
		{
			continue;
		}

		t->slot = (int)i;
		return;
	}

	UNREACHABLE();
}

void
dns_membudget_unregister(dns_membudget_tenant_t *t) {
	REQUIRE(t != NULL);
	REQUIRE(t->budget != NULL);
	REQUIRE(t->slot >= 0 && t->slot < DNS_MEMBUDGET_MAX_TENANTS);

	dns_membudget_t *b = t->budget;
	REQUIRE(DNS_MEMBUDGET_VALID(b));

	atomic_store_release(&b->tenants[t->slot], NULL);
	t->slot = -1;
	t->mctx = NULL;
	t->name = NULL;
	dns_membudget_detach(&t->budget);
}

uint8_t
dns_membudget_cleaning_prob(dns_membudget_tenant_t *t, size_t purgesize) {
	REQUIRE(t != NULL);

	dns_membudget_t *b = t->budget;
	if (b == NULL) {
		return 0;
	}
	REQUIRE(DNS_MEMBUDGET_VALID(b));

	uint64_t global_inuse = 0;
	uint64_t tenant_inuse = 0;
	unsigned int n_active = 0;

	for (size_t i = 0; i < DNS_MEMBUDGET_MAX_TENANTS; i++) {
		dns_membudget_tenant_t *ti =
			atomic_load_acquire(&b->tenants[i]);
		if (ti == NULL) {
			continue;
		}
		n_active++;
		uint64_t in = isc_mem_inuse(ti->mctx);
		if (ti == t) {
			in += purgesize;
			tenant_inuse = in;
		}
		global_inuse += in;
	}

	if (global_inuse == 0 || tenant_inuse == 0 || n_active == 0) {
		return 0;
	}

	uint8_t global_prob = dns_size_cleaning_prob(&b->ramp, global_inuse);
	if (global_prob == 0) {
		return 0;
	}

	/*
	 * Proportional pressure: scale the global ramp by this tenant's
	 * share of the global in-use total, amplified by the active tenant
	 * count.  A tenant holding the average share (1/n_active) cleans at
	 * exactly global_prob; a tenant holding twice the average cleans at
	 * 2 * global_prob (saturated to 255).
	 */
	uint64_t scaled =
		((uint64_t)global_prob * tenant_inuse * (uint64_t)n_active) /
		global_inuse;
	if (scaled > 255) {
		scaled = 255;
	}
	return (uint8_t)scaled;
}

uint64_t
dns_membudget_max(const dns_membudget_t *b) {
	REQUIRE(DNS_MEMBUDGET_VALID(b));
	return b->ramp.cached_size;
}

uint64_t
dns_membudget_inuse(const dns_membudget_t *b) {
	REQUIRE(DNS_MEMBUDGET_VALID(b));

	uint64_t sum = 0;
	for (size_t i = 0; i < DNS_MEMBUDGET_MAX_TENANTS; i++) {
		dns_membudget_tenant_t *ti =
			atomic_load_acquire(&b->tenants[i]);
		if (ti != NULL) {
			sum += isc_mem_inuse(ti->mctx);
		}
	}
	return sum;
}

uint64_t
dns_membudget_tenant_inuse(const dns_membudget_tenant_t *t) {
	REQUIRE(t != NULL);
	if (t->mctx == NULL) {
		return 0;
	}
	return isc_mem_inuse(t->mctx);
}

unsigned int
dns_membudget_tenant_count(const dns_membudget_t *b) {
	REQUIRE(DNS_MEMBUDGET_VALID(b));

	unsigned int n = 0;
	for (size_t i = 0; i < DNS_MEMBUDGET_MAX_TENANTS; i++) {
		if (atomic_load_acquire(&b->tenants[i]) != NULL) {
			n++;
		}
	}
	return n;
}
