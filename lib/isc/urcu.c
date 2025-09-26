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

#include <isc/mem.h>
#include <isc/urcu.h>

struct cds_lfht_alloc *isc__urcu_alloc = NULL;
isc_mem_t *isc__urcu_mctx = NULL;

#if HAVE_CDS_LFHT_ALLOC

void *
isc_urcu_malloc(void *state, size_t size) {
	REQUIRE(state != NULL);
	isc_mem_ref(state);
	return isc_mem_allocate(state, size);
}

void *
isc_urcu_calloc(void *state, size_t nmemb, size_t size) {
	REQUIRE(state != NULL);
	isc_mem_ref(state);
	return isc_mem_callocate(state, nmemb, size);
}

void *
isc_urcu_realloc(void *state, void *ptr, size_t size) {
	REQUIRE(state != NULL);
	return isc_mem_reallocate(state, ptr, size);
}

void *
isc_urcu_aligned_alloc(void *state ISC_ATTR_UNUSED,
		       size_t alignment ISC_ATTR_UNUSED,
		       size_t size ISC_ATTR_UNUSED) {
	/*
	 * This function is required by the API, but it is actually not used by
	 * the userspace-rcu, so instead of implementing aligned_alloc() in our
	 * isc_mem API, we make sure it won't be called.
	 */
	UNREACHABLE();
}

void
isc_urcu_free(void *state, void *ptr) {
	REQUIRE(state != NULL);
	isc_mem_free(state, ptr);
	isc_mem_unref(state);
}

static struct cds_lfht_alloc isc__urcu_alloc_s = { 0 };

void
isc__urcu_initialize(void) {
	isc_mem_create("cds_lfht_alloc", &isc__urcu_mctx);
	isc__urcu_alloc_s = (struct cds_lfht_alloc){
		.malloc = isc_urcu_malloc,
		.calloc = isc_urcu_calloc,
		.realloc = isc_urcu_realloc,
		.aligned_alloc = isc_urcu_aligned_alloc,
		.free = isc_urcu_free,
		.state = isc__urcu_mctx,
	};
	isc__urcu_alloc = &isc__urcu_alloc_s;
}

void
isc__urcu_shutdown(void) {
	isc__urcu_alloc = NULL;
	isc_mem_detach(&isc__urcu_mctx);
}

#else

void
isc__urcu_initialize(void) {
	/* no-op */
}

void
isc__urcu_shutdown(void) {
	/* no-op */
}

#endif /* HAVE_ISC_URCU_ALLOC */
