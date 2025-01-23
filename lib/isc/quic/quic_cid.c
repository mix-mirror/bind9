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

#include "quic_session.h"

void
isc_quic_cid_create(isc_mem_t *mctx, const isc_region_t *restrict cid_data,
		    isc_quic_cid_t **cidp) {
	isc_quic_cid_t *cid = NULL;

	REQUIRE(cid_data != NULL && cid_data->base != NULL &&
		cid_data->length > 0);
	REQUIRE(cidp != NULL && *cidp == NULL);

	cid = isc_mem_get(mctx, sizeof(*cid));

	*cid = (isc_quic_cid_t){
		.global_link = ISC_LINK_INITIALIZER,
		.local_link = ISC_LINK_INITIALIZER,
	};

	isc_refcount_init(&cid->references, 1);

	ngtcp2_cid_init(&cid->cid, cid_data->base, cid_data->length);

	isc_mem_attach(mctx, &cid->mctx);

	/* We need to acquire a memory barrier here */
	(void)isc_refcount_current(&cid->references);
	cid->magic = QUIC_CID_MAGIC;
	*cidp = cid;
}

void
isc_quic_cid_attach(isc_quic_cid_t *restrict source, isc_quic_cid_t **targetp) {
	REQUIRE(VALID_QUIC_CID(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
isc_quic_cid_detach(isc_quic_cid_t **cidp) {
	isc_quic_cid_t *restrict cid = NULL;

	cid = *cidp;
	*cidp = NULL;

	REQUIRE(VALID_QUIC_CID(cid));

	if (isc_refcount_decrement(&cid->references) > 1) {
		return;
	}

	/* We need to acquire a memory barrier here */
	(void)isc_refcount_current(&cid->references);
	cid->magic = 0;
	isc_mem_putanddetach(&cid->mctx, cid, sizeof(*cid));
}

void
isc_quic_cid_data(const isc_quic_cid_t *restrict cid,
		  isc_region_t *restrict cid_data) {
	REQUIRE(VALID_QUIC_CID(cid));
	REQUIRE(cid_data != NULL);

	cid_data->base = (uint8_t *)cid->cid.data;
	cid_data->length = (unsigned int)cid->cid.datalen;
}
