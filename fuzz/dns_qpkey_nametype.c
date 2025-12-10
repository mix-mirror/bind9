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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/random.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/qp.h>

#include "fuzz.h"

#include <tests/qp.h>

bool debug = false;

int
LLVMFuzzerInitialize(int *argc, char ***argv) {
	UNUSED(argc);
	UNUSED(argv);
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	dns_fixedname_t fixedin, fixedout;
	dns_name_t *namein, *nameout;
	uint16_t typein = 0, typeout = 0;
	dns_namespace_t spacein = 0, spaceout = 0;
	isc_buffer_t buf;
	dns_qpkey_t key;

	namein = dns_fixedname_initname(&fixedin);
	nameout = dns_fixedname_initname(&fixedout);

	isc_buffer_constinit(&buf, data, size);
	isc_buffer_add(&buf, size);
	isc_buffer_setactive(&buf, size);

	CHECK(dns_name_fromwire(namein, &buf, DNS_DECOMPRESS_NEVER, NULL));
	typein = isc_random16();
	spacein = isc_random_uniform(3);

	/* verify round-trip conversion of first name */
	size_t keylen = dns_qpkey_fromnametype(key, namein, typein, spacein);
	dns_qpkey_tonametype(key, keylen, nameout, &typeout, &spaceout);

	assert(dns_name_equal(namein, nameout));
	assert(typein == typeout);
	assert(spacein == spaceout);

	return 0;
}
