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

/*
 * Benchmark for the dns_message parse/reset cycle: the hot path of
 * every served query and every received response.  Run before and
 * after allocator changes to compare.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/message.h>

/*
 * Aim for a comparable wall-clock budget per case regardless of the
 * message size.
 */
#define BENCH_BYTES (100 * 1024 * 1024)

/* A query for isc.org/A with RD set. */
static const unsigned char query_wire[] = {
	0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 'i',  's',  'c',  0x03, 'o',
	'r',  'g',  0x00, 0x00, 0x01, 0x00, 0x01,
};

static isc_mem_t *mctx = NULL;

/*
 * Build a response with 'nrecords' A records owned by 'nnames' distinct
 * owner names (isc.org with a numeric label prefix), so both the dedup
 * and the no-dedup parse paths get exercised.
 */
static size_t
build_response(unsigned char *wire, size_t wiresize, unsigned int nrecords,
	       unsigned int nnames) {
	isc_buffer_t b;

	isc_buffer_init(&b, wire, wiresize);

	isc_buffer_putuint16(&b, 0x1234);	      /* ID */
	isc_buffer_putuint16(&b, 0x8180);	      /* QR RD RA */
	isc_buffer_putuint16(&b, 1);		      /* QDCOUNT */
	isc_buffer_putuint16(&b, (uint16_t)nrecords); /* ANCOUNT */
	isc_buffer_putuint16(&b, 0);		      /* NSCOUNT */
	isc_buffer_putuint16(&b, 0);		      /* ARCOUNT */

	/* question: isc.org A IN */
	isc_buffer_putmem(&b, (const unsigned char *)"\x03isc\x03org\x00", 9);
	isc_buffer_putuint16(&b, 1);
	isc_buffer_putuint16(&b, 1);

	for (unsigned int i = 0; i < nrecords; i++) {
		char label[16];
		unsigned int n = snprintf(label, sizeof(label), "h%u",
					  i % nnames);

		/* owner: hN.isc.org via compression pointer */
		isc_buffer_putuint8(&b, (uint8_t)n);
		isc_buffer_putmem(&b, (const unsigned char *)label, n);
		isc_buffer_putuint16(&b, 0xc00c);

		isc_buffer_putuint16(&b, 1); /* type A */
		isc_buffer_putuint16(&b, 1); /* class IN */
		isc_buffer_putuint32(&b, 60);
		isc_buffer_putuint16(&b, 4);
		isc_buffer_putuint8(&b, 192);
		isc_buffer_putuint8(&b, 0);
		isc_buffer_putuint8(&b, 2);
		isc_buffer_putuint8(&b, (uint8_t)(i % 251));
	}

	return isc_buffer_usedlength(&b);
}

static void
bench(const char *title, const unsigned char *wire, size_t size,
      unsigned int options) {
	dns_message_t *msg = NULL;
	isc_time_t start, finish;
	uint64_t microseconds;
	unsigned int iterations = ISC_CLAMP(BENCH_BYTES / size, 2000, 200000);

	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	start = isc_time_now_hires();
	for (unsigned int i = 0; i < iterations; i++) {
		isc_buffer_t buffer;
		isc_result_t result;

		isc_buffer_constinit(&buffer, wire, size);
		isc_buffer_add(&buffer, size);
		isc_buffer_setactive(&buffer, size);

		result = dns_message_parse(msg, &buffer, options);
		INSIST(result == ISC_R_SUCCESS);
		dns_message_reset(msg, DNS_MESSAGE_INTENTPARSE);
	}
	finish = isc_time_now_hires();
	microseconds = isc_time_microdiff(&finish, &start);

	printf("%-28s %8zu bytes %10u iters %8.0f ns/parse %10.0f/s\n", title,
	       size, iterations, (double)microseconds * 1000.0 / iterations,
	       iterations / ((double)microseconds / 1000000.0));

	dns_message_detach(&msg);
}

int
main(void) {
	static unsigned char large_wire[65535];
	size_t size;

	isc_mem_create("bench", &mctx);

	bench("query", query_wire, sizeof(query_wire), 0);

	size = build_response(large_wire, sizeof(large_wire), 20, 4);
	bench("response 20rr/4names", large_wire, size, 0);
	bench("response 20rr/4names order", large_wire, size,
	      DNS_MESSAGEPARSE_PRESERVEORDER);

	size = build_response(large_wire, sizeof(large_wire), 200, 40);
	bench("response 200rr/40names", large_wire, size, 0);
	bench("response 200rr/40names order", large_wire, size,
	      DNS_MESSAGEPARSE_PRESERVEORDER);

	size = build_response(large_wire, sizeof(large_wire), 1500, 1500);
	bench("axfr-like 1500rr", large_wire, size,
	      DNS_MESSAGEPARSE_PRESERVEORDER);

	isc_mem_detach(&mctx);

	return 0;
}
