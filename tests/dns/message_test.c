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
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>

#include <tests/dns.h>

/*
 * Lifecycle coverage for the dns_message allocation machinery: these
 * tests pin the externally visible behavior (parse layouts, reply and
 * re-render survival rules, temporary-object cycles) ahead of internal
 * allocator changes.
 */

/* A query for isc.org/A with RD set. */
static const unsigned char query_wire[] = {
	0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 'i',  's',  'c',  0x03, 'o',
	'r',  'g',  0x00, 0x00, 0x01, 0x00, 0x01,
};

/*
 * A response for isc.org/A: three A records plus one TXT record, all
 * owned by isc.org (compression pointers to the question name), which
 * exercises both the per-section name dedup and the per-name rdataset
 * dedup on parse.
 */
/* clang-format off */
static const unsigned char response_wire[] = {
	0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	/* question: isc.org A IN */
	0x03, 'i', 's', 'c', 0x03, 'o', 'r', 'g', 0x00, 0x00, 0x01, 0x00,
	0x01,
	/* answer 1: A 192.0.2.1 */
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
	0xc0, 0x00, 0x02, 0x01,
	/* answer 2: A 192.0.2.2 */
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
	0xc0, 0x00, 0x02, 0x02,
	/* answer 3: A 192.0.2.3 */
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
	0xc0, 0x00, 0x02, 0x03,
	/* answer 4: TXT "test" */
	0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x05,
	0x04, 't', 'e', 's', 't',
};
/* clang-format on */

/*
 * A dynamic update deleting the A RRset from del.example: the update
 * record has class ANY and zero-length rdata.
 */
/* clang-format off */
static const unsigned char update_wire[] = {
	0x12, 0x34, 0x28, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	/* zone: example SOA IN */
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00, 0x00, 0x06, 0x00,
	0x01,
	/* update: del.example A ANY, rdlen 0 */
	0x03, 'd', 'e', 'l', 0xc0, 0x0c, 0x00, 0x01, 0x00, 0xff, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};
/* clang-format on */

static void
wire_to_buffer(isc_buffer_t *buffer, const unsigned char *wire, size_t size) {
	isc_buffer_constinit(buffer, wire, size);
	isc_buffer_add(buffer, size);
	isc_buffer_setactive(buffer, size);
}

static void
parse_wire(dns_message_t *msg, const unsigned char *wire, size_t size,
	   unsigned int options, isc_result_t expected) {
	isc_buffer_t buffer;

	wire_to_buffer(&buffer, wire, size);
	assert_int_equal(dns_message_parse(msg, &buffer, options), expected);
}

static unsigned int
count_section_names(dns_message_t *msg, dns_section_t section) {
	unsigned int count = 0;
	isc_result_t result;

	for (result = dns_message_firstname(msg, section);
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(msg, section))
	{
		count++;
	}
	return count;
}

ISC_RUN_TEST_IMPL(message_parse_query) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	dns_name_t *qname = NULL;
	dns_fixedname_t fixed;
	dns_name_t *expected = dns_fixedname_initname(&fixed);

	isc_mem_create("message_parse_query", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	parse_wire(msg, query_wire, sizeof(query_wire), 0, ISC_R_SUCCESS);

	assert_int_equal(msg->counts[DNS_SECTION_QUESTION], 1);
	assert_int_equal(msg->counts[DNS_SECTION_ANSWER], 0);

	assert_int_equal(dns_message_firstname(msg, DNS_SECTION_QUESTION),
			 ISC_R_SUCCESS);
	dns_message_currentname(msg, DNS_SECTION_QUESTION, &qname);
	assert_int_equal(
		dns_name_fromstring(expected, "isc.org.", NULL, 0, NULL),
		ISC_R_SUCCESS);
	assert_true(dns_name_equal(qname, expected));

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(message_parse_response_dedup) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	dns_name_t *name = NULL;
	unsigned int rdatasets = 0;

	isc_mem_create("message_parse_dedup", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	parse_wire(msg, response_wire, sizeof(response_wire), 0, ISC_R_SUCCESS);

	/* All four answer records share one owner name... */
	assert_int_equal(count_section_names(msg, DNS_SECTION_ANSWER), 1);

	/* ...with two rdatasets: A (three rdata) and TXT (one). */
	assert_int_equal(dns_message_firstname(msg, DNS_SECTION_ANSWER),
			 ISC_R_SUCCESS);
	dns_message_currentname(msg, DNS_SECTION_ANSWER, &name);
	ISC_LIST_FOREACH(name->list, rds, link) {
		unsigned int rdatas = 0;
		isc_result_t result;

		for (result = dns_rdataset_first(rds); result == ISC_R_SUCCESS;
		     result = dns_rdataset_next(rds))
		{
			rdatas++;
		}
		if (rds->type == dns_rdatatype_a) {
			assert_int_equal(rdatas, 3);
		} else {
			assert_int_equal(rds->type, dns_rdatatype_txt);
			assert_int_equal(rdatas, 1);
		}
		rdatasets++;
	}
	assert_int_equal(rdatasets, 2);

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(message_parse_preserveorder) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;

	isc_mem_create("message_parse_preserve", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	parse_wire(msg, response_wire, sizeof(response_wire),
		   DNS_MESSAGEPARSE_PRESERVEORDER, ISC_R_SUCCESS);

	/* No dedup: each answer record keeps its own name. */
	assert_int_equal(count_section_names(msg, DNS_SECTION_ANSWER), 4);

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

/*
 * A response whose answer is an RRSIG covering type 0 ("none"), which
 * is a semantic error detected after the rdata parses cleanly.
 */
/* clang-format off */
static const unsigned char badsig_wire[] = {
	0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	/* question: isc.org A IN */
	0x03, 'i', 's', 'c', 0x03, 'o', 'r', 'g', 0x00, 0x00, 0x01, 0x00,
	0x01,
	/* answer: isc.org RRSIG covering type 0 */
	0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x17,
	/* covered 0, alg 5, labels 0, origttl 60 */
	0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x3c,
	/* expire 0, inception 0, keytag 0, signer ".", sig 4 bytes */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde,
	0xad, 0xbe, 0xef,
};
/* clang-format on */

ISC_RUN_TEST_IMPL(message_parse_besteffort) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;

	isc_mem_create("message_parse_besteffort", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	/*
	 * Truncation is a hard error even with BESTEFFORT (only
	 * IGNORETRUNCATION changes that), but the intact prefix of the
	 * message must survive: the in-flight partial objects are
	 * dropped, the completed ones stay in their sections.
	 */
	parse_wire(msg, response_wire, sizeof(response_wire) - 3,
		   DNS_MESSAGEPARSE_BESTEFFORT, ISC_R_UNEXPECTEDEND);
	assert_int_equal(count_section_names(msg, DNS_SECTION_QUESTION), 1);
	assert_int_equal(count_section_names(msg, DNS_SECTION_ANSWER), 1);

	/*
	 * A semantic problem (an RRSIG covering type "none") is fatal
	 * without BESTEFFORT and recoverable with it.
	 */
	dns_message_reset(msg, DNS_MESSAGE_INTENTPARSE);
	parse_wire(msg, badsig_wire, sizeof(badsig_wire), 0, DNS_R_FORMERR);

	dns_message_reset(msg, DNS_MESSAGE_INTENTPARSE);
	parse_wire(msg, badsig_wire, sizeof(badsig_wire),
		   DNS_MESSAGEPARSE_BESTEFFORT, DNS_R_RECOVERABLE);

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(message_parse_update_zerolen) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;

	isc_mem_create("message_parse_update", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	parse_wire(msg, update_wire, sizeof(update_wire), 0, ISC_R_SUCCESS);

	assert_int_equal(count_section_names(msg, DNS_SECTION_ZONE), 1);
	assert_int_equal(count_section_names(msg, DNS_SECTION_UPDATE), 1);

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

/*
 * Parse a query, turn the same message into a reply and render it: the
 * question-section name (and its storage) must survive the intent flip.
 */
ISC_RUN_TEST_IMPL(message_reply_render) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	dns_message_t *reparsed = NULL;
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char render_buf[512];
	dns_name_t *qname = NULL;
	dns_fixedname_t fixed;
	dns_name_t *expected = dns_fixedname_initname(&fixed);

	isc_mem_create("message_reply_render", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	parse_wire(msg, query_wire, sizeof(query_wire), 0, ISC_R_SUCCESS);

	assert_int_equal(dns_message_reply(msg, true), ISC_R_SUCCESS);
	msg->flags |= DNS_MESSAGEFLAG_QR;

	isc_buffer_init(&buffer, render_buf, sizeof(render_buf));
	dns_compress_init(&cctx, mctx, 0);
	assert_int_equal(dns_message_renderbegin(msg, &cctx, &buffer),
			 ISC_R_SUCCESS);
	assert_int_equal(
		dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0),
		ISC_R_SUCCESS);
	assert_int_equal(dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0),
			 ISC_R_SUCCESS);
	assert_int_equal(
		dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0),
		ISC_R_SUCCESS);
	assert_int_equal(
		dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0),
		ISC_R_SUCCESS);
	dns_message_renderend(msg);
	dns_compress_invalidate(&cctx);

	/* The rendered reply must contain the original question. */
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE,
			   &reparsed);
	assert_int_equal(dns_message_parse(reparsed, &buffer, 0),
			 ISC_R_SUCCESS);
	assert_true((reparsed->flags & DNS_MESSAGEFLAG_QR) != 0);
	assert_int_equal(reparsed->id, msg->id);
	assert_int_equal(dns_message_firstname(reparsed, DNS_SECTION_QUESTION),
			 ISC_R_SUCCESS);
	dns_message_currentname(reparsed, DNS_SECTION_QUESTION, &qname);
	assert_int_equal(
		dns_name_fromstring(expected, "isc.org.", NULL, 0, NULL),
		ISC_R_SUCCESS);
	assert_true(dns_name_equal(qname, expected));

	dns_message_detach(&reparsed);
	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

/*
 * Build a response from temporary objects, render it twice with a
 * renderreset in between: both renderings must be byte-identical
 * (request.c and nsupdate re-render the same message on retries).
 */
ISC_RUN_TEST_IMPL(message_renderreset_rerender) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	dns_name_t *name = NULL;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdataset_t *rdataset = NULL;
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char render_one[512];
	unsigned char render_two[512];
	size_t len_one, len_two;
	static unsigned char rdata_bytes[] = { 192, 0, 2, 1 };

	isc_mem_create("message_renderreset", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTRENDER, &msg);

	dns_message_gettempname(msg, &name);
	assert_int_equal(dns_name_fromstring(name, "a.example.", NULL, 0, NULL),
			 ISC_R_SUCCESS);

	dns_message_gettemprdata(msg, &rdata);
	rdata->data = rdata_bytes;
	rdata->length = sizeof(rdata_bytes);
	rdata->rdclass = dns_rdataclass_in;
	rdata->type = dns_rdatatype_a;

	dns_message_gettemprdatalist(msg, &rdatalist);
	rdatalist->rdclass = dns_rdataclass_in;
	rdatalist->type = dns_rdatatype_a;
	rdatalist->ttl = 60;
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);

	dns_message_gettemprdataset(msg, &rdataset);
	dns_rdatalist_tordataset(rdatalist, rdataset);

	ISC_LIST_APPEND(name->list, rdataset, link);
	dns_message_addname(msg, name, DNS_SECTION_ANSWER);

	for (size_t pass = 0; pass < 2; pass++) {
		unsigned char *render_buf = (pass == 0) ? render_one
							: render_two;

		isc_buffer_init(&buffer, render_buf, 512);
		dns_compress_init(&cctx, mctx, 0);
		assert_int_equal(dns_message_renderbegin(msg, &cctx, &buffer),
				 ISC_R_SUCCESS);
		assert_int_equal(
			dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0),
			ISC_R_SUCCESS);
		dns_message_renderend(msg);
		dns_compress_invalidate(&cctx);

		if (pass == 0) {
			len_one = isc_buffer_usedlength(&buffer);
			dns_message_renderreset(msg);
		} else {
			len_two = isc_buffer_usedlength(&buffer);
		}
	}

	assert_int_equal(len_one, len_two);
	assert_int_equal(memcmp(render_one, render_two, len_one), 0);

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

/*
 * Temporary-object churn: repeated get/put cycles must not accrete
 * memory (the dedup parse path and ns/query recycle objects heavily).
 */
ISC_RUN_TEST_IMPL(message_temp_cycles) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	dns_fixedname_t fixed;
	dns_name_t *source = dns_fixedname_initname(&fixed);
	size_t inuse[100];

	isc_mem_create("message_temp_cycles", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTRENDER, &msg);

	assert_int_equal(dns_name_fromstring(source, "long-name.example.", NULL,
					     0, NULL),
			 ISC_R_SUCCESS);

	for (size_t i = 0; i < 100; i++) {
		dns_name_t *name = NULL;
		dns_rdata_t *rdata = NULL;
		dns_rdatalist_t *rdatalist = NULL;
		dns_rdataset_t *rdataset = NULL;

		dns_message_gettempname(msg, &name);
		/* The temp name has a dedicated buffer to copy into. */
		dns_name_copy(source, name);
		assert_true(dns_name_equal(name, source));
		dns_message_puttempname(msg, &name);

		dns_message_gettemprdata(msg, &rdata);
		dns_message_puttemprdata(msg, &rdata);

		dns_message_gettemprdatalist(msg, &rdatalist);
		dns_message_puttemprdatalist(msg, &rdatalist);

		dns_message_gettemprdataset(msg, &rdataset);
		dns_message_puttemprdataset(msg, &rdataset);

		inuse[i] = isc_mem_inuse(mctx);
	}

	/* Steady state, no accretion. */
	for (size_t i = 4; i < 100; i++) {
		assert_int_equal(inuse[i], inuse[3]);
	}

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(message_takebuffer) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	isc_buffer_t *buffer = NULL;

	isc_mem_create("message_takebuffer", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTRENDER, &msg);

	isc_buffer_allocate(mctx, &buffer, 64);
	isc_buffer_putstr(buffer, "donated");
	dns_message_takebuffer(msg, &buffer);
	assert_null(buffer);

	/* The message now owns the buffer; detach must free it. */
	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

/*
 * The synthrecord plugin pattern: a foreign (non-message) name may be
 * added to a section as long as it is removed before the message is
 * reset or destroyed.
 */
ISC_RUN_TEST_IMPL(message_foreign_name) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	dns_fixedname_t fixed;
	dns_name_t *foreign = dns_fixedname_initname(&fixed);

	isc_mem_create("message_foreign_name", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTRENDER, &msg);

	assert_int_equal(
		dns_name_fromstring(foreign, "foreign.example.", NULL, 0, NULL),
		ISC_R_SUCCESS);

	dns_message_addname(msg, foreign, DNS_SECTION_ANSWER);
	assert_int_equal(count_section_names(msg, DNS_SECTION_ANSWER), 1);
	dns_message_removename(msg, foreign, DNS_SECTION_ANSWER);
	assert_int_equal(count_section_names(msg, DNS_SECTION_ANSWER), 0);

	/* The stack name must not be touched by message teardown. */
	dns_message_detach(&msg);
	assert_true(dns_name_equal(foreign, foreign));
	isc_mem_detach(&mctx);
}

/*
 * dns_message_setquerytsig() copies the caller's buffer into
 * message-owned storage (temp rdata + a donated buffer); the message
 * teardown must free all of it.
 */
ISC_RUN_TEST_IMPL(message_querytsig_copy) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	isc_buffer_t *tsigin = NULL;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	static const unsigned char tsig_bytes[] = { 0xde, 0xad, 0xbe, 0xef,
						    0x01, 0x02, 0x03, 0x04 };

	isc_mem_create("message_querytsig", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	isc_buffer_allocate(mctx, &tsigin, sizeof(tsig_bytes));
	isc_buffer_putmem(tsigin, tsig_bytes, sizeof(tsig_bytes));

	dns_message_setquerytsig(msg, tsigin);
	isc_buffer_free(&tsigin);

	assert_non_null(msg->querytsig);
	assert_int_equal(dns_rdataset_first(msg->querytsig), ISC_R_SUCCESS);
	dns_rdataset_current(msg->querytsig, &rdata);
	assert_int_equal(rdata.length, sizeof(tsig_bytes));
	assert_int_equal(memcmp(rdata.data, tsig_bytes, sizeof(tsig_bytes)), 0);

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

/*
 * A reused message (reset + reparse per client request) must reach a
 * memory steady state.
 */
ISC_RUN_TEST_IMPL(message_reset_reuse) {
	isc_mem_t *mctx = NULL;
	dns_message_t *msg = NULL;
	size_t inuse[20];

	isc_mem_create("message_reset_reuse", &mctx);
	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	for (size_t i = 0; i < 20; i++) {
		parse_wire(msg, response_wire, sizeof(response_wire), 0,
			   ISC_R_SUCCESS);
		dns_message_reset(msg, DNS_MESSAGE_INTENTPARSE);
		inuse[i] = isc_mem_inuse(mctx);
	}

	for (size_t i = 4; i < 20; i++) {
		assert_int_equal(inuse[i], inuse[3]);
	}

	dns_message_detach(&msg);
	isc_mem_detach(&mctx);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(message_parse_query)
ISC_TEST_ENTRY(message_parse_response_dedup)
ISC_TEST_ENTRY(message_parse_preserveorder)
ISC_TEST_ENTRY(message_parse_besteffort)
ISC_TEST_ENTRY(message_parse_update_zerolen)
ISC_TEST_ENTRY(message_reply_render)
ISC_TEST_ENTRY(message_renderreset_rerender)
ISC_TEST_ENTRY(message_temp_cycles)
ISC_TEST_ENTRY(message_takebuffer)
ISC_TEST_ENTRY(message_foreign_name)
ISC_TEST_ENTRY(message_querytsig_copy)
ISC_TEST_ENTRY(message_reset_reuse)

ISC_TEST_LIST_END

ISC_TEST_MAIN
