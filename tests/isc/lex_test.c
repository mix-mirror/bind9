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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <tests/isc.h>

#define AS_STR(x) (x).value.as_textregion.base

#define TEST_REFILL_SIZE (16U * 1024U)

/* check handling of 0x00 */
ISC_RUN_TEST_IMPL(lex_0x00) {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t buf;
	isc_token_t token;

	unsigned char nul_then_A[] = { '\0', 'A' };
	unsigned char embedded_null[] = { '"', 'a', '\0', 'b', '"' };
	unsigned char escaped_null[] = { 'a', '\\', '\0', 'b' };

	UNUSED(state);

	assert_int_equal(isc_lex_create_dns_master(isc_g_mctx, 1024, &lex),
			 ISC_R_SUCCESS);

	isc_buffer_init(&buf, &nul_then_A[0], sizeof(nul_then_A));
	isc_buffer_add(&buf, sizeof(nul_then_A));

	result = isc_lex_openbuffer(lex, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_unknown);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);

	isc_lex_close(lex);

	/*
	 * Check that an embedded NUL is preserved in a quoted string.
	 */
	isc_buffer_init(&buf, &embedded_null[0], sizeof(embedded_null));
	isc_buffer_add(&buf, sizeof(embedded_null));

	result = isc_lex_openbuffer(lex, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_int_equal(token.value.as_textregion.length, 3);
	assert_memory_equal(token.value.as_textregion.base, "a\0b", 3);

	isc_lex_close(lex);

	/*
	 * Check that an escaped NUL is preserved.
	 */
	isc_buffer_init(&buf, &escaped_null[0], sizeof(escaped_null));
	isc_buffer_add(&buf, sizeof(escaped_null));

	result = isc_lex_openbuffer(lex, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_int_equal(token.value.as_textregion.length, 4);
	assert_memory_equal(token.value.as_textregion.base, "a\\\0b", 4);

	isc_lex_destroy(&lex);
}

/*
 * A NUL token must not preserve a stale beginning-of-line state:
 * whitespace following the NUL is not initial whitespace.
 */
ISC_RUN_TEST_IMPL(lex_0x00_initialws) {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t buf;
	isc_token_t token;

	unsigned char nul_then_ws[] = { 'a', '\n', '\0', ' ', 'b' };

	UNUSED(state);

	assert_int_equal(isc_lex_create_dns_master(isc_g_mctx, 1024, &lex),
			 ISC_R_SUCCESS);

	isc_buffer_init(&buf, &nul_then_ws[0], sizeof(nul_then_ws));
	isc_buffer_add(&buf, sizeof(nul_then_ws));

	result = isc_lex_openbuffer(lex, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_unknown);
	/*
	 * The unknown token must not leave the previous token's text
	 * region pointer behind for a caller to dereference.
	 */
	assert_null(token.value.as_textregion.base);
	assert_int_equal(token.value.as_textregion.length, 0);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "b");

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_dns_master_policy) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = " 123 \"hello\"\nkey=\"a b\"port=53";

	UNUSED(state);

	assert_int_equal(isc_lex_create_dns_master(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_initialws);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "123");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_string_equal(AS_STR(token), "hello");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "key=");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_string_equal(AS_STR(token), "a b");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) != 0);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "port=53");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) != 0);

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_separated_qstring) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = "key= \"value\"";

	UNUSED(state);

	assert_int_equal(isc_lex_create_dns_master(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "key=");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_string_equal(AS_STR(token), "value");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) == 0);

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_refill_and_unget) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_region_t raw;
	isc_token_t token;
	FILE *stream = NULL;
	char *text;
	int fclose_result;
	const size_t atom_length = TEST_REFILL_SIZE * 2U + 37U;
	const size_t text_length = atom_length + sizeof("first  tail") - 1U;
	size_t offset;
	unsigned int source_kind;

	UNUSED(state);

	text = malloc(text_length);
	assert_non_null(text);
	offset = 0;
	memmove(text + offset, "first ", sizeof("first ") - 1U);
	offset += sizeof("first ") - 1U;
	memset(text + offset, 'a', atom_length);
	offset += atom_length;
	memmove(text + offset, " tail", sizeof(" tail") - 1U);
	offset += sizeof(" tail") - 1U;
	assert_int_equal(offset, text_length);

	for (source_kind = 0; source_kind < 2; source_kind++) {
		assert_int_equal(isc_lex_create_command(isc_g_mctx, 8, &lex),
				 ISC_R_SUCCESS);
		if (source_kind == 0) {
			isc_buffer_init(&buf, text, text_length);
			isc_buffer_add(&buf, text_length);
			assert_int_equal(isc_lex_openbuffer(lex, &buf),
					 ISC_R_SUCCESS);
		} else {
			stream = tmpfile();
			assert_non_null(stream);
			assert_int_equal(fwrite(text, 1, text_length, stream),
					 text_length);
			rewind(stream);
			isc_lex_openstream(lex, stream);
		}

		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_string);
		assert_string_equal(AS_STR(token), "first");

		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_string);
		assert_int_equal(token.value.as_textregion.length, atom_length);
		assert_memory_equal(AS_STR(token), text + sizeof("first ") - 1U,
				    atom_length);
		isc_lex_getlasttokentext(lex, &token, &raw);
		assert_int_equal(raw.length, atom_length);
		assert_memory_equal(raw.base, text + sizeof("first ") - 1U,
				    atom_length);

		isc_lex_ungettoken(lex, &token);
		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_string);
		assert_int_equal(token.value.as_textregion.length, atom_length);
		assert_memory_equal(AS_STR(token), text + sizeof("first ") - 1U,
				    atom_length);

		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_string);
		assert_string_equal(AS_STR(token), "tail");
		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_eof);

		isc_lex_destroy(&lex);
		if (stream != NULL) {
			fclose_result = fclose(stream);
			assert_int_equal(fclose_result, 0);
			stream = NULL;
		}
	}

	free(text);
}

ISC_RUN_TEST_IMPL(lex_qstring_refill_and_cooking) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_region_t raw;
	isc_token_t token;
	char *text;
	const size_t prefix_length = TEST_REFILL_SIZE - 2U;
	const size_t text_length = TEST_REFILL_SIZE + 3U;
	size_t offset = 0;

	UNUSED(state);

	text = malloc(text_length);
	assert_non_null(text);
	text[offset++] = '"';
	memset(text + offset, 'a', prefix_length);
	offset += prefix_length;
	text[offset++] = '\\';
	text[offset++] = '"';
	text[offset++] = 'b';
	text[offset++] = '"';
	assert_int_equal(offset, text_length);

	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_init(&buf, text, text_length);
	isc_buffer_add(&buf, text_length);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_int_equal(token.value.as_textregion.length, prefix_length + 2U);
	assert_memory_equal(AS_STR(token), text + 1U, prefix_length);
	assert_int_equal(AS_STR(token)[prefix_length], '"');
	assert_int_equal(AS_STR(token)[prefix_length + 1U], 'b');
	assert_int_equal(AS_STR(token)[prefix_length + 2U], '\0');

	isc_lex_getlasttokentext(lex, &token, &raw);
	assert_int_equal(raw.length, text_length);
	assert_memory_equal(raw.base, text, text_length);

	isc_lex_ungettoken(lex, &token);
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_int_equal(token.value.as_textregion.length, prefix_length + 2U);
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);

	isc_lex_destroy(&lex);
	free(text);
}

ISC_RUN_TEST_IMPL(lex_config_policy) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = "{ \"two\nlines\" 123 }";

	UNUSED(state);

	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_special);
	assert_int_equal(token.value.as_char, '{');

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_string_equal(AS_STR(token), "two\nlines");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "123");

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_no_sources) {
	isc_lex_t *lex = NULL;
	isc_token_t token;

	UNUSED(state);

	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_NOMORE);
	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_dns_comments) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] =
		"foo; ignored\n\"a;b\" foo\\;bar\r; ignored too\nbar";

	UNUSED(state);

	assert_int_equal(isc_lex_create_dns_master(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "foo");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_string_equal(AS_STR(token), "a;b");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "foo\\;bar");

	/* A bare CR and the comment's LF are separate line endings. */
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "bar");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_config_comments) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = "foo/* block */bar// line\n"
			    "baz# shell\n\"/*#//\"/x";

	UNUSED(state);

	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "foo");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "bar");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) == 0);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "baz");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) == 0);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_qstring);
	assert_string_equal(AS_STR(token), "/*#//");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) == 0);

	/* A non-comment slash remains an adjacent special. */
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_special);
	assert_int_equal(token.value.as_char, '/');
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) != 0);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "x");
	assert_true((token.flags & ISC_LEXFLAG_ADJACENT) != 0);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_unterminated_comment) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = "foo/*";

	UNUSED(state);

	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	/* Diagnose the comment on the call following the atom. */
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "foo");
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_UNEXPECTEDEND);

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_comment_refill) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	char *text;
	size_t length = TEST_REFILL_SIZE + 6U;

	UNUSED(state);

	/* Put the opening slash at the end of the first refill. */
	text = isc_mem_get(isc_g_mctx, length);
	memset(text, ' ', TEST_REFILL_SIZE - 1U);
	memmove(text + TEST_REFILL_SIZE - 1U, "/**/foo", 7U);
	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_init(&buf, text, length);
	isc_buffer_add(&buf, length);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "foo");
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);
	isc_lex_destroy(&lex);
	isc_mem_put(isc_g_mctx, text, length);

	/* Put the closing star at the end of the first refill. */
	length = TEST_REFILL_SIZE + 4U;
	text = isc_mem_get(isc_g_mctx, length);
	memmove(text, "/*", 2U);
	memset(text + 2U, 'x', TEST_REFILL_SIZE - 3U);
	memmove(text + TEST_REFILL_SIZE - 1U, "*/foo", 5U);
	assert_int_equal(isc_lex_create_config(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_init(&buf, text, length);
	isc_buffer_add(&buf, length);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "foo");
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);
	isc_lex_destroy(&lex);
	isc_mem_put(isc_g_mctx, text, length);
}

ISC_RUN_TEST_IMPL(lex_unget_eol) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = "key ; comment\n next";

	UNUSED(state);

	assert_int_equal(isc_lex_create_dns_master(isc_g_mctx, 4, &lex),
			 ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "key");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	isc_lex_ungettoken(lex, &token);

	/* Ungetting EOL must also restore beginning-of-line state. */
	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eol);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_initialws);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "next");

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_command_unget) {
	isc_buffer_t buf;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	const char text[] = "delzone example IN view";

	UNUSED(state);

	assert_int_equal(
		isc_lex_create_command(isc_g_mctx, sizeof(text) - 1, &lex),
		ISC_R_SUCCESS);
	isc_buffer_constinit(&buf, text, sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "delzone");
	isc_lex_ungettoken(lex, &token);

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "delzone");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "example");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "IN");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_string);
	assert_string_equal(AS_STR(token), "view");

	assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);

	isc_lex_destroy(&lex);
}

ISC_RUN_TEST_IMPL(lex_command_arguments) {
	static const struct {
		const char *input;
		const char *argument;
		isc_tokentype_t type;
	} tests[] = {
		{ "delzone .", ".", isc_tokentype_string },
		{ "delzone odd\"zone", "odd\"zone", isc_tokentype_string },
		{ "delzone odd\\\"zone", "odd\\\"zone", isc_tokentype_string },
		{ "delzone odd\\032zone", "odd\\032zone",
		  isc_tokentype_string },
		{ "delzone odd;zone", "odd;zone", isc_tokentype_string },
		{ "delzone odd#zone", "odd#zone", isc_tokentype_string },
		{ "delzone odd/zone", "odd/zone", isc_tokentype_string },
		{ "delzone odd{zone}", "odd{zone}", isc_tokentype_string },
		{ "delzone odd(zone)", "odd(zone)", isc_tokentype_string },
		{ "delzone \"odd zone\"", "odd zone", isc_tokentype_qstring },
		{ "delzone \"odd\\\"zone\"", "odd\"zone",
		  isc_tokentype_qstring },
	};

	UNUSED(state);

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		isc_buffer_t buf;
		isc_lex_t *lex = NULL;
		isc_token_t token;
		size_t length = strlen(tests[i].input);

		assert_int_equal(
			isc_lex_create_command(isc_g_mctx, length, &lex),
			ISC_R_SUCCESS);
		isc_buffer_constinit(&buf, tests[i].input, length);
		isc_buffer_add(&buf, length);
		assert_int_equal(isc_lex_openbuffer(lex, &buf), ISC_R_SUCCESS);

		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_string);
		assert_string_equal(AS_STR(token), "delzone");

		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, tests[i].type);
		assert_string_equal(AS_STR(token), tests[i].argument);

		assert_int_equal(isc_lex_next(lex, &token), ISC_R_SUCCESS);
		assert_int_equal(token.type, isc_tokentype_eof);

		isc_lex_destroy(&lex);
	}
}

/* check handling of 0xff */
ISC_RUN_TEST_IMPL(lex_0xff) {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	isc_buffer_t death_buf;
	isc_token_t token;

	unsigned char death[] = { EOF, 'A' };

	UNUSED(state);

	assert_int_equal(isc_lex_create_command(isc_g_mctx, 1024, &lex),
			 ISC_R_SUCCESS);

	isc_buffer_init(&death_buf, &death[0], sizeof(death));
	isc_buffer_add(&death_buf, sizeof(death));

	result = isc_lex_openbuffer(lex, &death_buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_lex_destroy(&lex);
}

/* check setting of source line */
ISC_RUN_TEST_IMPL(lex_setline) {
	isc_result_t result;
	isc_lex_t *lex = NULL;
	unsigned char text[] = "text\nto\nbe\nprocessed\nby\nlexer";
	isc_buffer_t buf;
	isc_token_t token;
	unsigned long line;
	int i;

	UNUSED(state);

	assert_int_equal(isc_lex_create_command(isc_g_mctx, 1024, &lex),
			 ISC_R_SUCCESS);

	isc_buffer_init(&buf, &text[0], sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);

	result = isc_lex_openbuffer(lex, &buf);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_lex_setsourceline(lex, 100);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (i = 0; i < 6; i++) {
		result = isc_lex_next(lex, &token);
		assert_int_equal(result, ISC_R_SUCCESS);

		line = isc_lex_getsourceline(lex);
		assert_int_equal(line, 100U + i);
	}

	result = isc_lex_next(lex, &token);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(token.type, isc_tokentype_eof);

	line = isc_lex_getsourceline(lex);
	assert_int_equal(line, 105U);

	isc_lex_destroy(&lex);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(lex_0x00)
ISC_TEST_ENTRY(lex_0x00_initialws)
ISC_TEST_ENTRY(lex_0xff)
ISC_TEST_ENTRY(lex_config_comments)
ISC_TEST_ENTRY(lex_config_policy)
ISC_TEST_ENTRY(lex_command_arguments)
ISC_TEST_ENTRY(lex_command_unget)
ISC_TEST_ENTRY(lex_comment_refill)
ISC_TEST_ENTRY(lex_dns_comments)
ISC_TEST_ENTRY(lex_dns_master_policy)
ISC_TEST_ENTRY(lex_no_sources)
ISC_TEST_ENTRY(lex_qstring_refill_and_cooking)
ISC_TEST_ENTRY(lex_refill_and_unget)
ISC_TEST_ENTRY(lex_separated_qstring)
ISC_TEST_ENTRY(lex_unget_eol)
ISC_TEST_ENTRY(lex_unterminated_comment)
ISC_TEST_ENTRY(lex_setline)
ISC_TEST_LIST_END

ISC_TEST_MAIN
