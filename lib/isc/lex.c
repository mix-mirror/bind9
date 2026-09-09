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

/*! \file */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/file.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/parseint.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/util.h>

#include "errno2result.h"

typedef struct inputsource {
	isc_result_t result;
	bool is_file;
	bool need_close;
	bool at_eof;
	bool last_was_eol;
	isc_buffer_t *pushback;
	unsigned int saved_current;
	unsigned int ignored;
	void *input;
	char *name;
	unsigned long line;
	unsigned long saved_line;
	bool have_token;
	bool saved_have_token;
	ISC_LINK(struct inputsource) link;
} inputsource;

#define LEX_MAGIC    ISC_MAGIC('L', 'e', 'x', '!')
#define VALID_LEX(l) ISC_MAGIC_VALID(l, LEX_MAGIC)

#define LEX_REFILL_SIZE	 (16U * 1024U)
#define LEX_PADDING_SIZE 2U

#define ISC_LEXOPT_EOF		    0x0002
#define ISC_LEXOPT_INITIALWS	    0x0004
#define ISC_LEXOPT_QSTRINGMULTILINE 0x0200

/*
 * Each character selects a 64-bit row containing ten six-bit transitions.
 * Scanning states are their bit offsets in the row (0, 6, ..., 54).  Odd
 * values select slow-path actions, which need no outgoing transitions.
 *
 * Only the low six bits of a shifted row encode the next state.  Masking
 * the shift count, rather than the result, lets hardware with modulo-64
 * shifts keep the mask off the loop-carried state dependency.
 */
typedef enum {
	lexstate_start = 0,
	lexstate_atom = 6,
	lexstate_atom_escaped = 12,
	lexstate_qstring = 18,
	lexstate_qstring_escaped = 24,
	lexstate_qstring_needs_cooking = 30,
	lexstate_slash = 36,
	lexstate_line_comment = 42,
	lexstate_block_comment = 48,
	lexstate_block_comment_star = 54,

	lexstate_atom_done = 1,
	lexstate_qstring_done = 3,
	lexstate_qstring_cooked_done = 5,
	lexstate_initialws = 7,
	lexstate_newline_return = 9,
	lexstate_newline_skip = 11,
	lexstate_cr_return = 13,
	lexstate_cr_skip = 15,
	lexstate_slash_done = 17,
	lexstate_comment_done = 19,
	lexstate_block_comment_newline = 21,
	lexstate_line_comment_nul = 23,
	lexstate_block_comment_nul = 25,
	lexstate_block_comment_star_nul = 27,
	lexstate_special = 29,
	lexstate_paren = 31,
	lexstate_start_nul = 33,
	lexstate_atom_escaped_nul = 35,
	lexstate_qstring_nul = 37,
	lexstate_qstring_escaped_nul = 39,
	lexstate_qstring_cooked_nul = 41,
	lexstate_qstring_newline = 43,
	lexstate_qstring_escaped_newline = 45,
	lexstate_qstring_cooked_newline = 47,
	lexstate_last_final = lexstate_qstring_cooked_newline,
} lexstate_t;

STATIC_ASSERT(lexstate_block_comment_star + 6 <= 64,
	      "scanning transitions fit in one row");
STATIC_ASSERT(lexstate_last_final < 64, "actions fit in six bits");

#define S lexstate_start
#define A lexstate_atom
#define E lexstate_atom_escaped
#define Q lexstate_qstring
#define X lexstate_qstring_escaped
#define C lexstate_qstring_needs_cooking
#define D lexstate_slash
#define L lexstate_line_comment
#define B lexstate_block_comment
#define T lexstate_block_comment_star

/* Columns: start, atom, escaped atom, quoted string, escaped quoted string,
 * cooked quoted string, slash, line comment, block comment, block-comment star.
 */
#define PACK_ROW(s, a, e, q, x, c, d, l, b, t)                             \
	(((1ull * (s)) << S) | ((1ull * (a)) << A) | ((1ull * (e)) << E) | \
	 ((1ull * (q)) << Q) | ((1ull * (x)) << X) | ((1ull * (c)) << C) | \
	 ((1ull * (d)) << D) | ((1ull * (l)) << L) | ((1ull * (b)) << B) | \
	 ((1ull * (t)) << T))

#define ROW_ORDINARY PACK_ROW(A, A, A, Q, C, C, lexstate_slash_done, L, B, B)
#define ROW_SPACE                                                    \
	PACK_ROW(lexstate_initialws, lexstate_atom_done, A, Q, C, C, \
		 lexstate_slash_done, L, B, B)
#define ROW_LF_RETURN                                                     \
	PACK_ROW(lexstate_newline_return, lexstate_atom_done,             \
		 lexstate_atom_done, lexstate_qstring_newline,            \
		 lexstate_qstring_escaped_newline,                        \
		 lexstate_qstring_cooked_newline, lexstate_slash_done,    \
		 lexstate_newline_return, lexstate_block_comment_newline, \
		 lexstate_block_comment_newline)
#define ROW_LF_SKIP                                                     \
	PACK_ROW(lexstate_newline_skip, lexstate_atom_done,             \
		 lexstate_atom_done, lexstate_qstring_newline,          \
		 lexstate_qstring_escaped_newline,                      \
		 lexstate_qstring_cooked_newline, lexstate_slash_done,  \
		 lexstate_newline_skip, lexstate_block_comment_newline, \
		 lexstate_block_comment_newline)
#define ROW_CR_RETURN                                                        \
	PACK_ROW(lexstate_cr_return, lexstate_atom_done, lexstate_atom_done, \
		 Q, C, C, lexstate_slash_done, L, B, B)
#define ROW_CR_SKIP                                                           \
	PACK_ROW(lexstate_cr_skip, lexstate_atom_done, lexstate_atom_done, Q, \
		 C, C, lexstate_slash_done, L, B, B)
#define ROW_NUL                                                             \
	PACK_ROW(lexstate_start_nul, lexstate_atom_done,                    \
		 lexstate_atom_escaped_nul, lexstate_qstring_nul,           \
		 lexstate_qstring_escaped_nul, lexstate_qstring_cooked_nul, \
		 lexstate_slash_done, lexstate_line_comment_nul,            \
		 lexstate_block_comment_nul, lexstate_block_comment_star_nul)
#define ROW_QUOTE                                                    \
	PACK_ROW(Q, lexstate_atom_done, A, lexstate_qstring_done, C, \
		 lexstate_qstring_cooked_done, lexstate_slash_done, L, B, B)
#define ROW_QSTRING_QUOTE                           \
	PACK_ROW(Q, A, A, lexstate_qstring_done, C, \
		 lexstate_qstring_cooked_done, lexstate_slash_done, L, B, B)
#define ROW_BACKSLASH PACK_ROW(E, E, A, X, C, X, lexstate_slash_done, L, B, B)
#define ROW_QSTRING_BACKSLASH \
	PACK_ROW(A, A, A, X, C, X, lexstate_slash_done, L, B, B)
#define ROW_SPECIAL                                                \
	PACK_ROW(lexstate_special, lexstate_atom_done, A, Q, C, C, \
		 lexstate_slash_done, L, B, B)
#define ROW_DNS_COMMENT                                                        \
	PACK_ROW(L, lexstate_atom_done, A, Q, C, C, lexstate_slash_done, L, B, \
		 B)
#define ROW_SHELL_COMMENT                                            \
	PACK_ROW(L, lexstate_atom_done, lexstate_atom_done, Q, C, C, \
		 lexstate_slash_done, L, B, B)
#define ROW_SLASH                                            \
	PACK_ROW(D, lexstate_atom_done, A, Q, C, C, L, L, B, \
		 lexstate_comment_done)
#define ROW_STAR PACK_ROW(A, A, A, Q, C, C, B, L, T, T)
#define ROW_PAREN                                                \
	PACK_ROW(lexstate_paren, lexstate_atom_done, A, Q, C, C, \
		 lexstate_slash_done, L, B, B)

/* Explicit ranges cover ordinary bytes without overriding initializers. */
static const uint64_t line_rows[256] = {
	['\0'] = ROW_NUL,
	[0x01 ... 0x08] = ROW_ORDINARY,
	['\t'] = ROW_SPACE,
	['\n'] = ROW_LF_RETURN,
	[0x0b ... 0x0c] = ROW_ORDINARY,
	['\r'] = ROW_CR_RETURN,
	[0x0e ... 0x1f] = ROW_ORDINARY,
	[' '] = ROW_SPACE,
	['!' ... 0xff] = ROW_ORDINARY,
};

static const uint64_t command_rows[256] = {
	['\0'] = ROW_NUL,
	[0x01 ... 0x08] = ROW_ORDINARY,
	['\t'] = ROW_SPACE,
	['\n'] = ROW_LF_SKIP,
	[0x0b ... 0x0c] = ROW_ORDINARY,
	['\r'] = ROW_CR_SKIP,
	[0x0e ... 0x1f] = ROW_ORDINARY,
	[' '] = ROW_SPACE,
	['!'] = ROW_ORDINARY,
	['"'] = ROW_QSTRING_QUOTE,
	['#' ... '['] = ROW_ORDINARY,
	['\\'] = ROW_QSTRING_BACKSLASH,
	[']' ... 0xff] = ROW_ORDINARY,
};

static const uint64_t dns_rows[256] = {
	['\0'] = ROW_NUL,
	[0x01 ... 0x08] = ROW_ORDINARY,
	['\t'] = ROW_SPACE,
	['\n'] = ROW_LF_RETURN,
	[0x0b ... 0x0c] = ROW_ORDINARY,
	['\r'] = ROW_CR_RETURN,
	[0x0e ... 0x1f] = ROW_ORDINARY,
	[' '] = ROW_SPACE,
	['!'] = ROW_ORDINARY,
	['"'] = ROW_QUOTE,
	['#' ... '\''] = ROW_ORDINARY,
	['(' ... ')'] = ROW_PAREN,
	['*' ... ':'] = ROW_ORDINARY,
	[';'] = ROW_DNS_COMMENT,
	['<' ... '['] = ROW_ORDINARY,
	['\\'] = ROW_BACKSLASH,
	[']' ... 0xff] = ROW_ORDINARY,
};

static const uint64_t dns_bundle_rows[256] = {
	['\0'] = ROW_NUL,
	[0x01 ... 0x08] = ROW_ORDINARY,
	['\t'] = ROW_SPACE,
	['\n'] = ROW_LF_RETURN,
	[0x0b ... 0x0c] = ROW_ORDINARY,
	['\r'] = ROW_CR_RETURN,
	[0x0e ... 0x1f] = ROW_ORDINARY,
	[' '] = ROW_SPACE,
	['!'] = ROW_ORDINARY,
	['"'] = ROW_QUOTE,
	['#' ... '\''] = ROW_ORDINARY,
	['(' ... ')'] = ROW_PAREN,
	['*' ... '['] = ROW_ORDINARY,
	['\\'] = ROW_BACKSLASH,
	[']' ... 0xff] = ROW_ORDINARY,
};

static const uint64_t config_rows[256] = {
	['\0'] = ROW_NUL,
	[0x01 ... 0x08] = ROW_ORDINARY,
	['\t'] = ROW_SPACE,
	['\n'] = ROW_LF_SKIP,
	[0x0b ... 0x0c] = ROW_ORDINARY,
	['\r'] = ROW_CR_SKIP,
	[0x0e ... 0x1f] = ROW_ORDINARY,
	[' '] = ROW_SPACE,
	['!'] = ROW_SPECIAL,
	['"'] = ROW_QUOTE,
	['#'] = ROW_SHELL_COMMENT,
	['$' ... ')'] = ROW_ORDINARY,
	['*'] = ROW_STAR,
	['+' ... '.'] = ROW_ORDINARY,
	['/'] = ROW_SLASH,
	['0' ... ':'] = ROW_ORDINARY,
	[';'] = ROW_SPECIAL,
	['<' ... '['] = ROW_ORDINARY,
	['\\'] = ROW_QSTRING_BACKSLASH,
	[']' ... 'z'] = ROW_ORDINARY,
	['{'] = ROW_SPECIAL,
	['|'] = ROW_ORDINARY,
	['}'] = ROW_SPECIAL,
	['~' ... 0xff] = ROW_ORDINARY,
};

#undef PACK_ROW
#undef ROW_ORDINARY
#undef ROW_SPACE
#undef ROW_LF_RETURN
#undef ROW_LF_SKIP
#undef ROW_CR_RETURN
#undef ROW_CR_SKIP
#undef ROW_NUL
#undef ROW_QUOTE
#undef ROW_QSTRING_QUOTE
#undef ROW_BACKSLASH
#undef ROW_QSTRING_BACKSLASH
#undef ROW_SPECIAL
#undef ROW_DNS_COMMENT
#undef ROW_SHELL_COMMENT
#undef ROW_SLASH
#undef ROW_STAR
#undef ROW_PAREN

struct isc_lex {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	size_t max_token;
	char *data;
	unsigned int options;
	bool last_was_eol;
	bool saved_last_was_eol;
	unsigned int paren_count;
	unsigned int saved_paren_count;
	const uint64_t *rows;
	ISC_LIST(struct inputsource) sources;
};

static const uint8_t in_token[64] = {
	[A] = 1,
	[E] = 1,
	[Q] = 1,
	[X] = 1,
	[C] = 1,
	[lexstate_qstring_done] = 1,
	[lexstate_qstring_cooked_done] = 1,
	[lexstate_qstring_newline] = 1,
	[lexstate_qstring_escaped_newline] = 1,
	[lexstate_qstring_cooked_newline] = 1,
};

#undef S
#undef A
#undef E
#undef Q
#undef X
#undef C
#undef D
#undef L
#undef B
#undef T

static void
ensure_data(isc_lex_t *lex, size_t length) {
	char *tmp;
	size_t size;

	if (length <= lex->max_token) {
		return;
	}

	size = lex->max_token;
	while (size < length) {
		size *= 2;
	}
	tmp = isc_mem_get(lex->mctx, size + 1);
	isc_mem_put(lex->mctx, lex->data, lex->max_token + 1);
	lex->data = tmp;
	lex->max_token = size;
}

static void
lex_create(isc_mem_t *mctx, size_t max_token, isc_lex_t **lexp) {
	isc_lex_t *lex;

	/*
	 * Create a lexer.
	 */
	REQUIRE(lexp != NULL && *lexp == NULL);

	if (max_token == 0U) {
		max_token = 1;
	}

	lex = isc_mem_get(mctx, sizeof(*lex));
	lex->data = isc_mem_get(mctx, max_token + 1);
	lex->mctx = mctx;
	lex->max_token = max_token;
	lex->options = 0;
	lex->last_was_eol = true;
	lex->paren_count = 0;
	lex->saved_paren_count = 0;
	lex->rows = line_rows;
	ISC_LIST_INIT(lex->sources);
	lex->magic = LEX_MAGIC;

	*lexp = lex;
}

isc_result_t
isc_lex_create_dns_master(isc_mem_t *mctx, size_t initial_token_size,
			  isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_INITIALWS;
	(*lexp)->rows = dns_rows;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_config(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_QSTRINGMULTILINE;
	(*lexp)->rows = config_rows;

	return ISC_R_SUCCESS;
}

static isc_result_t
create_dns_text(isc_mem_t *mctx, size_t initial_token_size, isc_lex_t **lexp,
		bool comments) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->rows = comments ? dns_rows : dns_bundle_rows;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_dnssec(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp) {
	return create_dns_text(mctx, initial_token_size, lexp, true);
}

isc_result_t
isc_lex_create_dnssec_bundle(isc_mem_t *mctx, size_t initial_token_size,
			     isc_lex_t **lexp) {
	return create_dns_text(mctx, initial_token_size, lexp, false);
}

isc_result_t
isc_lex_create_command(isc_mem_t *mctx, size_t initial_token_size,
		       isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF;
	(*lexp)->rows = command_rows;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_line(isc_mem_t *mctx, size_t initial_token_size,
		    isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF;

	return ISC_R_SUCCESS;
}

void
isc_lex_destroy(isc_lex_t **lexp) {
	isc_lex_t *lex;

	/*
	 * Destroy the lexer.
	 */

	REQUIRE(lexp != NULL);
	lex = *lexp;
	*lexp = NULL;
	REQUIRE(VALID_LEX(lex));

	while (!ISC_LIST_EMPTY(lex->sources)) {
		RUNTIME_CHECK(isc_lex_close(lex) == ISC_R_SUCCESS);
	}
	if (lex->data != NULL) {
		isc_mem_put(lex->mctx, lex->data, lex->max_token + 1);
	}
	lex->magic = 0;
	isc_mem_put(lex->mctx, lex, sizeof(*lex));
}

static void
new_source(isc_lex_t *lex, bool is_file, bool need_close, void *input,
	   const char *name) {
	inputsource *source;

	source = isc_mem_get(lex->mctx, sizeof(*source));
	*source = (inputsource){
		.is_file = is_file,
		.need_close = need_close,
		.last_was_eol = lex->last_was_eol,
		.input = input,
		.name = isc_mem_strdup(lex->mctx, name),
		.line = 1,
		.link = ISC_LINK_INITIALIZER,
	};
	isc_buffer_allocate(lex->mctx, &source->pushback,
			    LEX_REFILL_SIZE + LEX_PADDING_SIZE);
	((unsigned char *)source->pushback->base)[0] = 0;
	((unsigned char *)source->pushback->base)[1] = 0;
	ISC_LIST_PREPEND(lex->sources, source, link);
}

isc_result_t
isc_lex_openfile(isc_lex_t *lex, const char *filename) {
	FILE *stream = NULL;

	/*
	 * Open 'filename' and make it the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	RETERR(isc_stdio_open(filename, "r", &stream));

	new_source(lex, true, true, stream, filename);
	return ISC_R_SUCCESS;
}

void
isc_lex_openstream(isc_lex_t *lex, FILE *stream) {
	char name[128];

	/*
	 * Make 'stream' the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	snprintf(name, sizeof(name), "stream-%p", stream);

	new_source(lex, true, false, stream, name);
}

isc_result_t
isc_lex_openbuffer(isc_lex_t *lex, isc_buffer_t *buffer) {
	char name[128];

	/*
	 * Make 'buffer' the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	snprintf(name, sizeof(name), "buffer-%p", buffer);

	new_source(lex, false, false, buffer, name);
	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_close(isc_lex_t *lex) {
	inputsource *source;
	unsigned int unread;

	/*
	 * Close the most recently opened object (i.e. file or buffer).
	 */

	REQUIRE(VALID_LEX(lex));

	source = ISC_LIST_HEAD(lex->sources);
	if (source == NULL) {
		return ISC_R_NOMORE;
	}

	ISC_LIST_UNLINK(lex->sources, source, link);
	lex->last_was_eol = source->last_was_eol;
	unread = isc_buffer_remaininglength(source->pushback);
	if (source->is_file) {
		if (source->need_close) {
			(void)fclose((FILE *)(source->input));
		}
	} else if (unread != 0U) {
		isc_buffer_back((isc_buffer_t *)source->input, unread);
	}
	isc_mem_free(lex->mctx, source->name);
	isc_buffer_free(&source->pushback);
	isc_mem_put(lex->mctx, source, sizeof(*source));

	return ISC_R_SUCCESS;
}

static void
finish_atom(inputsource *source, isc_token_t *tokenp) {
	isc_buffer_t *buffer = source->pushback;
	size_t length = buffer->current - source->ignored;

	tokenp->type = isc_tokentype_string;
	tokenp->value.as_region.base = (unsigned char *)buffer->base +
				       source->ignored;
	tokenp->value.as_region.length = (unsigned int)length;
}

static void
finish_qstring(inputsource *source, isc_token_t *tokenp) {
	isc_buffer_t *buffer = source->pushback;
	unsigned char *raw;
	size_t raw_length;

	INSIST(buffer->current >= source->ignored + 2U);
	raw = (unsigned char *)buffer->base + source->ignored + 1U;
	raw_length = buffer->current - source->ignored - 2U;
	tokenp->type = isc_tokentype_qstring;
	tokenp->value.as_region.base = raw;
	tokenp->value.as_region.length = (unsigned int)raw_length;
}

static void
finish_qstring_cooked(isc_lex_t *lex, inputsource *source,
		      isc_token_t *tokenp) {
	isc_buffer_t *buffer = source->pushback;
	unsigned char *raw;
	char *dst;
	size_t raw_length;
	bool escaped = false;

	INSIST(buffer->current >= source->ignored + 2U);
	raw = (unsigned char *)buffer->base + source->ignored + 1U;
	raw_length = buffer->current - source->ignored - 2U;
	ensure_data(lex, raw_length);
	dst = lex->data;
	for (size_t i = 0; i < raw_length; i++) {
		int c = raw[i];

		if (c == '"' && escaped) {
			dst[-1] = '"';
			escaped = false;
			continue;
		}
		escaped = c == '\\' && !escaped;
		*dst++ = c;
	}

	tokenp->type = isc_tokentype_qstring;
	tokenp->value.as_region.base = (unsigned char *)lex->data;
	tokenp->value.as_region.length = (unsigned int)(dst - lex->data);
}

static void
compact_to_checkpoint(inputsource *source) {
	isc_buffer_t *buffer = source->pushback;
	unsigned int discarded = source->saved_current;
	unsigned int retained;

	if (discarded == 0U) {
		return;
	}

	INSIST(discarded <= buffer->current);
	INSIST(discarded <= source->ignored);
	retained = buffer->used - discarded;
	memmove(buffer->base, (unsigned char *)buffer->base + discarded,
		retained);
	buffer->current -= discarded;
	buffer->used = retained;
	buffer->active = 0;
	source->ignored -= discarded;
	source->saved_current = 0;
}

static isc_result_t
refill(inputsource *source) {
	isc_buffer_t *buffer = source->pushback;
	isc_region_t available;
	size_t nread;

	REQUIRE(isc_buffer_remaininglength(buffer) <= 1U);
	REQUIRE(!source->at_eof);

	if (isc_buffer_availablelength(buffer) <
	    LEX_REFILL_SIZE + LEX_PADDING_SIZE)
	{
		compact_to_checkpoint(source);
		RETERR(isc_buffer_reserve(buffer,
					  LEX_REFILL_SIZE + LEX_PADDING_SIZE));
	}
	isc_buffer_availableregion(buffer, &available);
	INSIST(available.length >= LEX_REFILL_SIZE + LEX_PADDING_SIZE);

	if (source->is_file) {
		nread = fread(available.base, 1, LEX_REFILL_SIZE,
			      (FILE *)source->input);
		isc_buffer_add(buffer, (unsigned int)nread);
		if (nread < LEX_REFILL_SIZE) {
			if (ferror((FILE *)source->input)) {
				return isc__errno2result(errno);
			}
			if (feof((FILE *)source->input)) {
				source->at_eof = true;
			}
		}
	} else {
		isc_buffer_t *input = source->input;
		isc_region_t remaining;

		isc_buffer_remainingregion(input, &remaining);
		nread = ISC_MIN(remaining.length, LEX_REFILL_SIZE);
		if (nread != 0U) {
			memmove(available.base, remaining.base, nread);
			isc_buffer_forward(input, (unsigned int)nread);
			isc_buffer_add(buffer, (unsigned int)nread);
		}
		if (isc_buffer_remaininglength(input) == 0U) {
			source->at_eof = true;
		}
	}

	/*
	 * Keep two readable bytes beyond the input so scanners can always load
	 * the current and following bytes without a bounds check.  The padding
	 * is not included in buffer->used and therefore is never input.
	 */
	((unsigned char *)buffer->base)[buffer->used] = 0;
	((unsigned char *)buffer->base)[buffer->used + 1] = 0;

	return ISC_R_SUCCESS;
}

static isc_result_t
consume_cr(inputsource *source) {
	isc_buffer_t *buffer = source->pushback;
	unsigned char *p;

	if (isc_buffer_remaininglength(buffer) <= 1U && !source->at_eof) {
		source->result = refill(source);
		if (source->result != ISC_R_SUCCESS) {
			return source->result;
		}
	}

	p = (unsigned char *)buffer->base + buffer->current;
	source->ignored = buffer->current;
	if (p[1] == '\n') {
		buffer->current += 2U;
		source->line++;
	} else {
		buffer->current++;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
lex_gettoken(isc_lex_t *lex, isc_token_t *tokenp) {
	/* Dispatch final states without a second bounds check after the loop.
	 */
	static const void *const dispatch[(lexstate_last_final >> 1) + 1] = {
		[lexstate_atom_done >> 1] = &&atom_done,
		[lexstate_qstring_done >> 1] = &&qstring_done,
		[lexstate_qstring_cooked_done >> 1] = &&qstring_cooked_done,
		[lexstate_initialws >> 1] = &&initialws,
		[lexstate_newline_return >> 1] = &&newline_return,
		[lexstate_newline_skip >> 1] = &&newline_skip,
		[lexstate_cr_return >> 1] = &&cr_return,
		[lexstate_cr_skip >> 1] = &&cr_skip,
		[lexstate_slash_done >> 1] = &&slash_done,
		[lexstate_comment_done >> 1] = &&comment_done,
		[lexstate_block_comment_newline >> 1] = &&block_comment_newline,
		[lexstate_line_comment_nul >> 1] = &&line_comment_nul,
		[lexstate_block_comment_nul >> 1] = &&block_comment_nul,
		[lexstate_block_comment_star_nul >> 1] =
			&&block_comment_star_nul,
		[lexstate_special >> 1] = &&special,
		[lexstate_paren >> 1] = &&paren,
		[lexstate_start_nul >> 1] = &&start_nul,
		[lexstate_atom_escaped_nul >> 1] = &&atom_escaped_nul,
		[lexstate_qstring_nul >> 1] = &&qstring_nul,
		[lexstate_qstring_escaped_nul >> 1] = &&qstring_escaped_nul,
		[lexstate_qstring_cooked_nul >> 1] = &&qstring_cooked_nul,
		[lexstate_qstring_newline >> 1] = &&qstring_newline,
		[lexstate_qstring_escaped_newline >> 1] =
			&&qstring_escaped_newline,
		[lexstate_qstring_cooked_newline >> 1] =
			&&qstring_cooked_newline,
	};
	inputsource *source;
	isc_buffer_t *buffer;
	unsigned char *base;
	unsigned char *p;
	size_t token_length = 0;
	isc_result_t result;
	size_t state;

	/*
	 * Get the next token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);
	REQUIRE(tokenp != NULL);
	tokenp->flags = 0;

	if (source == NULL) {
		return ISC_R_NOMORE;
	}

	if (source->result != ISC_R_SUCCESS) {
		return source->result;
	}
	buffer = source->pushback;

	lex->saved_paren_count = lex->paren_count;
	lex->saved_last_was_eol = lex->last_was_eol;
	source->saved_line = source->line;
	source->saved_have_token = source->have_token;
	source->saved_current = source->pushback->current;
	source->ignored = source->saved_current;

	state = lexstate_start;
	base = buffer->base;
	p = base + buffer->current;

	for (;;) {
		do {
			uint64_t row = lex->rows[*p++];

			state = row >> (state & 63);
			token_length += in_token[state & 63];
		} while ((state & 1) == 0);
		state &= 63;
		goto *dispatch[state >> 1];

	slash_done: {
		unsigned int lookahead = (unsigned int)(p - base - 1);

		if (p[-1] == 0 && lookahead == buffer->used && !source->at_eof)
		{
			buffer->current = lookahead;
			state = lexstate_slash;
			goto refill_and_resume;
		}
		buffer->current = lookahead;
		source->ignored = lookahead - 1U;
		tokenp->type = isc_tokentype_special;
		tokenp->value.as_char = '/';
		lex->last_was_eol = false;
		result = ISC_R_SUCCESS;
		goto done;
	}

	comment_done:
		buffer->current = (unsigned int)(p - base);
		state = lexstate_start;
		continue;

	block_comment_newline:
		buffer->current = (unsigned int)(p - base);
		source->line++;
		state = lexstate_block_comment;
		continue;

	atom_done: {
		unsigned int end = (unsigned int)(p - base - 1);

		if (p[-1] == 0 && end == buffer->used && !source->at_eof) {
			buffer->current = end;
			state = lexstate_atom;
			goto refill_and_resume;
		}
		buffer->current = end;
		source->ignored = end - (unsigned int)token_length;
		finish_atom(source, tokenp);
		lex->last_was_eol = false;
		result = ISC_R_SUCCESS;
		goto done;
	}

	qstring_done:
	qstring_cooked_done:
		buffer->current = (unsigned int)(p - base);
		source->ignored = buffer->current - (unsigned int)token_length;
		if (state == lexstate_qstring_done) {
			finish_qstring(source, tokenp);
		} else {
			finish_qstring_cooked(lex, source, tokenp);
		}
		lex->last_was_eol = false;
		result = ISC_R_SUCCESS;
		goto done;

	initialws:
		if (lex->paren_count != 0 || !lex->last_was_eol ||
		    (lex->options & ISC_LEXOPT_INITIALWS) == 0)
		{
			state = lexstate_start;
			continue;
		}
		buffer->current = (unsigned int)(p - base);
		source->ignored = buffer->current - 1U;
		lex->last_was_eol = false;
		tokenp->type = isc_tokentype_initialws;
		tokenp->value.as_char = p[-1];
		result = ISC_R_SUCCESS;
		goto done;

	newline_return:
		if (lex->paren_count != 0) {
			goto newline_skip;
		}
		buffer->current = (unsigned int)(p - base);
		source->ignored = buffer->current - 1U;
		source->line++;
		lex->last_was_eol = true;
		tokenp->type = isc_tokentype_eol;
		result = ISC_R_SUCCESS;
		goto done;

	newline_skip:
		buffer->current = (unsigned int)(p - base);
		source->ignored = buffer->current - 1U;
		source->line++;
		lex->last_was_eol = true;
		state = lexstate_start;
		continue;

	cr_return:
		if (lex->paren_count != 0) {
			goto cr_skip;
		}
		buffer->current = (unsigned int)(p - base - 1);
		result = consume_cr(source);
		if (result != ISC_R_SUCCESS) {
			goto done;
		}
		lex->last_was_eol = true;
		tokenp->type = isc_tokentype_eol;
		goto done;

	cr_skip:
		buffer->current = (unsigned int)(p - base - 1);
		result = consume_cr(source);
		if (result != ISC_R_SUCCESS) {
			goto done;
		}
		base = buffer->base;
		p = base + buffer->current;
		lex->last_was_eol = true;
		state = lexstate_start;
		continue;

	special:
		buffer->current = (unsigned int)(p - base);
		source->ignored = buffer->current - 1U;
		lex->last_was_eol = false;
		tokenp->type = isc_tokentype_special;
		tokenp->value.as_char = p[-1];
		result = ISC_R_SUCCESS;
		goto done;

	paren: {
		unsigned char c = p[-1];

		buffer->current = (unsigned int)(p - base);
		lex->last_was_eol = false;
		if (c == ')' && lex->paren_count == 0) {
			result = ISC_R_UNBALANCED;
			goto done;
		}
		lex->paren_count += (c == '(') - (c == ')');
		state = lexstate_start;
		continue;
	}

	line_comment_nul:
	block_comment_nul:
	block_comment_star_nul: {
		unsigned int nul = (unsigned int)(p - base - 1);
		lexstate_t resume;

		if (state == lexstate_line_comment_nul) {
			resume = lexstate_line_comment;
		} else if (state == lexstate_block_comment_star_nul) {
			resume = lexstate_block_comment_star;
		} else {
			resume = lexstate_block_comment;
		}

		buffer->current = nul;
		if (nul == buffer->used) {
			if (!source->at_eof) {
				state = resume;
				goto refill_and_resume;
			}
			if (state != lexstate_line_comment_nul) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			state = lexstate_start;
			p = base + buffer->current;
			continue;
		}

		buffer->current++;
		state = resume == lexstate_block_comment_star
				? lexstate_block_comment
				: resume;
		p = base + buffer->current;
		continue;
	}

	start_nul: {
		unsigned int nul = (unsigned int)(p - base - 1);

		if (nul == buffer->used) {
			buffer->current = nul;
			if (!source->at_eof) {
				state = lexstate_start;
				goto refill_and_resume;
			}
			source->ignored = buffer->current;
			lex->last_was_eol = false;
			if (lex->paren_count != 0) {
				lex->paren_count = 0;
				result = ISC_R_UNBALANCED;
				goto done;
			}
			if ((lex->options & ISC_LEXOPT_EOF) == 0) {
				result = ISC_R_EOF;
				goto done;
			}
			tokenp->type = isc_tokentype_eof;
			result = ISC_R_SUCCESS;
			goto done;
		}

		buffer->current = nul + 1U;
		source->ignored = nul;
		lex->last_was_eol = false;
		tokenp->type = isc_tokentype_unknown;
		tokenp->value.as_region.base = NULL;
		tokenp->value.as_region.length = 0;
		result = ISC_R_SUCCESS;
		goto done;
	}

	atom_escaped_nul:
	qstring_nul:
	qstring_escaped_nul:
	qstring_cooked_nul: {
		unsigned int nul = (unsigned int)(p - base - 1);
		lexstate_t resume;

		switch (state) {
		case lexstate_atom_escaped_nul:
			resume = lexstate_atom_escaped;
			break;
		case lexstate_qstring_nul:
			resume = lexstate_qstring;
			break;
		case lexstate_qstring_escaped_nul:
			resume = lexstate_qstring_escaped;
			break;
		case lexstate_qstring_cooked_nul:
			resume = lexstate_qstring_needs_cooking;
			break;
		default:
			UNREACHABLE();
		}

		buffer->current = nul;
		if (nul == buffer->used) {
			if (!source->at_eof) {
				state = resume;
				goto refill_and_resume;
			}
			lex->last_was_eol = false;
			result = ISC_R_UNEXPECTEDEND;
			goto done;
		}

		buffer->current++;
		token_length++;
		state = resume == lexstate_atom_escaped
				? lexstate_atom
				: (resume == lexstate_qstring_escaped
					   ? lexstate_qstring_needs_cooking
					   : resume);
		p = base + buffer->current;
		continue;
	}

	refill_and_resume:
		source->result = refill(source);
		if (source->result != ISC_R_SUCCESS) {
			result = source->result;
			goto done;
		}
		base = buffer->base;
		p = base + buffer->current;
		continue;

	qstring_newline:
	qstring_cooked_newline:
		if ((lex->options & ISC_LEXOPT_QSTRINGMULTILINE) == 0) {
			buffer->current = (unsigned int)(p - base - 1);
			lex->last_was_eol = false;
			result = ISC_R_UNBALANCEDQUOTES;
			goto done;
		}
		buffer->current = (unsigned int)(p - base);
		source->line++;
		state = state == lexstate_qstring_newline
				? lexstate_qstring
				: lexstate_qstring_needs_cooking;
		continue;

	qstring_escaped_newline:
		buffer->current = (unsigned int)(p - base);
		source->line++;
		state = lexstate_qstring_needs_cooking;
		continue;
	}

done:
	if (result == ISC_R_SUCCESS) {
		if (source->have_token &&
		    source->ignored == source->saved_current)
		{
			tokenp->flags |= ISC_LEXFLAG_ADJACENT;
		}
		source->have_token = true;
	}
	return result;
}

isc_result_t
isc_lex_next(isc_lex_t *lex, isc_token_t *tokenp) {
	REQUIRE(VALID_LEX(lex));

	return lex_gettoken(lex, tokenp);
}

isc_result_t
isc_lex_getmastertoken(isc_lex_t *lex, isc_token_t *token,
		       isc_tokentype_t expect, bool eol) {
	isc_result_t result;

	result = isc_lex_next(lex, token);
	if (result == ISC_R_SUCCESS && expect == isc_tokentype_number &&
	    token->type == isc_tokentype_string)
	{
		uint32_t number;

		result = isc_parse_uint32_region(&number,
						 &token->value.as_region, 10);
		if (result == ISC_R_SUCCESS) {
			token->type = isc_tokentype_number;
			token->value.as_ulong = number;
		}
	}
	if (result == ISC_R_RANGE || result == ISC_R_BADNUMBER) {
		isc_lex_ungettoken(lex, token);
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (eol && ((token->type == isc_tokentype_eol) ||
		    (token->type == isc_tokentype_eof)))
	{
		return ISC_R_SUCCESS;
	}
	if (token->type == isc_tokentype_string &&
	    expect == isc_tokentype_qstring)
	{
		return ISC_R_SUCCESS;
	}
	if (token->type != expect) {
		isc_lex_ungettoken(lex, token);
		if (token->type == isc_tokentype_eol ||
		    token->type == isc_tokentype_eof)
		{
			return ISC_R_UNEXPECTEDEND;
		}
		if (expect == isc_tokentype_number) {
			return ISC_R_BADNUMBER;
		}
		return ISC_R_UNEXPECTEDTOKEN;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_getoctaltoken(isc_lex_t *lex, isc_token_t *token, bool eol) {
	isc_result_t result;

	result = isc_lex_next(lex, token);
	if (result == ISC_R_SUCCESS && token->type == isc_tokentype_string) {
		uint32_t number;

		result = isc_parse_uint32_region(&number,
						 &token->value.as_region, 8);
		if (result == ISC_R_SUCCESS) {
			token->type = isc_tokentype_number;
			token->value.as_ulong = number;
		}
	}
	if (result == ISC_R_RANGE || result == ISC_R_BADNUMBER) {
		isc_lex_ungettoken(lex, token);
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (eol && ((token->type == isc_tokentype_eol) ||
		    (token->type == isc_tokentype_eof)))
	{
		return ISC_R_SUCCESS;
	}
	if (token->type != isc_tokentype_number) {
		isc_lex_ungettoken(lex, token);
		if (token->type == isc_tokentype_eol ||
		    token->type == isc_tokentype_eof)
		{
			return ISC_R_UNEXPECTEDEND;
		}
		return ISC_R_BADNUMBER;
	}
	return ISC_R_SUCCESS;
}

void
isc_lex_ungettoken(isc_lex_t *lex, isc_token_t *tokenp) {
	inputsource *source;
	/*
	 * Unget the current token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);
	REQUIRE(source != NULL);
	REQUIRE(tokenp != NULL);
	REQUIRE(source->pushback->current != source->saved_current ||
		tokenp->type == isc_tokentype_eof);

	UNUSED(tokenp);

	source->pushback->current = source->saved_current;
	lex->paren_count = lex->saved_paren_count;
	lex->last_was_eol = lex->saved_last_was_eol;
	source->line = source->saved_line;
	source->have_token = source->saved_have_token;
}

void
isc_lex_getlasttokentext(isc_lex_t *lex, isc_token_t *tokenp, isc_region_t *r) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);
	REQUIRE(source != NULL);
	REQUIRE(tokenp != NULL);
	REQUIRE(source->pushback->current != source->saved_current ||
		tokenp->type == isc_tokentype_eof);

	UNUSED(tokenp);

	INSIST(source->ignored <= source->pushback->current);
	r->base = (unsigned char *)isc_buffer_base(source->pushback) +
		  source->ignored;
	r->length = source->pushback->current - source->ignored;
}

char *
isc_lex_getsourcename(isc_lex_t *lex) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);

	if (source == NULL) {
		return NULL;
	}

	return source->name;
}

unsigned long
isc_lex_getsourceline(isc_lex_t *lex) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);

	if (source == NULL) {
		return 0;
	}

	return source->line;
}

isc_result_t
isc_lex_setsourcename(isc_lex_t *lex, const char *name) {
	inputsource *source;
	char *newname;

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);

	if (source == NULL) {
		return ISC_R_NOTFOUND;
	}
	newname = isc_mem_strdup(lex->mctx, name);
	isc_mem_free(lex->mctx, source->name);
	source->name = newname;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_setsourceline(isc_lex_t *lex, unsigned long line) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);

	if (source == NULL) {
		return ISC_R_NOTFOUND;
	}

	source->line = line;
	return ISC_R_SUCCESS;
}

bool
isc_lex_isfile(isc_lex_t *lex) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));

	source = ISC_LIST_HEAD(lex->sources);

	if (source == NULL) {
		return false;
	}

	return source->is_file;
}
