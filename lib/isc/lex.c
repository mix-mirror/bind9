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
 * Final states precede scanning states so the scanner can test all of them
 * with a single comparison.  Character classes are premultiplied by the
 * number of states, making the hot transition a single indexed load.
 */
typedef enum {
	lexstate_atom_done,
	lexstate_qstring_done,
	lexstate_qstring_cooked_done,
	lexstate_initialws,
	lexstate_newline_return,
	lexstate_newline_skip,
	lexstate_cr_return,
	lexstate_cr_skip,
	lexstate_slash_done,
	lexstate_comment_done,
	lexstate_block_comment_newline,
	lexstate_line_comment_nul,
	lexstate_block_comment_nul,
	lexstate_block_comment_star_nul,
	lexstate_special,
	lexstate_paren,
	lexstate_start_nul,
	lexstate_atom_escaped_nul,
	lexstate_qstring_nul,
	lexstate_qstring_escaped_nul,
	lexstate_qstring_cooked_nul,
	lexstate_qstring_newline,
	lexstate_qstring_escaped_newline,
	lexstate_qstring_cooked_newline,
	lexstate_last_final = lexstate_qstring_cooked_newline,

	lexstate_start,
	lexstate_start_initialws,
	lexstate_start_multiline,
	lexstate_atom,
	lexstate_atom_escaped,
	lexstate_qstring,
	lexstate_qstring_escaped,
	lexstate_qstring_needs_cooking,
	lexstate_slash,
	lexstate_line_comment,
	lexstate_line_comment_multiline,
	lexstate_block_comment,
	lexstate_block_comment_star,
	lexstate_count,
} lexstate_t;

typedef enum {
	lexclass_ordinary,
	lexclass_space,
	lexclass_lf_return,
	lexclass_lf_skip,
	lexclass_cr_return,
	lexclass_cr_skip,
	lexclass_nul,
	lexclass_quote,
	lexclass_qstring_quote,
	lexclass_backslash,
	lexclass_qstring_backslash,
	lexclass_special,
	lexclass_dns_comment,
	lexclass_shell_comment,
	lexclass_slash,
	lexclass_star,
	lexclass_paren,
	lexclass_count,
} lexclass_t;

STATIC_ASSERT(lexstate_count <= UINT8_MAX, "lexer states fit in table");
STATIC_ASSERT((lexclass_count * lexstate_count) <= UINT16_MAX,
	      "premultiplied lexer classes fit in table");

#define PREMULTIPLY(class) ((class) * lexstate_count)

static const uint16_t line_classes[256] = {
	[' '] = PREMULTIPLY(lexclass_space),
	['\t'] = PREMULTIPLY(lexclass_space),
	['\n'] = PREMULTIPLY(lexclass_lf_return),
	['\r'] = PREMULTIPLY(lexclass_cr_return),
	['\0'] = PREMULTIPLY(lexclass_nul),
};

static const uint16_t command_classes[256] = {
	[' '] = PREMULTIPLY(lexclass_space),
	['\t'] = PREMULTIPLY(lexclass_space),
	['\n'] = PREMULTIPLY(lexclass_lf_skip),
	['\r'] = PREMULTIPLY(lexclass_cr_skip),
	['\0'] = PREMULTIPLY(lexclass_nul),
	['"'] = PREMULTIPLY(lexclass_qstring_quote),
	['\\'] = PREMULTIPLY(lexclass_qstring_backslash),
};

static const uint16_t dns_classes[256] = {
	[' '] = PREMULTIPLY(lexclass_space),
	['\t'] = PREMULTIPLY(lexclass_space),
	['\n'] = PREMULTIPLY(lexclass_lf_return),
	['\r'] = PREMULTIPLY(lexclass_cr_return),
	['\0'] = PREMULTIPLY(lexclass_nul),
	['"'] = PREMULTIPLY(lexclass_quote),
	['\\'] = PREMULTIPLY(lexclass_backslash),
	[';'] = PREMULTIPLY(lexclass_dns_comment),
	['('] = PREMULTIPLY(lexclass_paren),
	[')'] = PREMULTIPLY(lexclass_paren),
};

static const uint16_t dns_bundle_classes[256] = {
	[' '] = PREMULTIPLY(lexclass_space),
	['\t'] = PREMULTIPLY(lexclass_space),
	['\n'] = PREMULTIPLY(lexclass_lf_return),
	['\r'] = PREMULTIPLY(lexclass_cr_return),
	['\0'] = PREMULTIPLY(lexclass_nul),
	['"'] = PREMULTIPLY(lexclass_quote),
	['\\'] = PREMULTIPLY(lexclass_backslash),
	['('] = PREMULTIPLY(lexclass_paren),
	[')'] = PREMULTIPLY(lexclass_paren),
};

static const uint16_t config_classes[256] = {
	[' '] = PREMULTIPLY(lexclass_space),
	['\t'] = PREMULTIPLY(lexclass_space),
	['\n'] = PREMULTIPLY(lexclass_lf_skip),
	['\r'] = PREMULTIPLY(lexclass_cr_skip),
	['\0'] = PREMULTIPLY(lexclass_nul),
	['"'] = PREMULTIPLY(lexclass_quote),
	['\\'] = PREMULTIPLY(lexclass_qstring_backslash),
	['{'] = PREMULTIPLY(lexclass_special),
	['}'] = PREMULTIPLY(lexclass_special),
	[';'] = PREMULTIPLY(lexclass_special),
	['!'] = PREMULTIPLY(lexclass_special),
	['#'] = PREMULTIPLY(lexclass_shell_comment),
	['/'] = PREMULTIPLY(lexclass_slash),
	['*'] = PREMULTIPLY(lexclass_star),
};

#undef PREMULTIPLY

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
	const uint16_t *classes;
	ISC_LIST(struct inputsource) sources;
};

#define S lexstate_start
#define I lexstate_start_initialws
#define M lexstate_start_multiline
#define A lexstate_atom
#define E lexstate_atom_escaped
#define Q lexstate_qstring
#define X lexstate_qstring_escaped
#define C lexstate_qstring_needs_cooking
#define D lexstate_slash
#define L lexstate_line_comment
#define N lexstate_line_comment_multiline
#define B lexstate_block_comment
#define T lexstate_block_comment_star

static const uint8_t transitions[lexclass_count][lexstate_count] = {
	[lexclass_ordinary] = { [S] = A,
				[I] = A,
				[M] = A,
				[A] = A,
				[E] = A,
				[Q] = Q,
				[X] = C,
				[C] = C,
				[D] = lexstate_slash_done,
				[L] = L,
				[N] = N,
				[B] = B,
				[T] = B },
	[lexclass_space] = { [S] = S,
			     [I] = lexstate_initialws,
			     [M] = M,
			     [A] = lexstate_atom_done,
			     [E] = A,
			     [Q] = Q,
			     [X] = C,
			     [C] = C,
			     [D] = lexstate_slash_done,
			     [L] = L,
			     [N] = N,
			     [B] = B,
			     [T] = B },
	[lexclass_lf_return] = { [S] = lexstate_newline_return,
				 [I] = lexstate_newline_return,
				 [M] = lexstate_newline_skip,
				 [A] = lexstate_atom_done,
				 [E] = lexstate_atom_done,
				 [Q] = lexstate_qstring_newline,
				 [X] = lexstate_qstring_escaped_newline,
				 [C] = lexstate_qstring_cooked_newline,
				 [D] = lexstate_slash_done,
				 [L] = lexstate_newline_return,
				 [N] = lexstate_newline_skip,
				 [B] = lexstate_block_comment_newline,
				 [T] = lexstate_block_comment_newline },
	[lexclass_lf_skip] = { [S] = lexstate_newline_skip,
			       [I] = lexstate_newline_skip,
			       [M] = lexstate_newline_skip,
			       [A] = lexstate_atom_done,
			       [E] = lexstate_atom_done,
			       [Q] = lexstate_qstring_newline,
			       [X] = lexstate_qstring_escaped_newline,
			       [C] = lexstate_qstring_cooked_newline,
			       [D] = lexstate_slash_done,
			       [L] = lexstate_newline_skip,
			       [N] = lexstate_newline_skip,
			       [B] = lexstate_block_comment_newline,
			       [T] = lexstate_block_comment_newline },
	[lexclass_cr_return] = { [S] = lexstate_cr_return,
				 [I] = lexstate_cr_return,
				 [M] = lexstate_cr_skip,
				 [A] = lexstate_atom_done,
				 [E] = lexstate_atom_done,
				 [Q] = Q,
				 [X] = C,
				 [C] = C,
				 [D] = lexstate_slash_done,
				 [L] = L,
				 [N] = N,
				 [B] = B,
				 [T] = B },
	[lexclass_cr_skip] = { [S] = lexstate_cr_skip,
			       [I] = lexstate_cr_skip,
			       [M] = lexstate_cr_skip,
			       [A] = lexstate_atom_done,
			       [E] = lexstate_atom_done,
			       [Q] = Q,
			       [X] = C,
			       [C] = C,
			       [D] = lexstate_slash_done,
			       [L] = L,
			       [N] = N,
			       [B] = B,
			       [T] = B },
	[lexclass_nul] = { [S] = lexstate_start_nul,
			   [I] = lexstate_start_nul,
			   [M] = lexstate_start_nul,
			   [A] = lexstate_atom_done,
			   [E] = lexstate_atom_escaped_nul,
			   [Q] = lexstate_qstring_nul,
			   [X] = lexstate_qstring_escaped_nul,
			   [C] = lexstate_qstring_cooked_nul,
			   [D] = lexstate_slash_done,
			   [L] = lexstate_line_comment_nul,
			   [N] = lexstate_line_comment_nul,
			   [B] = lexstate_block_comment_nul,
			   [T] = lexstate_block_comment_star_nul },
	[lexclass_quote] = { [S] = Q,
			     [I] = Q,
			     [M] = Q,
			     [A] = lexstate_atom_done,
			     [E] = A,
			     [Q] = lexstate_qstring_done,
			     [X] = C,
			     [C] = lexstate_qstring_cooked_done,
			     [D] = lexstate_slash_done,
			     [L] = L,
			     [N] = N,
			     [B] = B,
			     [T] = B },
	[lexclass_qstring_quote] = { [S] = Q,
				     [I] = Q,
				     [M] = Q,
				     [A] = A,
				     [E] = A,
				     [Q] = lexstate_qstring_done,
				     [X] = C,
				     [C] = lexstate_qstring_cooked_done,
				     [D] = lexstate_slash_done,
				     [L] = L,
				     [N] = N,
				     [B] = B,
				     [T] = B },
	[lexclass_backslash] = { [S] = E,
				 [I] = E,
				 [M] = E,
				 [A] = E,
				 [E] = A,
				 [Q] = X,
				 [X] = C,
				 [C] = X,
				 [D] = lexstate_slash_done,
				 [L] = L,
				 [N] = N,
				 [B] = B,
				 [T] = B },
	[lexclass_qstring_backslash] = { [S] = A,
					 [I] = A,
					 [M] = A,
					 [A] = A,
					 [E] = A,
					 [Q] = X,
					 [X] = C,
					 [C] = X,
					 [D] = lexstate_slash_done,
					 [L] = L,
					 [N] = N,
					 [B] = B,
					 [T] = B },
	[lexclass_special] = { [S] = lexstate_special,
			       [I] = lexstate_special,
			       [M] = lexstate_special,
			       [A] = lexstate_atom_done,
			       [E] = A,
			       [Q] = Q,
			       [X] = C,
			       [C] = C,
			       [D] = lexstate_slash_done,
			       [L] = L,
			       [N] = N,
			       [B] = B,
			       [T] = B },
	[lexclass_dns_comment] = { [S] = L,
				   [I] = L,
				   [M] = N,
				   [A] = lexstate_atom_done,
				   [E] = A,
				   [Q] = Q,
				   [X] = C,
				   [C] = C,
				   [D] = lexstate_slash_done,
				   [L] = L,
				   [N] = N,
				   [B] = B,
				   [T] = B },
	[lexclass_shell_comment] = { [S] = L,
				     [I] = L,
				     [M] = L,
				     [A] = lexstate_atom_done,
				     [E] = lexstate_atom_done,
				     [Q] = Q,
				     [X] = C,
				     [C] = C,
				     [D] = lexstate_slash_done,
				     [L] = L,
				     [N] = N,
				     [B] = B,
				     [T] = B },
	[lexclass_slash] = { [S] = D,
			     [I] = D,
			     [M] = D,
			     [A] = lexstate_atom_done,
			     [E] = A,
			     [Q] = Q,
			     [X] = C,
			     [C] = C,
			     [D] = L,
			     [L] = L,
			     [N] = N,
			     [B] = B,
			     [T] = lexstate_comment_done },
	[lexclass_star] = { [S] = A,
			    [I] = A,
			    [M] = A,
			    [A] = A,
			    [E] = A,
			    [Q] = Q,
			    [X] = C,
			    [C] = C,
			    [D] = B,
			    [L] = L,
			    [N] = N,
			    [B] = T,
			    [T] = T },
	[lexclass_paren] = { [S] = lexstate_paren,
			     [I] = lexstate_paren,
			     [M] = lexstate_paren,
			     [A] = lexstate_atom_done,
			     [E] = A,
			     [Q] = Q,
			     [X] = C,
			     [C] = C,
			     [D] = lexstate_slash_done,
			     [L] = L,
			     [N] = N,
			     [B] = B,
			     [T] = B },
};

static const uint8_t in_token[lexstate_count] = {
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
#undef I
#undef M
#undef A
#undef E
#undef Q
#undef X
#undef C
#undef D
#undef L
#undef N
#undef B
#undef T

static inline lexstate_t
start_state(const isc_lex_t *lex) {
	if (lex->paren_count != 0) {
		return lexstate_start_multiline;
	}
	if (lex->last_was_eol && (lex->options & ISC_LEXOPT_INITIALWS) != 0) {
		return lexstate_start_initialws;
	}
	return lexstate_start;
}

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
	lex->classes = line_classes;
	ISC_LIST_INIT(lex->sources);
	lex->magic = LEX_MAGIC;

	*lexp = lex;
}

isc_result_t
isc_lex_create_dns_master(isc_mem_t *mctx, size_t initial_token_size,
			  isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_INITIALWS;
	(*lexp)->classes = dns_classes;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_config(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_QSTRINGMULTILINE;
	(*lexp)->classes = config_classes;

	return ISC_R_SUCCESS;
}

static isc_result_t
create_dns_text(isc_mem_t *mctx, size_t initial_token_size, isc_lex_t **lexp,
		bool comments) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->classes = comments ? dns_classes : dns_bundle_classes;

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
	(*lexp)->classes = command_classes;

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
	static const void *const dispatch[lexstate_last_final + 1] = {
		[lexstate_atom_done] = &&atom_done,
		[lexstate_qstring_done] = &&qstring_done,
		[lexstate_qstring_cooked_done] = &&qstring_cooked_done,
		[lexstate_initialws] = &&initialws,
		[lexstate_newline_return] = &&newline_return,
		[lexstate_newline_skip] = &&newline_skip,
		[lexstate_cr_return] = &&cr_return,
		[lexstate_cr_skip] = &&cr_skip,
		[lexstate_slash_done] = &&slash_done,
		[lexstate_comment_done] = &&comment_done,
		[lexstate_block_comment_newline] = &&block_comment_newline,
		[lexstate_line_comment_nul] = &&line_comment_nul,
		[lexstate_block_comment_nul] = &&block_comment_nul,
		[lexstate_block_comment_star_nul] = &&block_comment_star_nul,
		[lexstate_special] = &&special,
		[lexstate_paren] = &&paren,
		[lexstate_start_nul] = &&start_nul,
		[lexstate_atom_escaped_nul] = &&atom_escaped_nul,
		[lexstate_qstring_nul] = &&qstring_nul,
		[lexstate_qstring_escaped_nul] = &&qstring_escaped_nul,
		[lexstate_qstring_cooked_nul] = &&qstring_cooked_nul,
		[lexstate_qstring_newline] = &&qstring_newline,
		[lexstate_qstring_escaped_newline] = &&qstring_escaped_newline,
		[lexstate_qstring_cooked_newline] = &&qstring_cooked_newline,
	};
	inputsource *source;
	isc_buffer_t *buffer;
	const uint8_t *transition = &transitions[0][0];
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

	state = start_state(lex);
	base = buffer->base;
	p = base + buffer->current;

	for (;;) {
		do {
			unsigned int char_class = lex->classes[*p++];

			state = transition[char_class + state];
			token_length += in_token[state];
		} while (state > lexstate_last_final);
		goto *dispatch[state];

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
		state = start_state(lex);
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
		buffer->current = (unsigned int)(p - base);
		source->ignored = buffer->current - 1U;
		lex->last_was_eol = false;
		tokenp->type = isc_tokentype_initialws;
		tokenp->value.as_char = p[-1];
		result = ISC_R_SUCCESS;
		goto done;

	newline_return:
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
		state = start_state(lex);
		continue;

	cr_return:
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
		state = start_state(lex);
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
		state = start_state(lex);
		continue;
	}

	line_comment_nul:
	block_comment_nul:
	block_comment_star_nul: {
		unsigned int nul = (unsigned int)(p - base - 1);
		lexstate_t resume;

		if (state == lexstate_line_comment_nul) {
			resume = lex->paren_count != 0
					 ? lexstate_line_comment_multiline
					 : lexstate_line_comment;
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
			state = start_state(lex);
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
				state = start_state(lex);
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
