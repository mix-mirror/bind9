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

#define ISC_LEXOPT_EOL		     0x0001
#define ISC_LEXOPT_EOF		     0x0002
#define ISC_LEXOPT_INITIALWS	     0x0004
#define ISC_LEXOPT_QSTRING	     0x0010
#define ISC_LEXOPT_DNSMULTILINE	     0x0020
#define ISC_LEXOPT_ESCAPE	     0x0100
#define ISC_LEXOPT_QSTRINGMULTILINE  0x0200
#define ISC_LEXCOMMENT_C	     0x01
#define ISC_LEXCOMMENT_CPLUSPLUS     0x02
#define ISC_LEXCOMMENT_SHELL	     0x04
#define ISC_LEXCOMMENT_DNSMASTERFILE 0x08

typedef char isc_lexspecials_t[256];

struct isc_lex {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	size_t max_token;
	char *data;
	unsigned int comments;
	unsigned int options;
	bool last_was_eol;
	bool saved_last_was_eol;
	unsigned int paren_count;
	unsigned int saved_paren_count;
	isc_lexspecials_t specials;
	ISC_LIST(struct inputsource) sources;
};

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
	lex->comments = 0;
	lex->options = 0;
	lex->last_was_eol = true;
	lex->paren_count = 0;
	lex->saved_paren_count = 0;
	memset(lex->specials, 0, 256);
	ISC_LIST_INIT(lex->sources);
	lex->magic = LEX_MAGIC;

	*lexp = lex;
}

isc_result_t
isc_lex_create_dns_master(isc_mem_t *mctx, size_t initial_token_size,
			  isc_lex_t **lexp) {
	isc_lexspecials_t specials = { 0 };

	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			   ISC_LEXOPT_INITIALWS | ISC_LEXOPT_DNSMULTILINE |
			   ISC_LEXOPT_ESCAPE | ISC_LEXOPT_QSTRING;
	(*lexp)->comments = ISC_LEXCOMMENT_DNSMASTERFILE;
	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	memmove((*lexp)->specials, specials, sizeof(specials));

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_config(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp) {
	isc_lexspecials_t specials = { 0 };

	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_QSTRING |
			   ISC_LEXOPT_QSTRINGMULTILINE;
	(*lexp)->comments = ISC_LEXCOMMENT_C | ISC_LEXCOMMENT_CPLUSPLUS |
			    ISC_LEXCOMMENT_SHELL;
	specials['{'] = 1;
	specials['}'] = 1;
	specials[';'] = 1;
	specials['/'] = 1;
	specials['"'] = 1;
	specials['!'] = 1;
	memmove((*lexp)->specials, specials, sizeof(specials));

	return ISC_R_SUCCESS;
}

static isc_result_t
create_dns_text(isc_mem_t *mctx, size_t initial_token_size, isc_lex_t **lexp,
		unsigned int comments) {
	isc_lexspecials_t specials = { 0 };

	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOL | ISC_LEXOPT_DNSMULTILINE |
			   ISC_LEXOPT_ESCAPE | ISC_LEXOPT_QSTRING;
	(*lexp)->comments = comments;
	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	memmove((*lexp)->specials, specials, sizeof(specials));

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_dnssec(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp) {
	return create_dns_text(mctx, initial_token_size, lexp,
			       ISC_LEXCOMMENT_DNSMASTERFILE);
}

isc_result_t
isc_lex_create_dnssec_bundle(isc_mem_t *mctx, size_t initial_token_size,
			     isc_lex_t **lexp) {
	return create_dns_text(mctx, initial_token_size, lexp, 0);
}

isc_result_t
isc_lex_create_command(isc_mem_t *mctx, size_t initial_token_size,
		       isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_QSTRING;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_create_line(isc_mem_t *mctx, size_t initial_token_size,
		    isc_lex_t **lexp) {
	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;

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

typedef enum {
	comment_none,
	comment_skipped,
	comment_unterminated,
	comment_refill_error,
} comment_result_t;

typedef enum {
	lexstate_start,
	lexstate_atom,
	lexstate_atom_escaped,
	lexstate_qstring,
	lexstate_qstring_escaped,
	lexstate_qstring_needs_cooking,
} lexstate_t;

#define IWSEOL (ISC_LEXOPT_INITIALWS | ISC_LEXOPT_EOL)

static void
finish_atom(isc_lex_t *lex, inputsource *source, isc_token_t *tokenp) {
	isc_buffer_t *buffer = source->pushback;
	size_t length = buffer->current - source->ignored;

	ensure_data(lex, length);
	memmove(lex->data, (unsigned char *)buffer->base + source->ignored,
		length);
	lex->data[length] = '\0';
	tokenp->type = isc_tokentype_string;
	tokenp->value.as_textregion.base = lex->data;
	tokenp->value.as_textregion.length = (unsigned int)length;
}

static void
finish_qstring(isc_lex_t *lex, inputsource *source, isc_token_t *tokenp) {
	isc_buffer_t *buffer = source->pushback;
	unsigned char *raw;
	size_t raw_length;

	INSIST(buffer->current >= source->ignored + 2U);
	raw = (unsigned char *)buffer->base + source->ignored + 1U;
	raw_length = buffer->current - source->ignored - 2U;
	ensure_data(lex, raw_length);
	memmove(lex->data, raw, raw_length);
	lex->data[raw_length] = '\0';
	tokenp->type = isc_tokentype_qstring;
	tokenp->value.as_textregion.base = lex->data;
	tokenp->value.as_textregion.length = (unsigned int)raw_length;
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

	*dst = '\0';
	tokenp->type = isc_tokentype_qstring;
	tokenp->value.as_textregion.base = lex->data;
	tokenp->value.as_textregion.length = (unsigned int)(dst - lex->data);
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

static inline isc_result_t
prepare(inputsource *source) {
	while (isc_buffer_remaininglength(source->pushback) <= 1U &&
	       !source->at_eof)
	{
		source->result = refill(source);
		if (source->result != ISC_R_SUCCESS) {
			return source->result;
		}
	}

	return ISC_R_SUCCESS;
}

static comment_result_t
skip_comment_chunk(isc_lex_t *lex, inputsource *source) {
	isc_buffer_t *buffer = source->pushback;
	unsigned char *p;
	bool block;

	p = (unsigned char *)buffer->base + buffer->current;
	if (p[0] == ';' && (lex->comments & ISC_LEXCOMMENT_DNSMASTERFILE) != 0)
	{
		buffer->current++;
		block = false;
	} else if (p[0] == '#' && (lex->comments & ISC_LEXCOMMENT_SHELL) != 0) {
		buffer->current++;
		block = false;
	} else if (p[0] == '/' && p[1] == '*' &&
		   (lex->comments & ISC_LEXCOMMENT_C) != 0)
	{
		buffer->current += 2;
		block = true;
	} else if (p[0] == '/' && p[1] == '/' &&
		   (lex->comments & ISC_LEXCOMMENT_CPLUSPLUS) != 0)
	{
		buffer->current += 2;
		block = false;
	} else {
		return comment_none;
	}

	for (;;) {
		if (isc_buffer_remaininglength(buffer) <= 1U && !source->at_eof)
		{
			source->result = refill(source);
			if (source->result != ISC_R_SUCCESS) {
				return comment_refill_error;
			}
		}

		p = (unsigned char *)buffer->base + buffer->current;
		if (buffer->current == buffer->used) {
			return block ? comment_unterminated : comment_skipped;
		}
		if (!block && p[0] == '\n') {
			return comment_skipped;
		}
		if (block && p[0] == '*' && p[1] == '/') {
			buffer->current += 2;
			return comment_skipped;
		}
		buffer->current++;
		if (p[0] == '\n') {
			source->line++;
		}
	}
}

static isc_result_t
lex_gettoken(isc_lex_t *lex, isc_token_t *tokenp) {
	inputsource *source;
	isc_buffer_t *buffer;
	unsigned char *p;
	int c;
	bool separated = false;
	unsigned int options;
	isc_result_t result;
	comment_result_t comment;
	lexstate_t state = lexstate_start;

	/*
	 * Get the next token.
	 */

	REQUIRE(VALID_LEX(lex));
	options = lex->options;
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

	if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 && lex->paren_count > 0) {
		options &= ~IWSEOL;
	}

	for (;;) {
		result = prepare(source);
		if (result != ISC_R_SUCCESS) {
			goto done;
		}

		if (state == lexstate_start) {
			/* Token text begins after leading whitespace and
			 * comments. */
			source->ignored = buffer->current;
		}
		p = (unsigned char *)buffer->base + buffer->current;
		if (buffer->current == buffer->used) {
			switch (state) {
			case lexstate_start:
				lex->last_was_eol = false;
				if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 &&
				    lex->paren_count != 0)
				{
					lex->paren_count = 0;
					result = ISC_R_UNBALANCED;
					goto done;
				}
				if ((options & ISC_LEXOPT_EOF) == 0) {
					result = ISC_R_EOF;
					goto done;
				}
				tokenp->type = isc_tokentype_eof;
				result = ISC_R_SUCCESS;
				goto done;
			case lexstate_atom:
				finish_atom(lex, source, tokenp);
				result = ISC_R_SUCCESS;
				goto done;
			case lexstate_atom_escaped:
			case lexstate_qstring:
			case lexstate_qstring_escaped:
			case lexstate_qstring_needs_cooking:
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
		}

		c = p[0];
		switch (state) {
		case lexstate_start:
			comment = skip_comment_chunk(lex, source);
			if (comment == comment_refill_error) {
				result = source->result;
				goto done;
			}
			if (comment == comment_unterminated) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (comment == comment_skipped) {
				separated = true;
				continue;
			}

			if (c == ' ' || c == '\t') {
				buffer->current++;
				if (lex->last_was_eol &&
				    (options & ISC_LEXOPT_INITIALWS) != 0)
				{
					lex->last_was_eol = false;
					tokenp->type = isc_tokentype_initialws;
					tokenp->value.as_char = c;
					result = ISC_R_SUCCESS;
					goto done;
				}
				separated = true;
				continue;
			}

			if (c == '\n' || c == '\r') {
				bool crlf = c == '\r' && p[1] == '\n';

				buffer->current += crlf ? 2 : 1;
				if (c == '\n' || crlf) {
					source->line++;
				}
				lex->last_was_eol = true;
				if ((options & ISC_LEXOPT_EOL) != 0) {
					tokenp->type = isc_tokentype_eol;
					result = ISC_R_SUCCESS;
					goto done;
				}
				separated = true;
				continue;
			}

			if (c == '"' && (options & ISC_LEXOPT_QSTRING) != 0) {
				lex->last_was_eol = false;
				buffer->current++;
				state = lexstate_qstring;
				continue;
			}

			if (c == '\0') {
				lex->last_was_eol = false;
				buffer->current++;
				tokenp->type = isc_tokentype_unknown;
				tokenp->value.as_textregion.base = NULL;
				tokenp->value.as_textregion.length = 0;
				result = ISC_R_SUCCESS;
				goto done;
			}

			if (lex->specials[c]) {
				lex->last_was_eol = false;
				buffer->current++;
				if ((c == '(' || c == ')') &&
				    (options & ISC_LEXOPT_DNSMULTILINE) != 0)
				{
					if (c == '(') {
						if (lex->paren_count == 0) {
							options &= ~IWSEOL;
						}
						lex->paren_count++;
					} else {
						if (lex->paren_count == 0) {
							result =
								ISC_R_UNBALANCED;
							goto done;
						}
						lex->paren_count--;
						if (lex->paren_count == 0) {
							options = lex->options;
						}
					}
					separated = true;
					continue;
				}
				tokenp->type = isc_tokentype_special;
				tokenp->value.as_char = c;
				result = ISC_R_SUCCESS;
				goto done;
			}

			lex->last_was_eol = false;
			state = lexstate_atom;
			continue;

		case lexstate_atom:
			if (c == '\r' || c == '\n' || c == ' ' || c == '\t' ||
			    c == '\0' || lex->specials[c] ||
			    (c == ';' && (lex->comments &
					  ISC_LEXCOMMENT_DNSMASTERFILE) != 0) ||
			    (c == '#' &&
			     (lex->comments & ISC_LEXCOMMENT_SHELL) != 0))
			{
				finish_atom(lex, source, tokenp);
				result = ISC_R_SUCCESS;
				goto done;
			}
			buffer->current++;
			if ((options & ISC_LEXOPT_ESCAPE) != 0 && c == '\\') {
				state = lexstate_atom_escaped;
			}
			continue;

		case lexstate_atom_escaped:
			if (c == '\r' || c == '\n' ||
			    (c == '#' &&
			     (lex->comments & ISC_LEXCOMMENT_SHELL) != 0))
			{
				finish_atom(lex, source, tokenp);
				result = ISC_R_SUCCESS;
				goto done;
			}
			buffer->current++;
			state = lexstate_atom;
			continue;

		case lexstate_qstring:
			if (c == '"') {
				buffer->current++;
				finish_qstring(lex, source, tokenp);
				result = ISC_R_SUCCESS;
				goto done;
			}
			if (c == '\n' &&
			    (options & ISC_LEXOPT_QSTRINGMULTILINE) == 0)
			{
				result = ISC_R_UNBALANCEDQUOTES;
				goto done;
			}
			buffer->current++;
			if (c == '\n') {
				source->line++;
			}
			if (c == '\\') {
				state = lexstate_qstring_escaped;
			}
			continue;

		case lexstate_qstring_escaped:
			buffer->current++;
			state = lexstate_qstring_needs_cooking;
			if (c == '\n') {
				source->line++;
			}
			continue;

		case lexstate_qstring_needs_cooking:
			if (c == '"') {
				buffer->current++;
				finish_qstring_cooked(lex, source, tokenp);
				result = ISC_R_SUCCESS;
				goto done;
			}
			if (c == '\n' &&
			    (options & ISC_LEXOPT_QSTRINGMULTILINE) == 0)
			{
				result = ISC_R_UNBALANCEDQUOTES;
				goto done;
			}
			buffer->current++;
			if (c == '\n') {
				source->line++;
			}
			if (c == '\\') {
				state = lexstate_qstring_escaped;
			}
			continue;
		}
	}

done:
	if (result == ISC_R_SUCCESS) {
		if (source->have_token && !separated) {
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
