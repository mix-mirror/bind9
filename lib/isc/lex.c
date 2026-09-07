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

#include <ctype.h>
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

#define LEX_REFILL_SIZE (16U * 1024U)

#define ISC_LEXOPT_EOL		     0x0001
#define ISC_LEXOPT_EOF		     0x0002
#define ISC_LEXOPT_INITIALWS	     0x0004
#define ISC_LEXOPT_NUMBER	     0x0008
#define ISC_LEXOPT_QSTRING	     0x0010
#define ISC_LEXOPT_DNSMULTILINE	     0x0020
#define ISC_LEXOPT_NOMORE	     0x0040
#define ISC_LEXOPT_CNUMBER	     0x0080
#define ISC_LEXOPT_ESCAPE	     0x0100
#define ISC_LEXOPT_QSTRINGMULTILINE  0x0200
#define ISC_LEXOPT_OCTAL	     0x0400
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
	bool comment_ok;
	bool last_was_eol;
	bool saved_last_was_eol;
	unsigned int paren_count;
	unsigned int saved_paren_count;
	isc_lexspecials_t specials;
	ISC_LIST(struct inputsource) sources;
};

static void
grow_data(isc_lex_t *lex, size_t *remainingp, char **currp, char **prevp) {
	char *tmp;

	tmp = isc_mem_get(lex->mctx, lex->max_token * 2 + 1);
	memmove(tmp, lex->data, lex->max_token + 1);
	*currp = tmp + (*currp - lex->data);
	if (*prevp != NULL) {
		*prevp = tmp + (*prevp - lex->data);
	}
	isc_mem_put(lex->mctx, lex->data, lex->max_token + 1);
	lex->data = tmp;
	*remainingp += lex->max_token;
	lex->max_token *= 2;
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
	lex->comment_ok = true;
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
	(*lexp)->options = ISC_LEXOPT_EOF | ISC_LEXOPT_NOMORE |
			   ISC_LEXOPT_QSTRING | ISC_LEXOPT_QSTRINGMULTILINE;
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
create_dns_text(isc_mem_t *mctx, size_t initial_token_size,
		isc_lex_t **lexp, unsigned int comments) {
	isc_lexspecials_t specials = { 0 };

	lex_create(mctx, initial_token_size, lexp);
	(*lexp)->options = ISC_LEXOPT_EOL | ISC_LEXOPT_DNSMULTILINE |
			   ISC_LEXOPT_ESCAPE |
			   ISC_LEXOPT_QSTRING;
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
	isc_buffer_allocate(lex->mctx, &source->pushback, LEX_REFILL_SIZE);
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
	lexstate_start,
	lexstate_crlf,
	lexstate_string,
	lexstate_number,
	lexstate_maybecomment,
	lexstate_ccomment,
	lexstate_ccommentend,
	lexstate_eatline,
	lexstate_qstring,
} lexstate;

#define IWSEOL (ISC_LEXOPT_INITIALWS | ISC_LEXOPT_EOL)

static void
pushback(inputsource *source, int c) {
	REQUIRE(source->pushback->current > 0);
	if (c == EOF) {
		return;
	}
	source->pushback->current--;
	if (c == '\n') {
		source->line--;
	}
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

	REQUIRE(isc_buffer_remaininglength(buffer) == 0U);
	REQUIRE(!source->at_eof);

	if (isc_buffer_availablelength(buffer) < LEX_REFILL_SIZE) {
		compact_to_checkpoint(source);
		RETERR(isc_buffer_reserve(buffer, LEX_REFILL_SIZE));
	}
	isc_buffer_availableregion(buffer, &available);
	INSIST(available.length >= LEX_REFILL_SIZE);

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

	return ISC_R_SUCCESS;
}

static isc_result_t
lex_gettoken(isc_lex_t *lex, unsigned int options, isc_token_t *tokenp) {
	inputsource *source;
	int c;
	bool done = false;
	bool no_comments = false;
	bool escaped = false;
	bool separated = false;
	lexstate state = lexstate_start;
	lexstate saved_state = lexstate_start;
	char *curr, *prev;
	size_t remaining;
	uint32_t as_ulong;
	unsigned int saved_options;
	isc_result_t result;

	/*
	 * Get the next token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = ISC_LIST_HEAD(lex->sources);
	REQUIRE(tokenp != NULL);
	tokenp->flags = 0;

	if (source == NULL) {
		if ((options & ISC_LEXOPT_NOMORE) != 0) {
			tokenp->type = isc_tokentype_nomore;
			return ISC_R_SUCCESS;
		}
		return ISC_R_NOMORE;
	}

	if (source->result != ISC_R_SUCCESS) {
		return source->result;
	}

	lex->saved_paren_count = lex->paren_count;
	lex->saved_last_was_eol = lex->last_was_eol;
	source->saved_line = source->line;
	source->saved_have_token = source->have_token;
	source->saved_current = source->pushback->current;
	source->ignored = source->saved_current;

	if (isc_buffer_remaininglength(source->pushback) == 0 && source->at_eof)
	{
		if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 &&
		    lex->paren_count != 0)
		{
			lex->paren_count = 0;
			return ISC_R_UNBALANCED;
		}
		if ((options & ISC_LEXOPT_EOF) != 0) {
			tokenp->type = isc_tokentype_eof;
			return ISC_R_SUCCESS;
		}
		return ISC_R_EOF;
	}

	saved_options = options;
	if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 && lex->paren_count > 0) {
		options &= ~IWSEOL;
	}

	curr = lex->data;
	*curr = '\0';

	prev = NULL;
	remaining = lex->max_token;

// #ifdef HAVE_FLOCKFILE
// 	if (source->is_file) {
// 		flockfile(source->input);
// 	}
// #endif /* ifdef HAVE_FLOCKFILE */

	do {
		if (isc_buffer_remaininglength(source->pushback) == 0U &&
		    !source->at_eof)
		{
			source->result = refill(source);
			if (source->result != ISC_R_SUCCESS) {
				result = source->result;
				goto done;
			}
		}

		if (isc_buffer_remaininglength(source->pushback) != 0U) {
			if (state == lexstate_start) {
				/* Token has not started yet. */
				source->ignored = isc_buffer_consumedlength(
					source->pushback);
			}
			c = ((unsigned char *)source->pushback->base)
				[source->pushback->current++];
		} else if (source->at_eof) {
			c = EOF;
		} else {
			continue;
		}

		if (c == '\n') {
			source->line++;
		}

		if (lex->comment_ok && !no_comments) {
			if (!escaped && c == ';' &&
			    ((lex->comments & ISC_LEXCOMMENT_DNSMASTERFILE) !=
			     0))
			{
				if (state == lexstate_start) {
					separated = true;
				}
				saved_state = state;
				state = lexstate_eatline;
				no_comments = true;
				continue;
			} else if (c == '/' &&
				   (lex->comments &
				    (ISC_LEXCOMMENT_C |
				     ISC_LEXCOMMENT_CPLUSPLUS)) != 0)
			{
				if (state == lexstate_start) {
					separated = true;
				}
				saved_state = state;
				state = lexstate_maybecomment;
				no_comments = true;
				continue;
			} else if (c == '#' && ((lex->comments &
						 ISC_LEXCOMMENT_SHELL) != 0))
			{
				if (state == lexstate_start) {
					separated = true;
				}
				saved_state = state;
				state = lexstate_eatline;
				no_comments = true;
				continue;
			}
		}

	no_read:
		/* INSIST(c == EOF || (c >= 0 && c <= 255)); */
		switch (state) {
		case lexstate_start:
			if (c == EOF) {
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
				done = true;
			} else if (c == ' ' || c == '\t') {
				if (lex->last_was_eol &&
				    (options & ISC_LEXOPT_INITIALWS) != 0)
				{
					lex->last_was_eol = false;
					tokenp->type = isc_tokentype_initialws;
					tokenp->value.as_char = c;
					done = true;
				} else {
					separated = true;
				}
			} else if (c == '\n') {
				if ((options & ISC_LEXOPT_EOL) != 0) {
					tokenp->type = isc_tokentype_eol;
					done = true;
				} else {
					separated = true;
				}
				lex->last_was_eol = true;
			} else if (c == '\r') {
				if ((options & ISC_LEXOPT_EOL) != 0) {
					state = lexstate_crlf;
				} else {
					separated = true;
				}
			} else if (c == '"' &&
				   (options & ISC_LEXOPT_QSTRING) != 0)
			{
				lex->last_was_eol = false;
				no_comments = true;
				state = lexstate_qstring;
			} else if (c == '\0') {
				lex->last_was_eol = false;
				tokenp->type = isc_tokentype_unknown;
				tokenp->value.as_textregion.base = NULL;
				tokenp->value.as_textregion.length = 0;
				done = true;
			} else if (lex->specials[c]) {
				lex->last_was_eol = false;
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
							options = saved_options;
						}
					}
					separated = true;
					continue;
				}
				tokenp->type = isc_tokentype_special;
				tokenp->value.as_char = c;
				done = true;
			} else if (isdigit((unsigned char)c) &&
				   (options & ISC_LEXOPT_NUMBER) != 0)
			{
				lex->last_was_eol = false;
				if ((options & ISC_LEXOPT_OCTAL) != 0 &&
				    (c == '8' || c == '9'))
				{
					state = lexstate_string;
				} else {
					state = lexstate_number;
				}
				goto no_read;
			} else {
				lex->last_was_eol = false;
				state = lexstate_string;
				goto no_read;
			}
			break;
		case lexstate_crlf:
			if (c != '\n') {
				pushback(source, c);
			}
			tokenp->type = isc_tokentype_eol;
			done = true;
			lex->last_was_eol = true;
			break;
		case lexstate_number:
			if (c == EOF || !isdigit((unsigned char)c)) {
				if (c == ' ' || c == '\t' || c == '\r' ||
				    c == '\n' || c == '\0' || c == EOF ||
				    lex->specials[c])
				{
					int base;
					if ((options & ISC_LEXOPT_OCTAL) != 0) {
						base = 8;
					} else if ((options &
						    ISC_LEXOPT_CNUMBER) != 0)
					{
						base = 0;
					} else {
						base = 10;
					}
					pushback(source, c);

					result = isc_parse_uint32(
						&as_ulong, lex->data, base);
					if (result == ISC_R_SUCCESS) {
						tokenp->type =
							isc_tokentype_number;
						tokenp->value.as_ulong =
							as_ulong;
					} else if (result == ISC_R_BADNUMBER) {
						isc_tokenvalue_t *v;

						tokenp->type =
							isc_tokentype_string;
						v = &(tokenp->value);
						v->as_textregion.base =
							lex->data;
						v->as_textregion.length =
							(unsigned int)(lex->max_token -
								       remaining);
					} else {
						goto done;
					}
					done = true;
					continue;
				} else if ((options & ISC_LEXOPT_CNUMBER) ==
						   0 ||
					   ((c != 'x' && c != 'X') ||
					    (curr != &lex->data[1]) ||
					    (lex->data[0] != '0')))
				{
					/* Above test supports hex numbers */
					state = lexstate_string;
				}
			} else if ((options & ISC_LEXOPT_OCTAL) != 0 &&
				   (c == '8' || c == '9'))
			{
				state = lexstate_string;
			}
			if (remaining == 0U) {
				grow_data(lex, &remaining, &curr, &prev);
			}
			INSIST(remaining > 0U);
			*curr++ = c;
			*curr = '\0';
			remaining--;
			break;
		case lexstate_string:
			/*
			 * EOF needs to be checked before lex->specials[c]
			 * as lex->specials[EOF] is not a good idea.
			 */
			if (c == '\r' || c == '\n' || c == EOF ||
			    (!escaped && (c == ' ' || c == '\t' || c == '\0' ||
					  lex->specials[c])))
			{
				pushback(source, c);
				if (source->result != ISC_R_SUCCESS) {
					result = source->result;
					goto done;
				}
				if (escaped && c == EOF) {
					result = ISC_R_UNEXPECTEDEND;
					goto done;
				}
				tokenp->type = isc_tokentype_string;
				tokenp->value.as_textregion.base = lex->data;
				tokenp->value.as_textregion.length =
					(unsigned int)(lex->max_token -
						       remaining);
				done = true;
				continue;
			}
			if ((options & ISC_LEXOPT_ESCAPE) != 0) {
				escaped = (!escaped && c == '\\') ? true
								  : false;
			}
			if (remaining == 0U) {
				grow_data(lex, &remaining, &curr, &prev);
			}
			INSIST(remaining > 0U);
			*curr++ = c;
			*curr = '\0';
			remaining--;
			break;
		case lexstate_maybecomment:
			if (c == '*' && (lex->comments & ISC_LEXCOMMENT_C) != 0)
			{
				state = lexstate_ccomment;
				continue;
			} else if (c == '/' && (lex->comments &
						ISC_LEXCOMMENT_CPLUSPLUS) != 0)
			{
				state = lexstate_eatline;
				continue;
			}
			pushback(source, c);
			c = '/';
			no_comments = false;
			state = saved_state;
			goto no_read;
		case lexstate_ccomment:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '*') {
				state = lexstate_ccommentend;
			}
			break;
		case lexstate_ccommentend:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '/') {
				/*
				 * C-style comments become a single space.
				 * We do this to ensure that a comment will
				 * act as a delimiter for strings and
				 * numbers.
				 */
				c = ' ';
				no_comments = false;
				state = saved_state;
				goto no_read;
			} else if (c != '*') {
				state = lexstate_ccomment;
			}
			break;
		case lexstate_eatline:
			if ((c == '\n') || (c == EOF)) {
				no_comments = false;
				state = saved_state;
				goto no_read;
			}
			break;
		case lexstate_qstring:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '"') {
				if (escaped) {
					escaped = false;
					/*
					 * Overwrite the preceding backslash.
					 */
					INSIST(prev != NULL);
					*prev = '"';
				} else {
					tokenp->type = isc_tokentype_qstring;
					tokenp->value.as_textregion.base =
						lex->data;
					tokenp->value.as_textregion.length =
						(unsigned int)(lex->max_token -
							       remaining);
					no_comments = false;
					done = true;
				}
			} else {
				if (c == '\n' && !escaped &&
				    (options & ISC_LEXOPT_QSTRINGMULTILINE) ==
					    0)
				{
					pushback(source, c);
					result = ISC_R_UNBALANCEDQUOTES;
					goto done;
				}
				if (c == '\\' && !escaped) {
					escaped = true;
				} else {
					escaped = false;
				}
				if (remaining == 0U) {
					grow_data(lex, &remaining, &curr,
						  &prev);
				}
				INSIST(remaining > 0U);
				prev = curr;
				*curr++ = c;
				*curr = '\0';
				remaining--;
			}
			break;
		default:
			FATAL_ERROR("Unexpected state %d", state);
		}
	} while (!done);

	result = ISC_R_SUCCESS;
done:
	if (result == ISC_R_SUCCESS) {
		if (source->have_token && !separated) {
			tokenp->flags |= ISC_LEXFLAG_ADJACENT;
		}
		source->have_token = true;
	}
// #ifdef HAVE_FLOCKFILE
// 	if (source->is_file) {
// 		funlockfile(source->input);
// 	}
// #endif /* ifdef HAVE_FLOCKFILE */
	return result;
}

isc_result_t
isc_lex_next(isc_lex_t *lex, isc_token_t *tokenp) {
	REQUIRE(VALID_LEX(lex));

	return lex_gettoken(lex, lex->options, tokenp);
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

		result = isc_parse_uint32_region(
			&number, &token->value.as_textregion, 10);
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

		result = isc_parse_uint32_region(
			&number, &token->value.as_textregion, 8);
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
