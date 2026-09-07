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

#pragma once

/*****
***** Module Info
*****/

/*! \file isc/lex.h
 * \brief The "lex" module provides a lightweight tokenizer.  It can operate
 * on files or buffers, and can handle "include".  It is designed for
 * parsing of DNS master files and the BIND configuration file, but
 * should be general enough to tokenize other things, e.g. HTTP.
 *
 * \li MP:
 *	No synchronization is provided.  Clients must ensure exclusive
 *	access.
 *
 * \li Reliability:
 *	No anticipated impact.
 *
 * \li Resources:
 *	TBS
 *
 * \li Security:
 *	No anticipated impact.
 *
 * \li Standards:
 * 	None.
 */

/***
 *** Imports
 ***/

#include <stdbool.h>
#include <stdio.h>

#include <isc/region.h>
#include <isc/types.h>

/***
 *** Types
 ***/

/*! Lex */

/* Tokens */

typedef enum {
	isc_tokentype_unknown = 0,
	isc_tokentype_string = 1,
	isc_tokentype_number = 2,
	isc_tokentype_qstring = 3,
	isc_tokentype_eol = 4,
	isc_tokentype_eof = 5,
	isc_tokentype_initialws = 6,
	isc_tokentype_special = 7,
} isc_tokentype_t;

/* No ignored input separated this token from the preceding token. */
#define ISC_LEXFLAG_ADJACENT 0x0001

typedef union {
	char	      as_char;
	unsigned long as_ulong;
	isc_region_t  as_region;
	void	     *as_pointer;
} isc_tokenvalue_t;

typedef struct isc_token {
	isc_tokentype_t	 type;
	isc_tokenvalue_t value;
	unsigned int	 flags;
} isc_token_t;

/***
 *** Functions
 ***/

isc_result_t
isc_lex_create_dns_master(isc_mem_t *mctx, size_t initial_token_size,
			  isc_lex_t **lexp);
/*%<
 * Create a lexer for DNS master-file text.  The lexical policy is fixed for
 * the lifetime of the lexer.
 */

isc_result_t
isc_lex_create_config(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp);
/*%<
 * Create a lexer for named.conf text.  The lexical policy is fixed for the
 * lifetime of the lexer.
 */

isc_result_t
isc_lex_create_dnssec(isc_mem_t *mctx, size_t initial_token_size,
		      isc_lex_t **lexp);
/*%< Create a lexer for DNSSEC key files. */

isc_result_t
isc_lex_create_dnssec_bundle(isc_mem_t *mctx, size_t initial_token_size,
			     isc_lex_t **lexp);
/*%< Create a lexer for KSR and SKR bundles. */

isc_result_t
isc_lex_create_command(isc_mem_t *mctx, size_t initial_token_size,
		       isc_lex_t **lexp);
/*%< Create a lexer for short command strings. */

isc_result_t
isc_lex_create_line(isc_mem_t *mctx, size_t initial_token_size,
		    isc_lex_t **lexp);
/*%< Create a lexer for simple line-oriented data files. */

void
isc_lex_destroy(isc_lex_t **lexp);
/*%<
 * Destroy the lexer.
 *
 * Requires:
 *\li	'*lexp' is a valid lexer.
 *
 * Ensures:
 *\li	*lexp == NULL
 */

isc_result_t
isc_lex_openfile(isc_lex_t *lex, const char *filename);
/*%<
 * Open 'filename' and make it the current input source for 'lex'.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	filename is a valid C string.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOTFOUND			File not found
 *\li	#ISC_R_NOPERM			No permission to open file
 *\li	#ISC_R_FAILURE			Couldn't open file, not sure why
 *\li	#ISC_R_UNEXPECTED
 */

void
isc_lex_openstream(isc_lex_t *lex, FILE *stream);
/*%<
 * Make 'stream' the current input source for 'lex'.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	'stream' is a valid C stream.
 */

isc_result_t
isc_lex_openbuffer(isc_lex_t *lex, isc_buffer_t *buffer);
/*%<
 * Make 'buffer' the current input source for 'lex'.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	'buffer' is a valid buffer.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 */

isc_result_t
isc_lex_close(isc_lex_t *lex);
/*%<
 * Close the most recently opened object (i.e. file or buffer).
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMORE			No more input sources
 */

isc_result_t
isc_lex_next(isc_lex_t *lex, isc_token_t *tokenp);
/*%<
 * Get the next token using the immutable policy selected when 'lex' was
 * created.  Atoms are returned as byte regions; interpreting an atom as a
 * number is the parser's responsibility.  A returned string region refers to
 * lexer-owned storage and remains valid until the next call to isc_lex_next(),
 * isc_lex_close(), or isc_lex_destroy().
 */

isc_result_t
isc_lex_getmastertoken(isc_lex_t *lex, isc_token_t *token,
		       isc_tokentype_t expect, bool eol);
/*%<
 * Get the next token from a DNS master file type stream.  This is a
 * convenience function that sets appropriate options and handles quoted
 * strings and end of line correctly for master files.  It also ungets
 * unexpected tokens.  If `eol` is set then expect end-of-line otherwise
 * eol is a error.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	'token' is a valid pointer
 *
 * Returns:
 *
 * \li	any return code from isc_lex_next().
 */

isc_result_t
isc_lex_getoctaltoken(isc_lex_t *lex, isc_token_t *token, bool eol);
/*%<
 * Get the next token from a DNS master file type stream.  This is a
 * convenience function that sets appropriate options and handles end
 * of line correctly for master files.  It also ungets unexpected tokens.
 * If `eol` is set then expect end-of-line otherwise eol is a error.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	'token' is a valid pointer
 *
 * Returns:
 *
 * \li	any return code from isc_lex_next().
 */

void
isc_lex_ungettoken(isc_lex_t *lex, isc_token_t *tokenp);
/*%<
 * Unget the current token.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	'lex' has an input source.
 *
 *\li	'tokenp' points to a valid token.
 *
 *\li	There is no ungotten token already.
 */

void
isc_lex_getlasttokentext(isc_lex_t *lex, isc_token_t *tokenp, isc_region_t *r);
/*%<
 * Returns a region containing the text of the last token returned.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 *\li	'lex' has an input source.
 *
 *\li	'tokenp' points to a valid token.
 *
 *\li	A token has been gotten and not ungotten.
 */

char *
isc_lex_getsourcename(isc_lex_t *lex);
/*%<
 * Return the input source name.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 * Returns:
 * \li	source name or NULL if no current source.
 *\li	result valid while current input source exists.
 */

unsigned long
isc_lex_getsourceline(isc_lex_t *lex);
/*%<
 * Return the input source line number.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 * Returns:
 *\li 	Current line number or 0 if no current source.
 */

isc_result_t
isc_lex_setsourcename(isc_lex_t *lex, const char *name);
/*%<
 * Assigns a new name to the input source.
 *
 * Requires:
 *
 * \li	'lex' is a valid lexer.
 *
 * Returns:
 * \li	#ISC_R_SUCCESS
 * \li	#ISC_R_NOTFOUND - there are no sources.
 */

isc_result_t
isc_lex_setsourceline(isc_lex_t *lex, unsigned long line);
/*%<
 * Assigns a new line number to the input source. This can be used
 * when parsing a buffer that's been excerpted from the middle a file,
 * allowing logged messages to display the correct line number,
 * rather than the line number within the buffer.
 *
 * Requires:
 *
 * \li	'lex' is a valid lexer.
 *
 * Returns:
 * \li	#ISC_R_SUCCESS
 * \li	#ISC_R_NOTFOUND - there are no sources.
 */

bool
isc_lex_isfile(isc_lex_t *lex);
/*%<
 * Return whether the current input source is a file.
 *
 * Requires:
 *\li	'lex' is a valid lexer.
 *
 * Returns:
 * \li	#true if the current input is a file,
 *\li	#false otherwise.
 */
