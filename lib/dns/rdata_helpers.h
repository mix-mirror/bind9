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

/*
 * Shared helper functions and macros for rdata type implementations.
 *
 * These are defined in rdata.c and used by the individual type .c files.
 * This header provides declarations for standalone compilation of type
 * files (when they are no longer #included via code.h).
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/ascii.h>
#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/hex.h>
#include <isc/lex.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/parseint.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/utf8.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/cert.h>
#include <dns/compress.h>
#include <dns/dsdigest.h>
#include <dns/enumtype.h>
#include <dns/fixedname.h>
#include <dns/keyflags.h>
#include <dns/keyvalues.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/secalg.h>
#include <dns/secproto.h>
#include <dns/time.h>
#include <dns/ttl.h>
#include <dns/types.h>

#include "rdata_p.h"

/*
 * Macros used by rdata type implementations.
 */

#define ARGS_FROMTEXT                                           \
	int rdclass, dns_rdatatype_t type, isc_lex_t *lexer,    \
		const dns_name_t *origin, unsigned int options, \
		isc_buffer_t *target, dns_rdatacallbacks_t *callbacks

#define CALL_FROMTEXT rdclass, type, lexer, origin, options, target, callbacks

#define ARGS_TOTEXT \
	dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, isc_buffer_t *target

#define CALL_TOTEXT rdata, tctx, target

#define ARGS_FROMWIRE                                            \
	int rdclass, dns_rdatatype_t type, isc_buffer_t *source, \
		dns_decompress_t dctx, isc_buffer_t *target

#define CALL_FROMWIRE rdclass, type, source, dctx, target

#define ARGS_TOWIRE \
	dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target

#define CALL_TOWIRE rdata, cctx, target

#define ARGS_COMPARE const dns_rdata_t *rdata1, const dns_rdata_t *rdata2

#define CALL_COMPARE rdata1, rdata2

#define ARGS_FROMSTRUCT \
	int rdclass, dns_rdatatype_t type, void *source, isc_buffer_t *target

#define CALL_FROMSTRUCT rdclass, type, source, target

#define ARGS_TOSTRUCT const dns_rdata_t *rdata, void *target, isc_mem_t *mctx

#define CALL_TOSTRUCT rdata, target, mctx

#define ARGS_FREESTRUCT void *source

#define CALL_FREESTRUCT source

#define ARGS_ADDLDATA                                \
	dns_rdata_t *rdata, const dns_name_t *owner, \
		dns_additionaldatafunc_t add, void *arg

#define CALL_ADDLDATA rdata, owner, add, arg

#define ARGS_DIGEST dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg

#define CALL_DIGEST rdata, digest, arg

#define ARGS_CHECKOWNER                                   \
	const dns_name_t *name, dns_rdataclass_t rdclass, \
		dns_rdatatype_t type, bool wildcard

#define CALL_CHECKOWNER name, rdclass, type, wildcard

#define ARGS_CHECKNAMES \
	dns_rdata_t *rdata, const dns_name_t *owner, dns_name_t *bad

#define CALL_CHECKNAMES rdata, owner, bad

#define RETTOK(x)                                          \
	do {                                               \
		isc_result_t _r = (x);                     \
		if (_r != ISC_R_SUCCESS) {                 \
			isc_lex_ungettoken(lexer, &token); \
			return (_r);                       \
		}                                          \
	} while (0)

#define CHECKTOK(op)                                       \
	do {                                               \
		result = (op);                             \
		if (result != ISC_R_SUCCESS) {             \
			isc_lex_ungettoken(lexer, &token); \
			goto cleanup;                      \
		}                                          \
	} while (0)

#define DNS_AS_STR(t) ((t).value.as_textregion.base)

/*
 * Helper function declarations.
 *
 * When type files are compiled as part of rdata.c (via code.h), these
 * are defined as static functions in rdata.c.  When compiled standalone,
 * these declarations allow linking against rdata.c's non-static exports.
 */

isc_result_t
str_totext(const char *source, isc_buffer_t *target);

isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

bool
name_prefix(dns_name_t *name, const dns_name_t *origin, dns_name_t *target);

unsigned int
name_length(const dns_name_t *name);

isc_result_t
name_tobuffer(const dns_name_t *name, isc_buffer_t *target);

isc_result_t
inet_totext(int af, uint32_t flags, isc_region_t *src, isc_buffer_t *target);

bool
buffer_empty(isc_buffer_t *source);

void
buffer_fromregion(isc_buffer_t *buffer, isc_region_t *region);

isc_result_t
uint32_tobuffer(uint32_t value, isc_buffer_t *target);

isc_result_t
uint16_tobuffer(uint32_t value, isc_buffer_t *target);

isc_result_t
uint8_tobuffer(uint32_t value, isc_buffer_t *target);

uint32_t
uint32_fromregion(isc_region_t *region);

uint16_t
uint16_fromregion(isc_region_t *region);

uint8_t
uint8_fromregion(isc_region_t *region);

uint8_t
uint8_consume_fromregion(isc_region_t *region);

uint16_t
uint16_consume_fromregion(isc_region_t *region);

int
hexvalue(char value);

int
decvalue(char value);

isc_result_t
txt_totext(isc_region_t *source, bool quote, isc_buffer_t *target);

isc_result_t
txt_fromtext(isc_textregion_t *source, isc_buffer_t *target);

isc_result_t
txt_fromwire(isc_buffer_t *source, isc_buffer_t *target);

isc_result_t
commatxt_fromtext(isc_textregion_t *source, bool comma, isc_buffer_t *target);

isc_result_t
commatxt_totext(isc_region_t *source, bool quote, bool comma,
		isc_buffer_t *target);

isc_result_t
multitxt_totext(isc_region_t *source, isc_buffer_t *target);

isc_result_t
multitxt_fromtext(isc_textregion_t *source, isc_buffer_t *target);

void
name_duporclone(const dns_name_t *source, isc_mem_t *mctx, dns_name_t *target);

void *
mem_maybedup(isc_mem_t *mctx, void *source, size_t length);

int
locator_pton(const char *src, unsigned char *dst);

isc_result_t
typemap_fromtext(isc_lex_t *lexer, isc_buffer_t *target, bool allow_empty);

isc_result_t
typemap_totext(isc_region_t *sr, dns_rdata_textctx_t *tctx,
	       isc_buffer_t *target);

isc_result_t
typemap_test(isc_region_t *sr, bool allow_empty);

isc_result_t
check_private(isc_buffer_t *source, dns_secalg_t alg);

bool
validate_dohpath(isc_region_t *region);

void
fromtext_error(void (*callback)(dns_rdatacallbacks_t *, const char *, ...),
	       dns_rdatacallbacks_t *callbacks, const char *name,
	       unsigned long line, isc_token_t *token, isc_result_t result);

void
fromtext_warneof(isc_lex_t *lexer, dns_rdatacallbacks_t *callbacks);

void
warn_badname(const dns_name_t *name, isc_lex_t *lexer,
	     dns_rdatacallbacks_t *callbacks);

void
warn_badmx(isc_token_t *token, isc_lex_t *lexer,
	   dns_rdatacallbacks_t *callbacks);

isc_result_t
unknown_totext(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	       isc_buffer_t *target);

void
default_fromtext_callback(dns_rdatacallbacks_t *callbacks, const char *, ...)
	ISC_FORMAT_PRINTF(2, 3);

extern unsigned char gc_msdcs_data[];
extern dns_name_t const gc_msdcs;

/*% INT16 Size */
#define NS_INT16SZ 2
/*% IPv6 Address Size */
#define NS_LOCATORSZ 8

/* SVCB parameter keys */
#define SVCB_ALPN_KEY	 1
#define SVCB_DOHPATH_KEY 7

/*
 * Shared type-family implementations.
 * Defined in the "primary" type file, used by related types.
 */

/* KEY family (key_25.c) — used by dnskey, cdnskey, rkey */
isc_result_t generic_fromtext_key(ARGS_FROMTEXT);
isc_result_t generic_totext_key(ARGS_TOTEXT);
isc_result_t generic_fromwire_key(ARGS_FROMWIRE);
isc_result_t generic_fromstruct_key(ARGS_FROMSTRUCT);
isc_result_t generic_tostruct_key(ARGS_TOSTRUCT);
void generic_freestruct_key(ARGS_FREESTRUCT);
bool
generic_key_nokey(dns_rdatatype_t type, unsigned int flags);

/* TXT family (txt_16.c) — used by spf, avc, ninfo, wallet, resinfo */
isc_result_t generic_fromtext_txt(ARGS_FROMTEXT);
isc_result_t generic_totext_txt(ARGS_TOTEXT);
isc_result_t generic_fromwire_txt(ARGS_FROMWIRE);
isc_result_t generic_fromstruct_txt(ARGS_FROMSTRUCT);
isc_result_t generic_tostruct_txt(ARGS_TOSTRUCT);
void generic_freestruct_txt(ARGS_FREESTRUCT);
isc_result_t
generic_txt_first(dns_rdata_txt_t *txt);
isc_result_t
generic_txt_next(dns_rdata_txt_t *txt);
isc_result_t
generic_txt_current(dns_rdata_txt_t *txt, dns_rdata_txt_string_t *string);

/* DS family (ds_43.c) — used by cds, dlv, ta */
isc_result_t generic_fromtext_ds(ARGS_FROMTEXT);
isc_result_t generic_totext_ds(ARGS_TOTEXT);
isc_result_t generic_fromwire_ds(ARGS_FROMWIRE);
isc_result_t generic_fromstruct_ds(ARGS_FROMSTRUCT);
isc_result_t generic_tostruct_ds(ARGS_TOSTRUCT);

/* TLSA family (tlsa_52.c) — used by smimea */
isc_result_t generic_fromtext_tlsa(ARGS_FROMTEXT);
isc_result_t generic_totext_tlsa(ARGS_TOTEXT);
isc_result_t generic_fromwire_tlsa(ARGS_FROMWIRE);
isc_result_t generic_fromstruct_tlsa(ARGS_FROMSTRUCT);
isc_result_t generic_tostruct_tlsa(ARGS_TOSTRUCT);
void generic_freestruct_tlsa(ARGS_FREESTRUCT);

/* SVCB family (svcb_64.c) — used by https */
isc_result_t generic_fromtext_in_svcb(ARGS_FROMTEXT);
isc_result_t generic_totext_in_svcb(ARGS_TOTEXT);
isc_result_t generic_fromwire_in_svcb(ARGS_FROMWIRE);
isc_result_t generic_towire_in_svcb(ARGS_TOWIRE);
isc_result_t generic_fromstruct_in_svcb(ARGS_FROMSTRUCT);
isc_result_t generic_tostruct_in_svcb(ARGS_TOSTRUCT);
void generic_freestruct_in_svcb(ARGS_FREESTRUCT);
isc_result_t generic_additionaldata_in_svcb(ARGS_ADDLDATA);
bool generic_checknames_in_svcb(ARGS_CHECKNAMES);
isc_result_t
generic_rdata_in_svcb_first(dns_rdata_in_svcb_t *);
isc_result_t
generic_rdata_in_svcb_next(dns_rdata_in_svcb_t *);
void
generic_rdata_in_svcb_current(dns_rdata_in_svcb_t *, isc_region_t *);
