/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include <stddef.h>
#include <stdint.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/util.h>

#include "fuzz.h"

bool debug = false;

static isc_mem_t *mctx = NULL;
static isc_lex_t *lex = NULL;

int
LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED) {
	isc_mem_create("fuzz", &mctx);
	RUNTIME_CHECK(isc_lex_create_command(mctx, 1024, &lex) ==
		      ISC_R_SUCCESS);

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	isc_buffer_t buf;
	isc_result_t result;

	isc_buffer_constinit(&buf, data, size);
	isc_buffer_add(&buf, size);
	isc_buffer_setactive(&buf, size);

	CHECK(isc_lex_openbuffer(lex, &buf));

	do {
		isc_token_t token;
		result = isc_lex_next(lex, &token);
		if (result == ISC_R_SUCCESS &&
		    token.type == isc_tokentype_eof)
		{
			break;
		}
	} while (result == ISC_R_SUCCESS);

cleanup:
	return 0;
}
