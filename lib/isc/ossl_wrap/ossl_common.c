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

#include <openssl/err.h>

#include <isc/ossl_wrap.h>
#include <isc/util.h>

#include "../openssl_shim.h"

isc_result_t
isc_ossl_wrap_toresult(isc_result_t fallback) {
	isc_result_t result = fallback;
	unsigned long err = ERR_peek_error();
#ifdef ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED
	int lib = ERR_GET_LIB(err);
#endif /* ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED */
	int reason = ERR_GET_REASON(err);

	switch (reason) {
	/*
	 * ERR_* errors are globally unique; others
	 * are unique per sublibrary
	 */
	case ERR_R_MALLOC_FAILURE:
		result = ISC_R_NOMEMORY;
		break;
	default:
#ifdef ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED
		if (lib == ERR_R_ECDSA_LIB &&
		    reason == ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
		{
			result = ISC_R_NOENTROPY;
			break;
		}
#endif /* ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED */
		break;
	}

	return result;
}

isc_result_t
isc__ossl_wrap_logged_toresult(isc_logcategory_t category,
			       isc_logmodule_t module, const char *funcname,
			       isc_result_t fallback, const char *file,
			       int line) {
	isc_result_t result = isc_ossl_wrap_toresult(fallback);

	/*
	 * This is an exception - normally, we don't allow this, but the
	 * compatibility shims in dst_openssl.h needs a call that just
	 * translates the error code and don't do any logging.
	 */
	if (category == ISC_LOGCATEGORY_INVALID) {
		goto done;
	}

	isc_log_write(category, module, ISC_LOG_WARNING,
		      "%s (%s:%d) failed (%s)", funcname, file, line,
		      isc_result_totext(result));

	if (result == ISC_R_NOMEMORY) {
		goto done;
	}

	for (;;) {
		const char *func, *data;
		int flags;
		unsigned long err = ERR_get_error_all(&file, &line, &func,
						      &data, &flags);
		if (err == 0U) {
			break;
		}

		char buf[256];
		ERR_error_string_n(err, buf, sizeof(buf));

		isc_log_write(category, module, ISC_LOG_INFO, "%s:%s:%d:%s",
			      buf, file, line,
			      ((flags & ERR_TXT_STRING) != 0) ? data : "");
	}

done:
	ERR_clear_error();
	return result;
}
