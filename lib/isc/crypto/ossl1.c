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

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <isc/crypto.h>
#include <isc/mem.h>
#include <isc/tls.h>
#include <isc/util.h>

#ifndef LIBRESSL_VERSION_NUMBER
static isc_mem_t *isc__crypto_mctx = NULL;
#endif

EVP_MD *isc__crypto_md5 = NULL;
EVP_MD *isc__crypto_sha1 = NULL;
EVP_MD *isc__crypto_sha224 = NULL;
EVP_MD *isc__crypto_sha256 = NULL;
EVP_MD *isc__crypto_sha384 = NULL;
EVP_MD *isc__crypto_sha512 = NULL;

#ifndef LIBRESSL_VERSION_NUMBER

#if ISC_MEM_TRACKLINES
/*
 * We use the internal isc__mem API here, so we can pass the file and line
 * arguments passed from OpenSSL >= 1.1.0 to our memory functions for better
 * tracking of the OpenSSL allocations.  Without this, we would always just see
 * isc__crypto_{malloc,realloc,free} in the tracking output, but with this in
 * place we get to see the places in the OpenSSL code where the allocations
 * happen.
 */

static void *
isc__crypto_malloc_ex(size_t size, const char *file, int line) {
	return isc__mem_allocate(isc__crypto_mctx, size, 0, __func__, file,
				 (unsigned int)line);
}

static void *
isc__crypto_realloc_ex(void *ptr, size_t size, const char *file, int line) {
	return isc__mem_reallocate(isc__crypto_mctx, ptr, size, 0, __func__,
				   file, (unsigned int)line);
}

static void
isc__crypto_free_ex(void *ptr, const char *file, int line) {
	if (ptr == NULL) {
		return;
	}
	if (isc__crypto_mctx != NULL) {
		isc__mem_free(isc__crypto_mctx, ptr, 0, __func__, file,
			      (unsigned int)line);
	}
}

#else /* ISC_MEM_TRACKLINES */

static void *
isc__crypto_malloc_ex(size_t size, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	return isc_mem_allocate(isc__crypto_mctx, size);
}

static void *
isc__crypto_realloc_ex(void *ptr, size_t size, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	return isc_mem_reallocate(isc__crypto_mctx, ptr, size);
}

static void
isc__crypto_free_ex(void *ptr, const char *file, int line) {
	UNUSED(file);
	UNUSED(line);
	if (ptr == NULL) {
		return;
	}
	if (isc__crypto_mctx != NULL) {
		isc__mem_free(isc__crypto_mctx, ptr, 0);
	}
}

#endif /* ISC_MEM_TRACKLINES */

#endif /* !LIBRESSL_VERSION_NUMBER */

#define md_register_algorithm(alg)                        \
	do {                                              \
		isc__crypto_##alg = UNCONST(EVP_##alg()); \
		if (isc__crypto_##alg == NULL) {          \
			ERR_clear_error();                \
		}                                         \
	} while (0)

static isc_result_t
register_algorithms(void) {
	if (!isc_crypto_fips_mode()) {
		md_register_algorithm(md5);
	}

	md_register_algorithm(sha1);
	md_register_algorithm(sha224);
	md_register_algorithm(sha256);
	md_register_algorithm(sha384);
	md_register_algorithm(sha512);

	return ISC_R_SUCCESS;
}

#ifdef HAVE_FIPS_MODE
bool
isc_crypto_fips_mode(void) {
	return FIPS_mode() != 0;
}

isc_result_t
isc_crypto_fips_enable(void) {
	if (isc_crypto_fips_mode()) {
		return ISC_R_SUCCESS;
	}

	if (FIPS_mode_set(1) == 0) {
		return isc_tlserr2result(ISC_LOGCATEGORY_GENERAL,
					 ISC_LOGMODULE_CRYPTO, "FIPS_mode_set",
					 ISC_R_CRYPTOFAILURE);
	}

	register_algorithms();

	return ISC_R_SUCCESS;
}
#else
bool
isc_crypto_fips_mode(void) {
	return false;
}

isc_result_t
isc_crypto_fips_enable(void) {
	return ISC_R_NOTIMPLEMENTED;
}
#endif /* HAVE_FIPS_MODE */

#ifndef LIBRESSL_VERSION_NUMBER
void
isc__crypto_setdestroycheck(bool check) {
	isc_mem_setdestroycheck(isc__crypto_mctx, check);
}
#else
void
isc__crypto_setdestroycheck(bool check) {
	(void)check;
}
#endif /* !LIBRESSL_VERSION_NUMBER */

void
isc__crypto_initialize(void) {
#ifndef LIBRESSL_VERSION_NUMBER
	isc_mem_create("OpenSSL", &isc__crypto_mctx);
	isc_mem_setdebugging(isc__crypto_mctx, 0);
	isc_mem_setdestroycheck(isc__crypto_mctx, false);
	/*
	 * CRYPTO_set_mem_(_ex)_functions() returns 1 on success or 0 on
	 * failure, which means OpenSSL already allocated some memory.  There's
	 * nothing we can do about it.
	 */
	(void)CRYPTO_set_mem_functions(isc__crypto_malloc_ex,
				       isc__crypto_realloc_ex,
				       isc__crypto_free_ex);
#endif /* LIBRESSL_VERSION_NUMBER */

	/*
	 * The OPENSSL_INIT_NO_ATEXIT flag was introduces with 3.0.0. Otherwise
	 * it can only be found in the form of no-op such as with LibreSSL.
	 *
	 * https://github.com/openssl/openssl/commit/8f6a5c56c17aa89b80fef73875beec53aef1f2c8
	 * https://github.com/libressl/openbsd/commit/da7b0f4bfa71c9b8be4c449be0da83036941e3a2
	 */
	RUNTIME_CHECK(OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 1);

#ifdef ENABLE_FIPS_MODE
	if (isc_crypto_fips_enable() != ISC_R_SUCCESS) {
		ERR_clear_error();
		FATAL_ERROR("Failed to toggle FIPS mode but is "
			    "required for this build");
	}
#endif

	register_algorithms();

	/* Protect ourselves against unseeded PRNG */
	if (RAND_status() != 1) {
		FATAL_ERROR("OpenSSL pseudorandom number generator "
			    "cannot be initialized (see the `PRNG not "
			    "seeded' message in the OpenSSL FAQ)");
	}
}

void
isc__crypto_shutdown(void) {
	OPENSSL_cleanup();

#ifndef LIBRESSL_VERSION_NUMBER
	isc_mem_detach(&isc__crypto_mctx);
#endif /* LIBRESSL_VERSION_NUMBER */
}
