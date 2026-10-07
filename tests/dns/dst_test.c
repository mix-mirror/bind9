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
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * As a workaround, include an OpenSSL header file before including cmocka.h,
 * because OpenSSL 3.1.0 uses __attribute__(malloc), conflicting with a
 * redefined malloc in cmocka.h.
 */
#include <openssl/err.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/crypto.h>
#include <isc/file.h>
#include <isc/hex.h>
#include <isc/lex.h>
#include <isc/lib.h>
#include <isc/result.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/lib.h>

#include <dst/dst.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <tests/dns.h>

#define VARGC(...) (sizeof((unsigned char[]){ __VA_ARGS__ }))
#define FROMDATA(secalg, dstalg, ...) \
	{ { __VA_ARGS__ }, VARGC(__VA_ARGS__), secalg, dstalg }

ISC_RUN_TEST_IMPL(algorithm_fromdata) {
	struct {
		unsigned char data[512];
		size_t len;
		dns_secalg_t secalg;
		dst_algorithm_t dstalg;
	} fromdata[] = {
		/* An unsupported private dns algorithm */
		FROMDATA(DNS_KEYALG_PRIVATEDNS, 0, 0x04, 't', 'e', 's', 't',
			 0x00),
#ifdef TEST_PRIVATEDNS
		FROMDATA(DNS_KEYALG_PRIVATEDNS, DST_ALG_RSASHA256PRIVATEDNS,
			 0x09, 'r', 's', 'a', 's', 'h', 'a', '2', '5', '6',
			 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'o',
			 'r', 'g', 0x00),
		FROMDATA(DNS_KEYALG_PRIVATEDNS, DST_ALG_RSASHA512PRIVATEDNS,
			 0x09, 'r', 's', 'a', 's', 'h', 'a', '5', '1', '2',
			 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'o',
			 'r', 'g', 0x00),
#endif

		/* length byte + 1.2.840.113549.1.1.11 BER encoded RFC 4055 */
		FROMDATA(DNS_KEYALG_PRIVATEOID, DST_ALG_RSASHA256PRIVATEOID,
			 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
			 0x01, 0x01, 0x0b),

		/* length byte + 1.2.840.113549.1.1.13 BER encoded RFC 4055 */
		FROMDATA(DNS_KEYALG_PRIVATEOID, DST_ALG_RSASHA512PRIVATEOID,
			 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
			 0x01, 0x01, 0x0d),

		/* An unsupported private oid algorithm */
		FROMDATA(DNS_KEYALG_PRIVATEOID, 0, 0x0b, 0x06, 0x09, 0x2a, 0x86,
			 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c)
	};

	for (size_t i = 0; i < ARRAY_SIZE(fromdata); i++) {
		dst_algorithm_t alg;
		alg = dst_algorithm_fromdata(fromdata[i].secalg,
					     fromdata[i].data, fromdata[i].len);
		assert_int_equal(alg, fromdata[i].dstalg);
		if (alg != 0) {
			assert_int_equal(dst_algorithm_tosecalg(alg),
					 fromdata[i].secalg);
		}
	}
}

/* Read sig in file at path to buf. Check signature ineffability */
static isc_result_t
sig_fromfile(const char *path, isc_buffer_t *buf) {
	isc_result_t result;
	size_t rval, len;
	FILE *fp = NULL;
	unsigned char val;
	char *p, *data;
	off_t size;

	result = isc_stdio_open(path, "rb", &fp);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_file_getsizefd(fileno(fp), &size);
	assert_int_equal(result, ISC_R_SUCCESS);

	data = isc_mem_get(isc_g_mctx, size + 1);
	assert_non_null(data);

	len = (size_t)size;
	p = data;
	while (len != 0U) {
		result = isc_stdio_read(p, 1, len, fp, &rval);
		assert_int_equal(result, ISC_R_SUCCESS);
		len -= rval;
		p += rval;
	}
	isc_stdio_close(fp);

	p = data;
	len = size;
	while (len > 0U) {
		if ((*p == '\r') || (*p == '\n')) {
			++p;
			--len;
			continue;
		} else if (len < 2U) {
			goto err;
		}
		if (('0' <= *p) && (*p <= '9')) {
			val = *p - '0';
		} else if (('A' <= *p) && (*p <= 'F')) {
			val = *p - 'A' + 10;
		} else {
			result = ISC_R_BADHEX;
			goto err;
		}
		++p;
		val <<= 4;
		--len;
		if (('0' <= *p) && (*p <= '9')) {
			val |= (*p - '0');
		} else if (('A' <= *p) && (*p <= 'F')) {
			val |= (*p - 'A' + 10);
		} else {
			result = ISC_R_BADHEX;
			goto err;
		}
		++p;
		--len;
		isc_buffer_putuint8(buf, val);
	}

	result = ISC_R_SUCCESS;

err:
	isc_mem_put(isc_g_mctx, data, size + 1);
	return result;
}

static void
check_sig(const char *datapath, const char *sigpath, const char *keyname,
	  dns_keytag_t id, dns_secalg_t alg, int type, bool expect) {
	isc_result_t result;
	size_t rval, len;
	FILE *fp;
	dst_key_t *key = NULL;
	unsigned char sig[512];
	unsigned char *p;
	unsigned char *data;
	off_t size;
	isc_buffer_t b;
	isc_buffer_t databuf, sigbuf;
	isc_region_t datareg, sigreg;
	dns_fixedname_t fname;
	dns_name_t *name;
	dst_context_t *ctx = NULL;

	/*
	 * Read data from file in a form usable by dst_verify.
	 */
	result = isc_stdio_open(datapath, "rb", &fp);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_file_getsizefd(fileno(fp), &size);
	assert_int_equal(result, ISC_R_SUCCESS);

	data = isc_mem_get(isc_g_mctx, size + 1);
	assert_non_null(data);

	p = data;
	len = (size_t)size;
	do {
		result = isc_stdio_read(p, 1, len, fp, &rval);
		assert_int_equal(result, ISC_R_SUCCESS);
		len -= rval;
		p += rval;
	} while (len);
	isc_stdio_close(fp);

	/*
	 * Read key from file in a form usable by dst_verify.
	 */
	name = dns_fixedname_initname(&fname);
	isc_buffer_constinit(&b, keyname, strlen(keyname));
	isc_buffer_add(&b, strlen(keyname));
	result = dns_name_fromtext(name, &b, dns_rootname, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_fromfile(name, id, alg, type,
				  TESTS_DIR "/testdata/dst", isc_g_mctx, &key);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_init(&databuf, data, (unsigned int)size);
	isc_buffer_add(&databuf, (unsigned int)size);
	isc_buffer_usedregion(&databuf, &datareg);

	memset(sig, 0, sizeof(sig));
	isc_buffer_init(&sigbuf, sig, sizeof(sig));

	/*
	 * Read precomputed signature from file in a form usable by dst_verify.
	 */
	result = sig_fromfile(sigpath, &sigbuf);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Verify that the key signed the data.
	 */
	isc_buffer_remainingregion(&sigbuf, &sigreg);

	result = dst_context_create(key, isc_g_mctx, DNS_LOGCATEGORY_GENERAL,
				    false, &ctx);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dst_context_adddata(ctx, &datareg);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_context_verify(ctx, &sigreg);

	/*
	 * Compute the expected signature and emit it
	 * so the precomputed signature can be updated.
	 * This should only be done if the covered data
	 * is updated.
	 */
	if (expect && result != ISC_R_SUCCESS) {
		isc_result_t result2;

		dst_context_destroy(&ctx);
		result2 = dst_context_create(
			key, isc_g_mctx, DNS_LOGCATEGORY_GENERAL, false, &ctx);
		assert_int_equal(result2, ISC_R_SUCCESS);

		result2 = dst_context_adddata(ctx, &datareg);
		assert_int_equal(result2, ISC_R_SUCCESS);

		char sigbuf2[4096];
		isc_buffer_t sigb;
		isc_buffer_init(&sigb, sigbuf2, sizeof(sigbuf2));

		result2 = dst_context_sign(ctx, &sigb);
		assert_int_equal(result2, ISC_R_SUCCESS);

		isc_region_t r;
		isc_buffer_usedregion(&sigb, &r);

		char hexbuf[4096] = { 0 };
		isc_buffer_t hb;
		isc_buffer_init(&hb, hexbuf, sizeof(hexbuf));

		isc_hex_totext(&r, 0, "", &hb);

		fprintf(stderr, "# %s:\n# %s\n", sigpath, hexbuf);
	}

	isc_mem_put(isc_g_mctx, data, size + 1);
	dst_context_destroy(&ctx);
	dst_key_free(&key);

	assert_true((expect && (result == ISC_R_SUCCESS)) ||
		    (!expect && (result != ISC_R_SUCCESS)));

	return;
}

ISC_RUN_TEST_IMPL(sig_test) {
	struct {
		const char *datapath;
		const char *sigpath;
		const char *keyname;
		dns_keytag_t keyid;
		dns_secalg_t alg;
		bool expect;
	} testcases[] = {
		{ TESTS_DIR "/testdata/dst/test1.data",
		  TESTS_DIR "/testdata/dst/test1.ecdsa256sig", "test.", 49130,
		  DST_ALG_ECDSA256, true },
		{ TESTS_DIR "/testdata/dst/test1.data",
		  TESTS_DIR "/testdata/dst/test1.rsasha256sig", "test.", 11349,
		  DST_ALG_RSASHA256, true },
		{ /* wrong sig */
		  TESTS_DIR "/testdata/dst/test1.data",
		  TESTS_DIR "/testdata/dst/test1.ecdsa256sig", "test.", 11349,
		  DST_ALG_RSASHA256, false },
		{ /* wrong data */
		  TESTS_DIR "/testdata/dst/test2.data",
		  TESTS_DIR "/testdata/dst/test1.ecdsa256sig", "test.", 49130,
		  DST_ALG_ECDSA256, false },
	};
	unsigned int i;

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		if (!dst_algorithm_supported(testcases[i].alg)) {
			continue;
		}

		check_sig(testcases[i].datapath, testcases[i].sigpath,
			  testcases[i].keyname, testcases[i].keyid,
			  testcases[i].alg, DST_TYPE_PRIVATE | DST_TYPE_PUBLIC,
			  testcases[i].expect);
	}
}

static void
check_cmp(const char *key1_name, dns_keytag_t key1_id, const char *key2_name,
	  dns_keytag_t key2_id, dns_secalg_t alg, int type, bool expect) {
	isc_result_t result;
	dst_key_t *key1 = NULL;
	dst_key_t *key2 = NULL;
	isc_buffer_t b1;
	isc_buffer_t b2;
	dns_fixedname_t fname1;
	dns_fixedname_t fname2;
	dns_name_t *name1;
	dns_name_t *name2;

	/*
	 * Read key1 from the file.
	 */
	name1 = dns_fixedname_initname(&fname1);
	isc_buffer_constinit(&b1, key1_name, strlen(key1_name));
	isc_buffer_add(&b1, strlen(key1_name));
	result = dns_name_fromtext(name1, &b1, dns_rootname, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_fromfile(name1, key1_id, alg, type,
				  TESTS_DIR "/comparekeys", isc_g_mctx, &key1);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Read key2 from the file.
	 */
	name2 = dns_fixedname_initname(&fname2);
	isc_buffer_constinit(&b2, key2_name, strlen(key2_name));
	isc_buffer_add(&b2, strlen(key2_name));
	result = dns_name_fromtext(name2, &b2, dns_rootname, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_fromfile(name2, key2_id, alg, type,
				  TESTS_DIR "/comparekeys", isc_g_mctx, &key2);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Compare the keys (for public-only keys).
	 */
	if ((type & DST_TYPE_PRIVATE) == 0) {
		assert_true(dst_key_pubcompare(key1, key2, false) == expect);
	}

	/*
	 * Compare the keys (for both public-only keys and keypairs).
	 */
	assert_true(dst_key_compare(key1, key2) == expect);

	/*
	 * Free the keys
	 */
	dst_key_free(&key2);
	dst_key_free(&key1);

	return;
}

ISC_RUN_TEST_IMPL(cmp_test) {
	struct {
		const char *key1_name;
		dns_keytag_t key1_id;
		const char *key2_name;
		dns_keytag_t key2_id;
		dns_secalg_t alg;
		int type;
		bool expect;
	} testcases[] = {
		/* RSA Keypair: self */
		{ "example.", 53461, "example.", 53461, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, true },

		/* RSA Keypair: different key */
		{ "example.", 53461, "example2.", 37993, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, false },

		/* RSA Keypair: different PublicExponent (e) */
		{ "example.", 53461, "example-e.", 53973, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, false },

		/* RSA Keypair: different Modulus (n) */
		{ "example.", 53461, "example-n.", 37464, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, false },

		/* RSA Public Key: self */
		{ "example.", 53461, "example.", 53461, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC, true },

		/* RSA Public Key: different key */
		{ "example.", 53461, "example2.", 37993, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC, false },

		/* RSA Public Key: different PublicExponent (e) */
		{ "example.", 53461, "example-e.", 53973, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC, false },

		/* RSA Public Key: different Modulus (n) */
		{ "example.", 53461, "example-n.", 37464, DST_ALG_RSASHA256,
		  DST_TYPE_PUBLIC, false },

		/* ECDSA Keypair: self */
		{ "example.", 19786, "example.", 19786, DST_ALG_ECDSA256,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, true },

		/* ECDSA Keypair: different key */
		{ "example.", 19786, "example2.", 16384, DST_ALG_ECDSA256,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, false },

		/* ECDSA Public Key: self */
		{ "example.", 19786, "example.", 19786, DST_ALG_ECDSA256,
		  DST_TYPE_PUBLIC, true },

		/* ECDSA Public Key: different key */
		{ "example.", 19786, "example2.", 16384, DST_ALG_ECDSA256,
		  DST_TYPE_PUBLIC, false },

		/* EdDSA Keypair: self */
		{ "example.", 63663, "example.", 63663, DST_ALG_ED25519,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, true },

		/* EdDSA Keypair: different key */
		{ "example.", 63663, "example2.", 37529, DST_ALG_ED25519,
		  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, false },

		/* EdDSA Public Key: self */
		{ "example.", 63663, "example.", 63663, DST_ALG_ED25519,
		  DST_TYPE_PUBLIC, true },

		/* EdDSA Public Key: different key */
		{ "example.", 63663, "example2.", 37529, DST_ALG_ED25519,
		  DST_TYPE_PUBLIC, false },
	};
	unsigned int i;

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		if (!dst_algorithm_supported(testcases[i].alg)) {
			continue;
		}

		check_cmp(testcases[i].key1_name, testcases[i].key1_id,
			  testcases[i].key2_name, testcases[i].key2_id,
			  testcases[i].alg, testcases[i].type,
			  testcases[i].expect);
	}
}

ISC_RUN_TEST_IMPL(ecdsa_determinism_test) {
	isc_result_t result;
	isc_buffer_t *sigbuf1 = NULL, *sigbuf2 = NULL;
	isc_buffer_t databuf, keybuf;
	isc_region_t datareg;
	dns_fixedname_t fname;
	dns_name_t *name = NULL;
	dst_key_t *key = NULL;
	dst_context_t *ctx = NULL;
	unsigned int siglen;

	const char *data = "these are some bytes to sign";

	isc_buffer_constinit(&databuf, data, strlen(data));
	isc_buffer_add(&databuf, strlen(data));
	isc_buffer_region(&databuf, &datareg);

	name = dns_fixedname_initname(&fname);
	isc_buffer_constinit(&keybuf, "example.", strlen("example."));
	isc_buffer_add(&keybuf, strlen("example."));
	result = dns_name_fromtext(name, &keybuf, dns_rootname, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_fromfile(name, 19786, DST_ALG_ECDSA256,
				  DST_TYPE_PUBLIC | DST_TYPE_PRIVATE,
				  TESTS_DIR "/comparekeys", isc_g_mctx, &key);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_sigsize(key, &siglen);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_allocate(isc_g_mctx, &sigbuf1, siglen);
	result = dst_context_create(key, isc_g_mctx, DNS_LOGCATEGORY_GENERAL,
				    true, &ctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_context_sign(ctx, sigbuf1);
	assert_int_equal(result, ISC_R_SUCCESS);
	dst_context_destroy(&ctx);

	isc_buffer_allocate(isc_g_mctx, &sigbuf2, siglen);
	result = dst_context_create(key, isc_g_mctx, DNS_LOGCATEGORY_GENERAL,
				    true, &ctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_context_sign(ctx, sigbuf2);
	assert_int_equal(result, ISC_R_SUCCESS);
	dst_context_destroy(&ctx);

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
	if (isc_crypto_fips_mode()) {
		assert_memory_not_equal(sigbuf1->base, sigbuf2->base, siglen);
	} else {
		assert_memory_equal(sigbuf1->base, sigbuf2->base, siglen);
	}
#else
	assert_memory_not_equal(sigbuf1->base, sigbuf2->base, siglen);
#endif

	isc_buffer_free(&sigbuf1);
	isc_buffer_free(&sigbuf2);

	dst_key_free(&key);
}

/* All private-file metadata must survive an RSA key round trip. */
ISC_RUN_TEST_IMPL(private_metadata) {
	const int timetags[] = {
		DST_TIME_CREATED,   DST_TIME_PUBLISH,	  DST_TIME_ACTIVATE,
		DST_TIME_REVOKE,    DST_TIME_INACTIVE,	  DST_TIME_DELETE,
		DST_TIME_DSPUBLISH, DST_TIME_SYNCPUBLISH, DST_TIME_SYNCDELETE,
	};
	const int numerictags[] = {
		DST_NUM_PREDECESSOR,
		DST_NUM_SUCCESSOR,
		DST_NUM_MAXTTL,
		DST_NUM_ROLLPERIOD,
	};
	const isc_stdtime_t base = 1700000000;
	const int type = DST_TYPE_PUBLIC | DST_TYPE_PRIVATE;
	char directory[] = BUILDDIR "/private_metadata.XXXXXX";
	char filename[1024];
	isc_buffer_t buffer;
	isc_result_t result;
	dst_key_t *key = NULL, *copy = NULL, *invalid = NULL;

	/* Fill all private metadata */
	result = dst_key_fromnamedfile("Ktest.+008+11349",
				       TESTS_DIR "/testdata/dst", type,
				       isc_g_mctx, &key);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < ARRAY_SIZE(timetags); i++) {
		dst_key_settime(key, timetags[i], base + i);
	}
	for (size_t i = 0; i < ARRAY_SIZE(numerictags); i++) {
		dst_key_setnum(key, numerictags[i], 100 + i);
	}

	/* All private metadata must be read correctly */
	assert_non_null(mkdtemp(directory));
	result = dst_key_tofile(key, type, directory);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dst_key_fromnamedfile("Ktest.+008+11349", directory, type,
				       isc_g_mctx, &copy);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(dst_key_compare(key, copy));

	for (size_t i = 0; i < ARRAY_SIZE(timetags); i++) {
		isc_stdtime_t when;

		result = dst_key_gettime(copy, timetags[i], &when);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(when, base + i);
	}
	for (size_t i = 0; i < ARRAY_SIZE(numerictags); i++) {
		uint32_t value;

		result = dst_key_getnum(copy, numerictags[i], &value);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(value, 100 + i);
	}

	/* Make the private key invalid */
	isc_buffer_init(&buffer, filename, sizeof(filename));
	result = dst_key_buildfilename(key, DST_TYPE_PRIVATE, directory,
				       &buffer);
	assert_int_equal(result, ISC_R_SUCCESS);
	FILE *fp = fopen(filename, "a");
	fprintf(fp, "Predecessor: 888\n");
	fprintf(fp, "Successor: 999\n");
	fprintf(fp, "Private-key-format: v1.3\n");
	fprintf(fp, "Algorithm: 8 (RSASHA256)\n");
	fprintf(fp, "PublicExponent: AQAB\n");
	fclose(fp);

	result = dst_key_fromnamedfile("Ktest.+008+11349", directory, type,
				       isc_g_mctx, &invalid);
	assert_int_equal(result, DST_R_INVALIDPRIVATEKEY);

	/* Clean up files */
	isc_buffer_clear(&buffer);
	result = dst_key_buildfilename(key, DST_TYPE_PUBLIC, directory,
				       &buffer);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(unlink(filename), 0);

	isc_buffer_clear(&buffer);
	result = dst_key_buildfilename(key, DST_TYPE_PRIVATE, directory,
				       &buffer);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(unlink(filename), 0);
	assert_int_equal(rmdir(directory), 0);

	dst_key_free(&copy);
	dst_key_free(&key);
}

/* Metadata and ignored future fields must not leave gaps in key data. */
ISC_RUN_TEST_IMPL(private_metadata_order) {
	const char *fields[] = {
		"Predecessor: 123\nKey: AQID\nBits: AAA=\n",
		"Key: AQID\nPredecessor: 123\nBits: AAA=\n",
		"Future: ignored\nKey: AQID\nPredecessor: 123\n"
		"Future: ignored\nBits: AAA=\n",
	};
	unsigned char secret[] = { 1, 2, 3 };

	for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
		char text[512];
		isc_buffer_t buffer;
		isc_lex_t *lex = NULL;
		dst_key_t *key = NULL;
		dst_private_t priv;
		isc_result_t result;
		uint32_t predecessor;

		isc_buffer_init(&buffer, secret, sizeof(secret));
		isc_buffer_add(&buffer, sizeof(secret));
		result = dst_key_frombuffer(dns_rootname, DST_ALG_HMACSHA256, 0,
					    DNS_KEYPROTO_DNSSEC,
					    dns_rdataclass_in, &buffer,
					    isc_g_mctx, &key);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_buffer_init(&buffer, text, sizeof(text));
		result = isc_buffer_printf(
			&buffer,
			"Private-key-format: v%d.%d\nAlgorithm: %u\n%s",
			DST_MAJOR_VERSION, DST_MINOR_VERSION + (i == 2),
			DST_ALG_HMACSHA256, fields[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
		isc_lex_create(isc_g_mctx, sizeof(text), &lex);
		result = isc_lex_openbuffer(lex, &buffer);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dst__privstruct_parse(key, DST_ALG_HMACSHA256, lex,
					       isc_g_mctx, &priv);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(priv.nelements, 2);
		assert_int_equal(priv.elements[0].tag, TAG_HMACSHA256_KEY);
		assert_int_equal(priv.elements[0].length, sizeof(secret));
		assert_memory_equal(priv.elements[0].data, secret,
				    sizeof(secret));
		assert_int_equal(priv.elements[1].tag, TAG_HMACSHA256_BITS);
		assert_int_equal(priv.elements[1].length, 2);
		assert_memory_equal(priv.elements[1].data, "\0\0", 2);
		result = dst_key_getnum(key, DST_NUM_PREDECESSOR, &predecessor);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(predecessor, 123);

		dst__privstruct_free(&priv, isc_g_mctx);
		isc_lex_destroy(&lex);
		dst_key_free(&key);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(algorithm_fromdata)
ISC_TEST_ENTRY(sig_test)
ISC_TEST_ENTRY(cmp_test)
ISC_TEST_ENTRY(ecdsa_determinism_test)
ISC_TEST_ENTRY(private_metadata)
ISC_TEST_ENTRY(private_metadata_order)
ISC_TEST_LIST_END

ISC_TEST_MAIN
