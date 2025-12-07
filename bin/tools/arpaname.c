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

#include <ctype.h>
#include <stdio.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/hex.h>
#include <isc/lib.h>
#include <isc/md.h>
#include <isc/net.h>
#include <isc/utf8.h>

#include <dns/fixedname.h>
#include <dns/name.h>

#define UNUSED(x) (void)(x)

static const char *keylabel = "_openpgpkey";

/* https://www.rfc-editor.org/rfc/rfc6116.html */
static bool
is_enum(const char *str) {
	const char *i = str;
	unsigned char c;
	bool valid = false;

	if (*i != '+')
		return false;
	for (i = str + 1; *i != '\0'; i++) {
		c = *i;
		if (!((c >= '0' && c <= '9') || c == '-'))
			return false;
		valid = true;
	}
	return valid;
}

/* Basic check to test whether string looks like email address.
 *
 * OPENPGPKEY, _openpgpkey, https://www.rfc-editor.org/rfc/rfc7929.html
 * SMIMEA, _smimecert, https://www.rfc-editor.org/rfc/rfc8162.html
 */
static bool
is_email(const char *str) {
	const char *delim = strrchr(str, '@');
	unsigned i, userpart;
	dns_fixedname_t fname;
	dns_name_t *domain = NULL;
	isc_result_t result;

	if (!delim)
		return false;
	userpart = delim - str;
	if (userpart == 0)
		return false;
	if (!isc_utf8_valid((const unsigned char *)str, userpart))
		return false;
	for (i = 0; i < userpart; i++) {
		if (isspace(str[i]))
			return false;
	}

	if (strlen(delim + 1) == 0)
		return false;

	domain = dns_fixedname_initname(&fname);
	result = dns_name_fromstring(domain, delim + 1, dns_rootname, 0, NULL);
	return result == ISC_R_SUCCESS;
}

static isc_result_t
print_hashed_record(const char *email, const char *label) {
	unsigned char digest[ISC_MAX_BLOCK_SIZE];
	isc_result_t result;
	const unsigned char *user = (const unsigned char *)email;
	const char *delim = strrchr(email, '@');
	unsigned int user_len = delim - email;
	char hexbuf[ISC_MAX_BLOCK_SIZE * 2] = "";
	isc_buffer_t hex_buffer;
	isc_region_t digest_region = { digest, sizeof(digest) };

	result = isc_md(ISC_MD_SHA256, user, user_len, digest,
			&digest_region.length);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Failed digest of user: %s!\n",
			isc_result_totext(result));
		return result;
	}
	isc_buffer_init(&hex_buffer, hexbuf, sizeof(hexbuf));
	digest_region.length = 28;
	result = isc_hex_totext(&digest_region, 0, "", &hex_buffer);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Failed user conversion to hex: %s!\n",
			isc_result_totext(result));
		return result;
	}
	fprintf(stdout, "%s.%s.%s\n", hexbuf, label, delim + 1);
	return result;
}

static bool
parse_one(const char *arg) {
	unsigned char buf[16];
	int i;

	if (inet_pton(AF_INET6, arg, buf) == 1) {
		for (i = 15; i >= 0; i--) {
			fprintf(stdout, "%X.%X.", buf[i] & 0xf,
				(buf[i] >> 4) & 0xf);
		}
		fprintf(stdout, "IP6.ARPA\n");
		return true;
	}
	if (inet_pton(AF_INET, arg, buf) == 1) {
		fprintf(stdout, "%u.%u.%u.%u.IN-ADDR.ARPA\n", buf[3], buf[2],
			buf[1], buf[0]);
		return true;
	}
	if (is_enum(arg)) {
		size_t len = strlen(arg);
		for (i = len - 1; i >= 0; i--) {
			unsigned char c = arg[i];
			if (c >= '0' && c <= '9')
				fprintf(stdout, "%c.", c);
		}
		fprintf(stdout, "E164.ARPA\n");
		return true;
	}
	if (is_email(arg)) {
		return print_hashed_record(arg, keylabel) == ISC_R_SUCCESS;
	}
	return false;
}

static void
show_usage(const char *myname) {
	printf("Usage: %s [-o] [-s] <IP address/tel. number/email>\n", myname);
}

static const char *optstring = "osh";

static void
parse_args(int argc, char **argv) {
	int c;

	isc_commandline_reset = true;
	while ((c = isc_commandline_parse(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'o':
			keylabel = "_openpgpkey";
			break;
		case 's':
			keylabel = "_smimecert";
			break;
		case 'h':
		default:
			show_usage(argv[0]);
			break;
		}
	}
}

int
main(int argc, char *argv[]) {
	int i;

	UNUSED(argc);

	parse_args(argc, argv);
	for (i = isc_commandline_index; i < argc; i++) {
		if (!parse_one(argv[i]))
			return 1;
	}

	fflush(stdout);
	return ferror(stdout);
}
