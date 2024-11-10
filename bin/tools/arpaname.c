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

#include <stdio.h>

#include <isc/lib.h>
#include <isc/net.h>

#define UNUSED(x) (void)(x)

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

int
main(int argc, char *argv[]) {
	unsigned char buf[16];
	int i;

	UNUSED(argc);

	while (argv[1]) {
		if (inet_pton(AF_INET6, argv[1], buf) == 1) {
			for (i = 15; i >= 0; i--) {
				fprintf(stdout, "%X.%X.", buf[i] & 0xf,
					(buf[i] >> 4) & 0xf);
			}
			fprintf(stdout, "IP6.ARPA\n");
			argv++;
			continue;
		}
		if (inet_pton(AF_INET, argv[1], buf) == 1) {
			fprintf(stdout, "%u.%u.%u.%u.IN-ADDR.ARPA\n", buf[3],
				buf[2], buf[1], buf[0]);
			argv++;
			continue;
		}
		if (is_enum(argv[1])) {
			size_t len = strlen(argv[1]);
			for (i = len - 1; i >= 0; i--) {
				unsigned char c = argv[1][i];
				if (c >= '0' && c <= '9')
					fprintf(stdout, "%c.", c);
			}
			fprintf(stdout, "E164.ARPA\n");
			argv++;
			continue;
		}
		return 1;
	}
	fflush(stdout);
	return ferror(stdout);
}
