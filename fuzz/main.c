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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <isc/lib.h>

#include <dns/lib.h>

#include "fuzz.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#include <dirent.h>

/* Returns 1 if the input was fed to the target, 0 otherwise. */
static int
test_one_file(const char *filename) {
	int fd;
	struct stat st;
	char *data;
	ssize_t n;
	int tested = 0;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", filename,
			strerror(errno));
		return 0;
	}

	if (fstat(fd, &st) != 0) {
		fprintf(stderr, "Failed to stat %s: %s\n", filename,
			strerror(errno));
		goto closefd;
	}

	data = malloc(st.st_size);
	n = read(fd, data, st.st_size);
	if (n == st.st_size) {
		printf("testing %zd bytes from %s\n", n, filename);
		fflush(stdout);
		LLVMFuzzerTestOneInput((const uint8_t *)data, n);
		fflush(stderr);
		tested = 1;
	} else {
		if (n < 0) {
			fprintf(stderr,
				"Failed to read %zd bytes from %s: %s\n",
				(ssize_t)st.st_size, filename, strerror(errno));
		} else {
			fprintf(stderr,
				"Failed to read %zd bytes from %s, got %zd\n",
				(ssize_t)st.st_size, filename, n);
		}
	}
	free(data);
closefd:
	close(fd);
	return tested;
}

/* Returns the number of inputs that were fed to the target. */
static size_t
test_all_from(const char *dirname) {
	DIR *dirp;
	struct dirent *dp;
	size_t tested = 0;

	dirp = opendir(dirname);
	if (dirp == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n", dirname,
			strerror(errno));
		return 0;
	}

	while ((dp = readdir(dirp)) != NULL) {
		char filename[strlen(dirname) + strlen(dp->d_name) + 2];

		if (dp->d_name[0] == '.') {
			continue;
		}
		snprintf(filename, sizeof(filename), "%s/%s", dirname,
			 dp->d_name);
		tested += test_one_file(filename);
	}

	closedir(dirp);
	return tested;
}

int
main(int argc, char **argv) {
	int ret;
	char corpusdir[PATH_MAX];
	const char *target = strrchr(argv[0], '/');

	ret = LLVMFuzzerInitialize(&argc, &argv);
	if (ret != 0) {
		fprintf(stderr, "LLVMFuzzerInitialize failure: %d\n", ret);
		return 1;
	}

	if (argv[1] != NULL && strcmp(argv[1], "-d") == 0) {
		debug = true;
		argv++;
		argc--;
	}

	if (argv[1] != NULL) {
		size_t tested = 0;
		while (argv[1] != NULL) {
			tested += test_one_file(argv[1]);
			argv++;
			argc--;
		}
		POST(argc);
		if (tested == 0) {
			fprintf(stderr, "no test cases could be read\n");
			return 1;
		}
		return 0;
	}

	target = (target != NULL) ? target + 1 : argv[0];
	/* The binaries are named fuzz_<name>, the corpora are <name>.in. */
	if (strncmp(target, "fuzz_", 5) == 0) {
		target += 5;
	}

	snprintf(corpusdir, sizeof(corpusdir), FUZZDIR "/%s.in", target);

	/*
	 * Fail instead of silently passing if the corpus directory is missing
	 * or empty, so that a naming mismatch cannot turn the regression test
	 * into a no-op.
	 */
	if (test_all_from(corpusdir) == 0) {
		fprintf(stderr, "no test cases found in %s\n", corpusdir);
		return 1;
	}

	return 0;
}

#elif __AFL_COMPILER

int
main(int argc, char **argv) {
	int ret;
	size_t n;
	unsigned char buf[64 * 1024];

	ret = LLVMFuzzerInitialize(&argc, &argv);
	if (ret != 0) {
		fprintf(stderr, "LLVMFuzzerInitialize failure: %d\n", ret);
		return 1;
	}

#ifdef __AFL_LOOP
	while (__AFL_LOOP(10000)) { /* only works with afl-clang-fast */
#else  /* ifdef __AFL_LOOP */
	{
#endif /* ifdef __AFL_LOOP */
		n = fread(buf, 1, sizeof(buf), stdin);
		if (ferror(stdin) != 0) {
			fprintf(stderr, "Failed to read from stdin: %s\n",
				strerror(errno));
			return 1;
		}

		LLVMFuzzerTestOneInput(buf, n);
	}

	return 0;
}

#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
