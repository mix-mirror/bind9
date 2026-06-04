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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <isc/dir.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dst/dst.h>

/*
 * Self-test for the fuzzers.  When built with -Dfuzzing-canary, every target
 * carries a deliberately planted bug: an input starting with the four magic
 * bytes aborts.  The fuzz-canary CI job (util/fuzz-afl.sh with
 * FUZZ_EXPECT_CRASH=1) feeds each target a seed containing the magic and fails
 * if any target does NOT crash - proving, per target, that the binary builds
 * with instrumentation, runs under AFL, reaches LLVMFuzzerTestOneInput, and
 * that crashes are detected.  Never enabled in normal builds.
 */
#ifdef FUZZING_CANARY
#define FUZZ_CANARY(data, size)                                            \
	do {                                                               \
		if ((size) >= 4 && (data)[0] == 'F' && (data)[1] == 'U' && \
		    (data)[2] == 'Z' && (data)[3] == 'Z')                  \
		{                                                          \
			abort();                                           \
		}                                                          \
	} while (0)
#else
#define FUZZ_CANARY(data, size) \
	do {                    \
	} while (0)
#endif

extern bool debug;

int
LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
