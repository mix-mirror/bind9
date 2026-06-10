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

/*! \file isc/os.h */
#include <sys/stat.h>

#include <isc/types.h>
#include <isc/urcu.h>

/*
 * Reuse the L1 cacheline size from Userspace RCU.
 */
#define ISC_OS_CACHELINE_SIZE CAA_CACHE_LINE_SIZE

unsigned int
isc_os_ncpus(void);
/*%<
 * Return the number of CPUs available on the system, or 1 if this cannot
 * be determined.
 */

mode_t
isc_os_umask(void);
/*%<
 * Return umask of the current process as initialized at the program start
 */

void
isc_os_kernel(char **name, int *major, int *minor, int *patch);
/*%<
 * Fill the running kernel version into major, minor and patch.
 * If any of these are not available then -1 is returned.
 */
