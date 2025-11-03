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

#include <isc/lib.h>
#include <isc/mem.h>

#include <isccfg/lib.h>

#include "parser_p.h"

static isc_refcount_t isccfg__lib_references = 0;

static void
isccfginitialize(void) {
	if (isc_refcount_increment0(&isccfg__lib_references) > 0) {
		return;
	}

	isccfg__parser_initialize();
}

static void
isccfgshutdown(void) {
	if (isc_refcount_decrement(&isccfg__lib_references) > 1) {
		return;
	}

	isccfg__parser_shutdown();
}

void
isccfg_lib_initialize(void) {
	isc_lib_initialize();
	isccfginitialize();
}

void
isccfg_lib_shutdown(void) {
	isccfgshutdown();
	isc_lib_shutdown();
}
