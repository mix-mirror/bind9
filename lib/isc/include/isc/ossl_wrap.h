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

#include <isc/log.h>
#include <isc/types.h>

#define isc_ossl_wrap_logged_toresult(category, module, funcname, fallback)  \
	isc__ossl_wrap_logged_toresult(category, module, funcname, fallback, \
				       __FILE__, __LINE__)

isc_result_t
isc_ossl_wrap_toresult(isc_result_t fallback);

isc_result_t
isc__ossl_wrap_logged_toresult(isc_logcategory_t category,
			       isc_logmodule_t module, const char *funcname,
			       isc_result_t fallback, const char *file,
			       int line);
