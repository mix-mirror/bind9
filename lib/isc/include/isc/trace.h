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

#define ISC_TRACE_FLARG                                                       \
	, const char *func ISC_ATTR_UNUSED, const char *file ISC_ATTR_UNUSED, \
		unsigned int line ISC_ATTR_UNUSED
#define ISC_TRACE_FLARG_PASS , func, file, line
#define ISC_TRACE_FILELINE   , __func__, __FILE__, __LINE__
