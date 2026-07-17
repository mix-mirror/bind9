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

#ifdef ENABLE_TRACING

#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
/*
 * The header containing our LTTNG_UST_TRACEPOINT_EVENTs.
 */
#define LTTNG_UST_TRACEPOINT_DEFINE
#include <ns/tracing.h>

#endif /* ENABLE_TRACING */
