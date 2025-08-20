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

/*****
***** Module Info
*****/

/*
 * Mozilla maintains a PSL at https://github.com/publicsuffix/list which
 * this module is designed to process.
 *
 * Also see https://publicsuffix.org/list/
 */

#include <dns/db.h>

isc_result_t
dns_psl_fromfile(const char *file, isc_mem_t *mctx, dns_db_t **psl);
/*
 * Read the public suffix list (PSL) from 'file' and return a 'db'
 * where each name in the PSL coresponds to an A record which contains
 * the number of labels in the name.  0.0.0.0 indicates the name is not
 * a PSL name.
 *
 * Requires:
 *
 * \li  'file' is non NULL.
 *
 * \li  'mctx' is a valid memory context.
 *
 * \li  psl != NULL and *psl == NULL
 */
