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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/stdio.h>
#include <isc/types.h>

#include <dns/masterdump.h>
#include <dns/types.h>
#include <dns/zone.h>

isc_result_t
setup_logging(FILE *errout);

isc_result_t
load_zone(isc_mem_t *mctx, const char *zonename, const char *filename,
	  dns_masterformat_t fileformat, const char *classname,
	  dns_ttl_t maxttl, dns_zonemgr_t *zmgr, dns_loaddonefunc_t done,
	  void *done_arg, dns_zone_t **zonep);
/*%<
 * Start loading the zone asynchronously under the zone manager 'zmgr';
 * '*zonep' is attached to the new zone immediately.  On ISC_R_SUCCESS
 * 'done' will be called with 'done_arg' and the load result once the
 * load has finished; on error 'done' is never called.  The load can
 * be canceled with dns_zone_cancelload().
 */

isc_result_t
dump_zone(const char *zonename, dns_zone_t *zone, const char *filename,
	  dns_masterformat_t fileformat, const dns_master_style_t *style,
	  const uint32_t rawversion, dns_dumpdonefunc_t done, void *done_arg,
	  FILE **outputp, dns_dumpctx_t **dctxp);
/*%<
 * Start dumping the zone asynchronously to 'filename' ("-" for
 * stdout).  On ISC_R_SUCCESS '*outputp' holds the output stream to be
 * closed by the caller (unless it is stdout) and '*dctxp' the dump
 * context that can be used with dns_dumpctx_cancel(); 'done' will be
 * called with 'done_arg' and the dump result once the dump has
 * finished.  On error 'done' is never called.
 */

extern int debug;
extern const char *journal;
extern bool nomerge;
extern bool docheckmx;
extern bool docheckns;
extern bool dochecksrv;
extern bool docheckrpz;
extern dns_zoneopt_t zone_options;
