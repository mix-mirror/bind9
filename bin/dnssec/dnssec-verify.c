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

/*! \file */

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <isc/atomic.h>
#include <isc/attributes.h>
#include <isc/base32.h>
#include <isc/commandline.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/hex.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/serial.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/diff.h>
#include <dns/dnssec.h>
#include <dns/ds.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>
#include <dns/master.h>
#include <dns/masterdump.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/soa.h>
#include <dns/time.h>
#include <dns/zoneverify.h>

#include <dst/dst.h>

#include "dnssectool.h"

static isc_stdtime_t now;
static dns_masterformat_t inputformat = dns_masterformat_text;
static dns_db_t *gdb = NULL;		 /* The database */
static dns_dbversion_t *gversion = NULL; /* The database version */
static dns_rdataclass_t gclass;		 /* The class */
static dns_name_t *gorigin = NULL;	 /* The database origin */
static bool ignore_kskflag = false;
static bool keyset_kskonly = false;
static char *file = NULL;
static const char *originstr = NULL;
static bool origin_is_file = false;
static dns_rdataclass_t zoneclass;
static isc_result_t vresult = ISC_R_FAILURE;
static atomic_bool completed;
static dns_loadctx_t *lctx = NULL;

static void
report(const char *format, ...) {
	if (!quiet) {
		char buf[4096];
		va_list args;

		va_start(args, format);
		vsnprintf(buf, sizeof(buf), format, args);
		va_end(args);
		fprintf(stdout, "%s\n", buf);
	}
}

static void
load_done(void *arg, isc_result_t result);

/*%
 * Create the zone database and start loading the zone file from disk
 * asynchronously; load_done() takes over when the load has finished.
 * Runs on the main loop.
 */
static void
start_load(void *arg ISC_ATTR_UNUSED) {
	isc_buffer_t b;
	int len;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_result_t result;

	len = strlen(originstr);
	isc_buffer_constinit(&b, originstr, len);
	isc_buffer_add(&b, len);

	name = dns_fixedname_initname(&fname);
	result = dns_name_fromtext(name, &b, dns_rootname, 0);
	if (result != ISC_R_SUCCESS) {
		fatal("failed converting name '%s' to dns format: %s",
		      originstr, isc_result_totext(result));
	}

	result = dns_db_create(isc_g_mctx, ZONEDB_DEFAULT, name,
			       dns_dbtype_zone, zoneclass, 0, NULL, &gdb);
	check_result(result, "dns_db_create()");

	result = dns_db_loadasync(gdb, file, inputformat, 0, isc_loop_main(),
				  load_done, NULL, &lctx);
	if (result != ISC_R_SUCCESS) {
		fatal("failed loading zone from '%s': %s", file,
		      isc_result_totext(result));
	}
}

/*%
 * The zone file has been loaded: apply the journal if requested,
 * verify the zone, and stop the loop manager.
 */
static void
load_done(void *arg ISC_ATTR_UNUSED, isc_result_t result) {
	dns_loadctx_detach(&lctx);

	switch (result) {
	case ISC_R_CANCELED:
		/* Shutting down; main() reports the abort. */
		return;
	case DNS_R_SEENINCLUDE:
	case ISC_R_SUCCESS:
		break;
	case DNS_R_NOTZONETOP:
		if (origin_is_file) {
			fatal("failed loading zone '%s' from file '%s': "
			      "use -o to specify a different zone origin",
			      originstr, file);
		}
		FALLTHROUGH;
	default:
		fatal("failed loading zone from '%s': %s", file,
		      isc_result_totext(result));
	}

	if (journal != NULL) {
		loadjournal(isc_g_mctx, gdb, journal);
	}

	gorigin = dns_db_origin(gdb);
	gclass = dns_db_class(gdb);

	gversion = NULL;
	result = dns_db_newversion(gdb, &gversion);
	check_result(result, "dns_db_newversion()");

	vresult = dns_zoneverify_dnssec(NULL, gdb, gversion, gorigin, NULL,
					isc_g_mctx, ignore_kskflag,
					keyset_kskonly, report);

	dns_db_closeversion(gdb, &gversion, false);
	dns_db_detach(&gdb);

	atomic_store(&completed, true);
	isc_loopmgr_shutdown();
}

/*%
 * Loop teardown callback: cancel a load still in flight (e.g. on
 * SIGINT) so that its completion callback runs and the loop can
 * finish.
 */
static void
cancel_inflight(void *arg ISC_ATTR_UNUSED) {
	if (lctx != NULL) {
		dns_loadctx_cancel(lctx);
	}
}

ISC_NORETURN static void
usage(int ret);

static void
usage(int ret) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t%s [options] zonefile [keys]\n",
		isc_commandline_progname);

	fprintf(stderr, "\n");

	fprintf(stderr, "Version: %s\n", PACKAGE_VERSION);

	fprintf(stderr, "Options: (default value in parenthesis) \n");
	fprintf(stderr, "\t-v debuglevel (0)\n");
	fprintf(stderr, "\t-q quiet\n");
	fprintf(stderr, "\t-V:\tprint version information\n");
	fprintf(stderr, "\t-o origin:\n");
	fprintf(stderr, "\t\tzone origin (name of zonefile)\n");
	fprintf(stderr, "\t-I format:\n");
	fprintf(stderr, "\t\tfile format of input zonefile (text)\n");
	fprintf(stderr, "\t-c class (IN)\n");
	fprintf(stderr, "\t-x:\tDNSKEY record signed with KSKs only, "
			"not ZSKs\n");
	fprintf(stderr, "\t-z:\tAll records signed with KSKs\n");
	exit(ret);
}

int
main(int argc, char *argv[]) {
	char *inputformatstr = NULL;
	char *classname = NULL;
	char *endp;
	int ch;

	atomic_init(&completed, false);

	isc_commandline_init(argc, argv);

#define CMDLINE_FLAGS "c:E:hJ:m:o:I:qv:Vxz"

	/*
	 * Process memory debugging argument first.
	 */
	while ((ch = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != -1) {
		switch (ch) {
		case 'm':
			if (strcasecmp(isc_commandline_argument, "record") == 0)
			{
				isc_mem_debugon(ISC_MEM_DEBUGRECORD);
			}
			if (strcasecmp(isc_commandline_argument, "trace") == 0)
			{
				isc_mem_debugon(ISC_MEM_DEBUGTRACE);
			}
			if (strcasecmp(isc_commandline_argument, "usage") == 0)
			{
				isc_mem_debugon(ISC_MEM_DEBUGUSAGE);
			}
			break;
		default:
			break;
		}
	}
	isc_commandline_reset = true;

	isc_commandline_errprint = false;

	while ((ch = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != -1) {
		switch (ch) {
		case 'c':
			classname = isc_commandline_argument;
			break;

		case 'E':
			fatal("%s", isc_result_totext(DST_R_NOENGINE));
			break;

		case 'I':
			inputformatstr = isc_commandline_argument;
			break;

		case 'J':
			journal = isc_commandline_argument;
			break;

		case 'm':
			break;

		case 'o':
			originstr = isc_commandline_argument;
			break;

		case 'v':
			endp = NULL;
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0') {
				fatal("verbose level must be numeric");
			}
			break;

		case 'q':
			quiet = true;
			break;

		case 'x':
			keyset_kskonly = true;
			break;

		case 'z':
			ignore_kskflag = true;
			break;

		case '?':
			if (isc_commandline_option != '?') {
				fprintf(stderr, "%s: invalid argument -%c\n",
					isc_commandline_progname,
					isc_commandline_option);
			}
			/* Does not return. */
			usage(EXIT_FAILURE);

		case 'h':
			/* Does not return. */
			usage(EXIT_SUCCESS);

		case 'V':
			/* Does not return. */
			version(isc_commandline_progname);

		default:
			fprintf(stderr, "%s: unhandled option -%c\n",
				isc_commandline_progname,
				isc_commandline_option);
			exit(EXIT_FAILURE);
		}
	}

	now = isc_stdtime_now();

	zoneclass = strtoclass(classname);

	isc_managers_create(1);

	setup_logging();

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc < 1) {
		usage(EXIT_FAILURE);
	}

	file = argv[0];

	argc -= 1;
	argv += 1;

	POST(argc);
	POST(argv);

	if (originstr == NULL) {
		originstr = isc_file_basename(file);
		origin_is_file = true;
	}

	if (inputformatstr != NULL) {
		if (strcasecmp(inputformatstr, "text") == 0) {
			inputformat = dns_masterformat_text;
		} else if (strcasecmp(inputformatstr, "raw") == 0) {
			inputformat = dns_masterformat_raw;
		} else {
			fatal("unknown file format: %s\n", inputformatstr);
		}
	}

	gdb = NULL;
	report("Loading zone '%s' from file '%s'\n", originstr, file);
	isc_loopmgr_setup(start_load, NULL);
	isc_loopmgr_teardown(cancel_inflight, NULL);
	isc_loopmgr_run();

	if (!atomic_load(&completed)) {
		fatal("process aborted by user");
	}

	if (verbose > 10) {
		isc_mem_stats(isc_g_mctx, stdout);
	}

	isc_managers_destroy();

	return vresult == ISC_R_SUCCESS ? 0 : 1;
}
