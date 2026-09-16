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

#include <isc/mem.h>
#include <isc/util.h>
#include <isc/xml.h>

#ifdef HAVE_LIBXML2
#include <libxml/parser.h>
#include <libxml/xmlversion.h>

#endif /* HAVE_LIBXML2 */

void
isc__xml_initialize(void) {
#ifdef HAVE_LIBXML2
	xmlInitParser();
#endif /* HAVE_LIBXML2 */
}

void
isc__xml_shutdown(void) {
#ifdef HAVE_LIBXML2
	xmlCleanupParser();
#endif /* HAVE_LIBXML2 */
}
