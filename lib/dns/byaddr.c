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

#include <isc/hex.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/parseint.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/byaddr.h>
#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/resolver.h>
#include <dns/view.h>

/*
 * XXXRTH  We could use a static event...
 */

static char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

isc_result_t
dns_byaddr_createptrname(const isc_netaddr_t *address,
			 dns_fixedname_t *fixed_name) {
	char textname[128];
	const unsigned char *bytes;
	int i;
	char *cp;
	isc_buffer_t buffer;
	unsigned int len;

	REQUIRE(address != NULL);

	/*
	 * We create the text representation and then convert to a
	 * dns_name_t.  This is not maximally efficient, but it keeps all
	 * of the knowledge of wire format in the dns_name_ routines.
	 */

	bytes = (const unsigned char *)(&address->type);
	if (address->family == AF_INET) {
		(void)snprintf(textname, sizeof(textname),
			       "%u.%u.%u.%u.in-addr.arpa.",
			       (unsigned int)bytes[3] & 0xffU,
			       (unsigned int)bytes[2] & 0xffU,
			       (unsigned int)bytes[1] & 0xffU,
			       (unsigned int)bytes[0] & 0xffU);
	} else if (address->family == AF_INET6) {
		size_t remaining;

		cp = textname;
		for (i = 15; i >= 0; i--) {
			*cp++ = hex_digits[bytes[i] & 0x0f];
			*cp++ = '.';
			*cp++ = hex_digits[(bytes[i] >> 4) & 0x0f];
			*cp++ = '.';
		}
		remaining = sizeof(textname) - (cp - textname);
		strlcpy(cp, "ip6.arpa.", remaining);
	} else {
		return ISC_R_NOTIMPLEMENTED;
	}

	len = (unsigned int)strlen(textname);
	isc_buffer_init(&buffer, textname, len);
	isc_buffer_add(&buffer, len);
	return dns_fixedname_fromtext(fixed_name, &buffer, dns_rootname, 0);
}

static isc_result_t
parseptrnamev4(const dns_name_t *name, isc_netaddr_t *addr) {
	isc_buffer_t b;

	if (!dns_name_issubdomain(name, dns_inaddrarpa)) {
		return ISC_R_FAILURE;
	}

	*addr = (isc_netaddr_t){ .family = AF_INET };
	isc_buffer_init(&b, &addr->type.in, sizeof(addr->type.in));

	/*
	 * Parse the IP address by extracting z y x w labels in reverse
	 * order to put the IP blocks in the right order.
	 */
	for (int i = 3; i >= 0; i--) {
		dns_label_t label;
		char labelstr[4];
		uint8_t block;

		dns_name_getlabel(name, i, &label);
		if (label.length > 4) {
			return ISC_R_FAILURE;
		}

		/*
		 * Skip the first byte of the label as it encodes the length
		 * of the label (name wire format).
		 */
		strncpy(labelstr, (char *)label.base + 1, label.length);
		labelstr[label.length - 1] = 0;
		if (isc_parse_uint8(&block, labelstr, 10) != ISC_R_SUCCESS) {
			return ISC_R_FAILURE;
		}

		isc_buffer_putuint8(&b, block);
	}

	INSIST(isc_buffer_availablelength(&b) == 0);
	return ISC_R_SUCCESS;
}

static isc_result_t
parseptrnamev6(const dns_name_t *name, isc_netaddr_t *addr) {
	isc_buffer_t b;
	isc_hex_decodectx_t ctx;

	if (!dns_name_issubdomain(name, dns_ip6arpa)) {
		return ISC_R_FAILURE;
	}

	*addr = (isc_netaddr_t){ .family = AF_INET6 };
	isc_buffer_init(&b, &addr->type.in6, sizeof(addr->type.in6));
	isc_hex_decodeinit(&ctx, isc_buffer_length(&b), &b);

	/*
	 * Parse the IP address by extracting labels in reverse order to
	 * put the IP blocks in the right order.
	 */
	for (int i = 31; i >= 0; i--) {
		dns_label_t label;

		dns_name_getlabel(name, i, &label);
		if (label.length != 2) {
			return ISC_R_FAILURE;
		}

		/*
		 * First byte is the label length
		 */
		if (isc_hex_decodechar(&ctx, label.base[1]) != ISC_R_SUCCESS) {
			return ISC_R_FAILURE;
		}
	}

	if (isc_hex_decodefinish(&ctx) != ISC_R_SUCCESS) {
		return ISC_R_FAILURE;
	}

	INSIST(isc_buffer_availablelength(&b) == 0);
	return ISC_R_SUCCESS;
}

isc_result_t
dns_byaddr_parseptrname(const dns_name_t *name, isc_netaddr_t *addr) {
	int result;

	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(addr != NULL);
	REQUIRE(dns_name_isabsolute(name));

	switch (dns_name_countlabels(name)) {
	case 7:
		/* z.y.x.w.in-addr.arpa. has 7 labels */
		result = parseptrnamev4(name, addr);
		break;
	case 35:
		/*
		 * 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0
		 * .0.0.0.0.0.0.0.0.0.ip6.arpa. has 35 labels
		 */
		result = parseptrnamev6(name, addr);
		break;
	default:
		result = ISC_R_FAILURE;
	}

	return result;
}
