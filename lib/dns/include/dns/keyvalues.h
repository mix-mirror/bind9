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

/*! \file dns/keyvalues.h */

/*
 * Flags field of the KEY rdata. Also used by DNSKEY, CDNSKEY, RKEY,
 * KEYDATA. Some values are only defined for KEY and not the others,
 * and vice versa.
 */
enum {
	/*
	 * Using following flags will break backwards compatibilty with
	 * old software.  As long as these are zero they are safe.
	 *
	 * Following flags were removed by RFC 3445:
	 * - 1 << 15: Formerly DNS_KEYTYPE_NOAUTH.
	 * - 1 << 14: Formerly DNS_KEYTYPE_NOCONF.
	 * - 1 << 12: Formerly DNS_KEYFLAG_EXTENDED.
	 * - 1 << 9: Formerly DNS_KEYOWNER_ENTITY.
	 */

	/*
	 * Following flags are reserved and must be zero.
	 * - 1 << 13, 1 << 11, 1 << 10, 1 << 6 - 1 << 2
	 */

	DNS_KEYOWNER_ZONE = 1 << 8,  /* zone key (mandatory for DNSKEY). */
	DNS_KEYFLAG_REVOKE = 1 << 7, /* key revoked (per rfc5011) */
	DNS_KEYFLAG_KSK = 1 << 0,    /* key signing key */
};

#define DNS_KEYFLAG_OWNERMASK DNS_KEYOWNER_ZONE

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
enum {
	DNS_KEYALG_RSAMD5 = 1,	      /*%< RSA with MD5 */
	DNS_KEYALG_DH_DEPRECATED = 2, /*%< deprecated */
	DNS_KEYALG_DSA = 3,	      /*%< DSA KEY */
	DNS_KEYALG_RSASHA1 = 5,
	DNS_KEYALG_NSEC3DSA = 6,
	DNS_KEYALG_NSEC3RSASHA1 = 7,
	DNS_KEYALG_RSASHA256 = 8,
	DNS_KEYALG_RSASHA512 = 10,
	DNS_KEYALG_ECCGOST = 12,
	DNS_KEYALG_ECDSA256 = 13,
	DNS_KEYALG_ECDSA384 = 14,
	DNS_KEYALG_ED25519 = 15,
	DNS_KEYALG_ED448 = 16,
	DNS_KEYALG_INDIRECT = 252,
	DNS_KEYALG_PRIVATEDNS = 253,
	DNS_KEYALG_PRIVATEOID = 254, /*%< Key begins with OID giving alg */
	DNS_KEYALG_MAX = 255,
};

/* Protocol values  */
enum {
	DNS_KEYPROTO_RESERVED = 0,
	DNS_KEYPROTO_DNSSEC = 3,
	DNS_KEYPROTO_ANY = 255,
};

/* Key and signature sizes */
#define DNS_KEY_ECDSA256SIZE 64
#define DNS_SIG_ECDSA256SIZE 64

#define DNS_KEY_ECDSA384SIZE 96
#define DNS_SIG_ECDSA384SIZE 96

#define DNS_KEY_ED25519SIZE 32
#define DNS_SIG_ED25519SIZE 64

#define DNS_KEY_ED448SIZE 57
#define DNS_SIG_ED448SIZE 114
