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

/*
 * Trie-neutral DNS name key encoding.
 *
 * A DNS name is converted to an ordered byte array whose lexicographic
 * order matches DNS canonical name order (with a namespace prefix that
 * separates NORMAL from NSEC and NSEC3).  The encoding is used as the
 * lookup key for DNS-keyed data structures regardless of the underlying
 * trie implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include <dns/db.h>   /* for dns_namespace_t */
#include <dns/name.h> /* for dns_name_t */

/*%
 * The maximum size of a key is also the maximum depth of a trie.
 *
 * A domain name can be up to 255 bytes.  When converted to a key, each
 * character in the name corresponds to one byte in the key if it is a
 * common hostname character; otherwise unusual characters are escaped,
 * using two bytes in the key.  Because the maximum label length is 63
 * characters, the actual max is (255 - 5) * 2 + 6 == 506.  Then, we
 * need one more byte to prepend the namespace.
 *
 * Note: this gives us 5 bytes available space to store more data.
 */
#define DNS_QP_MAXKEY 512

/*%
 * Each element within dns_qpkey_t is a "shift" value satisfying
 * SHIFT_NOBYTE <= key[off] && key[off] < SHIFT_OFFSET (with those
 * bounds defined by the encoder).
 */
typedef uint8_t dns_qpshift_t;

/*%
 * A trie lookup key is a small array, allocated on the stack during
 * lookups.  Keys are usually created on demand from DNS names using
 * `dns_qpkey_fromname()`.
 */
typedef dns_qpshift_t dns_qpkey_t[DNS_QP_MAXKEY];

size_t
dns_qpkey_fromname(dns_qpkey_t key, const dns_name_t *name,
		   dns_namespace_t space);
/*%<
 * Convert a DNS name into a trie lookup key in the right namespace.
 *
 * Requires:
 * \li  `name` is a pointer to a valid `dns_name_t`
 *
 * Ensures:
 * \li	returned length is less than `sizeof(dns_qpkey_t)`
 *
 * Returns:
 * \li  the length of the key
 */

void
dns_qpkey_toname(const dns_qpkey_t key, size_t keylen, dns_name_t *name,
		 dns_namespace_t *space);
/*%<
 * Convert a trie lookup key back into a DNS name.
 *
 * 'space' stores whether the key is for a normal name, or denial of
 * existence.
 *
 * Requires:
 * \li  `name` is a pointer to a valid `dns_name_t`
 * \li  `name->buffer` is not NULL
 * \li  `name->offsets` is not NULL
 */
