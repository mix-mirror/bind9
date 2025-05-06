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


/* Required by cmocka */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h> /* strlen, strcmp */

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/result.h>
#include <isc/fxhash.h>
#include <isc/random.h>
#include <dns/lhashmap.h>

/* Test macros */
#include <tests/dns.h>

static uint64_t cstar_hash(const void* value) {
    const char* as_cstar = *(const char**) value;
    const uint8_t* as_bytes = *(const uint8_t**) value;
    return fx_hash_bytes(0, as_bytes, strlen(as_cstar), true);
}

static bool cstar_match(const void* lhs, const void* rhs) {
    return strcmp(*(const char**) lhs, *(const char**) rhs) == 0;
}

static isc_lhashmap_t init_fxhash(size_t size, char buffer[]) {
    return isc_lhashmap_init(size, sizeof(char*), buffer, cstar_hash, cstar_match);
}

static void ensure_exists(const void* map, char* elem) {
    isc_lhashmap_entry_t* entry_ptr = NULL;
    isc_result_t res = isc_lhashmap_entry((const isc_lhashmap_t*) map, (void*) &elem, &entry_ptr);
    assert_non_null(entry_ptr);
    assert_true(entry_ptr->hash != 0ul);

    char* value = *(char**) isc_lhashmap_entry_get_data(entry_ptr);

    assert_non_null(value);
    assert_true(res == ISC_R_SUCCESS);
    assert_true(strcmp(value, elem) == 0);

    // printf("elem:   %s\n", elem);
    // printf("value:  %s\n", value);
    // printf("res:    %s\n", isc_result_totext(res));
    // printf("strcmp: %s\n", strcmp(value, elem) ? "false" : "true");
}

static void put(void* map, char* elem) {
    isc_result_t res = isc_lhashmap_put((isc_lhashmap_t*) map, (void*) &elem);
    assert_true(res == ISC_R_SUCCESS);
}

static void prepare_seed_bytes(uint16_t seed, unsigned char bytes[4]) {
    bytes[0] = ((seed >> 12) & 0x0F) | 0xF0;  // Highest nibble
    bytes[1] = ((seed >> 8) & 0x0F) | 0xF0;   // Second nibble
    bytes[2] = ((seed >> 4) & 0x0F) | 0xF0;   // Third nibble
    bytes[3] = (seed & 0x0F) | 0xF0;          // Lowest nibble
}

static char* generate_random_string(size_t max_length, uint16_t seed) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t charset_length = sizeof(charset) - 1; // -1 to exclude the null terminator of charset
    
    size_t random_length = isc_random32() % (max_length + 1);
    
    size_t total_length = 4 /* seed */ + random_length + 1 /* null terminator */;
    
    char *str = (char *)calloc(total_length, sizeof(char));
    
    unsigned char seed_bytes[4];
    prepare_seed_bytes(seed, seed_bytes);
    memmove(str, seed_bytes, 4);
    
    for (size_t i = 0; i < random_length; i++) {
        str[4 + i] = charset[rand() % charset_length];
    }
    
    return str;
}

enum {
    BUFFER_SIZE_BYTES = (2048 * (sizeof(size_t) + sizeof(char*)))
};

ISC_RUN_TEST_IMPL(dns_lhashmap_cstar) {
    (void)put;
    (void)ensure_exists;

    char* keys[1024];
    for (size_t idx = 0; idx < 1024; ++idx) {
	keys[idx] = generate_random_string(63, (uint16_t) idx);
    }

    char buffer[BUFFER_SIZE_BYTES];
    isc_lhashmap_t ht = init_fxhash(1024, buffer); 

    for (size_t idx = 0; idx < 1024; ++idx) {
	put(&ht, keys[idx]);

	for (size_t prev = 0; prev <= idx; ++prev) {
	    ensure_exists(&ht, keys[prev]);
	}
    }

    for (size_t idx = 0; idx < 1024; ++idx) {
	free(keys[idx]);
    }
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_lhashmap_cstar)
ISC_TEST_LIST_END

ISC_TEST_MAIN
