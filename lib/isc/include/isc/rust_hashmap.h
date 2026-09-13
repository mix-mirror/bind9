/* Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 * SPDX-License-Identifier: MPL-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * Rust-owned map of (C string, unsigned type) to non-NULL opaque pointers.
 * Keys are copied, with ASCII folding when case_sensitive is false. Values
 * remain caller-owned. All map/key pointers must be valid and non-NULL.
 * Calls must be externally serialized. Callbacks must not reenter the map.
 */
typedef struct IscRustHashmap isc_rust_hashmap_t;

isc_rust_hashmap_t *
isc_rust_hashmap_new(bool case_sensitive);
void
isc_rust_hashmap_free(isc_rust_hashmap_t *map);
void *
isc_rust_hashmap_get(const isc_rust_hashmap_t *map, const char *key,
		     unsigned int type);
/* Return the existing value without replacing it, or NULL on insertion. */
void *
isc_rust_hashmap_insert(isc_rust_hashmap_t *map, const char *key,
			unsigned int type, void *value);
void *
isc_rust_hashmap_remove(isc_rust_hashmap_t *map, const char *key,
			unsigned int type);
size_t
isc_rust_hashmap_len(const isc_rust_hashmap_t *map);
/* Remove entries for which action returns true; action may free the value. */
void
isc_rust_hashmap_foreach(isc_rust_hashmap_t *map,
			 bool (*action)(void *, void *), void *arg);
