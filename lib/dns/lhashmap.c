// #pragma once

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <isc/result.h>
#include <isc/util.h>

#include <dns/lhashmap.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

static inline size_t
inc_and_saturate(size_t hash) {
	size_t result;
	if (__builtin_add_overflow(hash, 1, &result)) {
		return SIZE_MAX;
	}
	return result;
}

bool
isc_lhashmap_entry_is_empty(isc_lhashmap_entry_t *entry) {
	return entry->hash == 0ul;
}

void
isc_lhashmap_entry_put_data(isc_lhashmap_t *map, isc_lhashmap_entry_t *entry,
			    void *elem) {
	size_t elem_hash = map->hash_func(elem);
	entry->hash = inc_and_saturate(elem_hash);
	memcpy(entry->data, elem, map->elem_size);
}

void *
isc_lhashmap_entry_get_data(isc_lhashmap_t *map, isc_lhashmap_entry_t *entry,
			    void *elem) {
	REQUIRE(entry != NULL);
	return entry->data;
}

// Helper function to get entry at a specific index
static isc_lhashmap_entry_t *
lhashmap_entry_pointer(const isc_lhashmap_t *map, size_t elem_hash,
		       size_t offset) {
	size_t index = (elem_hash + offset) % map->size;
	return (isc_lhashmap_entry_t *)(map->array + index * (sizeof(size_t) +
							      map->elem_size));
}

isc_lhashmap_t
isc_lhashmap_init(size_t size, size_t elem_size, char *array,
		  hash_func_t hash_func, match_func_t match_func) {
	REQUIRE(size > 0); // TODO is this precondition even necessary?

	isc_lhashmap_t map;

	// Calculate actual size to satisfy load factor > 1.3
	size_t actual_size = ceil(size / 0.7);

	// Ensure size is at least the original size and doesn't exceed max
	if (actual_size < size) {
		actual_size = size;
	}

	map.size = actual_size;
	map.elem_size = elem_size;
	map.array = array;
	map.hash_func = hash_func;
	map.match_func = match_func;

	// Zero out the entire hashmap
	memset(array, 0, actual_size * (sizeof(size_t) + elem_size));

	return map;
}

isc_lhashmap_entry_t *
isc_lhashmap_entry(const isc_lhashmap_t *map, void *elem) {
	size_t elem_hash = map->hash_func(elem);
	size_t saturated_hash = inc_and_saturate(elem_hash);
	for (size_t i = 0; i < map->size; i++) {
		isc_lhashmap_entry_t *entry =
			lhashmap_entry_pointer(map, elem_hash, i);

		if (entry->hash == saturated_hash &&
		    map->match_func(entry->data, elem))
		{
			return entry;
		} else if (entry->hash == 0ul) {
			return entry;
		}
	}
	return NULL;
}

isc_result_t
isc_lhashmap_put(isc_lhashmap_t *map, void *elem) {
	isc_lhashmap_entry_t *entry = isc_lhashmap_entry(map, elem);
	if (entry) {
		isc_lhashmap_entry_put_data(map, entry, elem);
		return ISC_R_SUCCESS;
	}
	return ISC_R_FAILURE;
}

#pragma GCC diagnostic pop
