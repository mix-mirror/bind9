#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <isc/result.h>

typedef struct {
	size_t hash;
	char   data[]; // flexible array member
} isc_lhashmap_entry_t;

typedef uint64_t (*hash_func_t)(const void *);
typedef bool (*match_func_t)(const void *, const void *);

typedef struct {
	char	    *array;
	size_t	     size;
	size_t	     elem_size;
	hash_func_t  hash_func;
	match_func_t match_func;
} isc_lhashmap_t;

bool
isc_lhashmap_entry_is_empty(isc_lhashmap_entry_t *entry);
void
isc_lhashmap_entry_put_data(isc_lhashmap_t *map, isc_lhashmap_entry_t *entry,
			    void *elem);
void *
isc_lhashmap_entry_get_data(isc_lhashmap_entry_t *entry);

isc_lhashmap_t
isc_lhashmap_init(size_t size, size_t elem_size, char *array,
		  hash_func_t hash_func, match_func_t match_func);
isc_result_t
isc_lhashmap_entry(const isc_lhashmap_t *map, void *elem,
		   isc_lhashmap_entry_t **output);
isc_result_t
isc_lhashmap_put(isc_lhashmap_t *map, void *elem);

size_t
isc_lhashmap_count(isc_lhashmap_t *map);
