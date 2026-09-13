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

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/rust_hashmap.h>
#include <isc/string.h>
#include <isc/symtab.h>
#include <isc/util.h>

typedef struct elt {
	void *key;
	unsigned int type;
	isc_symvalue_t value;
} elt_t;

#define SYMTAB_MAGIC	 ISC_MAGIC('S', 'y', 'm', 'T')
#define VALID_SYMTAB(st) ISC_MAGIC_VALID(st, SYMTAB_MAGIC)

struct isc_symtab {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	isc_symtabaction_t undefine_action;
	void *undefine_arg;

	isc_rust_hashmap_t *hashmap;
};

static void
elt_destroy(isc_symtab_t *symtab, elt_t *elt) {
	if (symtab->undefine_action != NULL) {
		(symtab->undefine_action)(elt->key, elt->type, elt->value,
					  symtab->undefine_arg);
	}
	isc_mem_put(symtab->mctx, elt, sizeof(*elt));
}

void
isc_symtab_create(isc_mem_t *mctx, isc_symtabaction_t undefine_action,
		  void *undefine_arg, bool case_sensitive,
		  isc_symtab_t **symtabp) {
	REQUIRE(mctx != NULL);
	REQUIRE(symtabp != NULL && *symtabp == NULL);

	isc_symtab_t *symtab = isc_mem_get(mctx, sizeof(*symtab));
	*symtab = (isc_symtab_t){
		.undefine_action = undefine_action,
		.undefine_arg = undefine_arg,
		.magic = SYMTAB_MAGIC,
	};

	isc_mem_attach(mctx, &symtab->mctx);
	symtab->hashmap = isc_rust_hashmap_new(case_sensitive);

	*symtabp = symtab;
}

static bool
elt_destroy_action(void *value, void *arg) {
	elt_destroy(arg, value);
	return true;
}

void
isc_symtab_destroy(isc_symtab_t **symtabp) {
	REQUIRE(symtabp != NULL && VALID_SYMTAB(*symtabp));

	isc_symtab_t *symtab = *symtabp;
	*symtabp = NULL;
	symtab->magic = 0;
	isc_rust_hashmap_foreach(symtab->hashmap, elt_destroy_action, symtab);
	isc_rust_hashmap_free(symtab->hashmap);
	isc_mem_putanddetach(&symtab->mctx, symtab, sizeof(*symtab));
}

isc_result_t
isc_symtab_lookup(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t *valuep) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(key != NULL);
	REQUIRE(type != 0);

	elt_t *found = isc_rust_hashmap_get(symtab->hashmap, key, type);
	if (found == NULL) {
		return ISC_R_NOTFOUND;
	}
	SET_IF_NOT_NULL(valuep, found->value);
	return ISC_R_SUCCESS;
}

isc_result_t
isc_symtab_define(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t value, isc_symexists_t exists_policy) {
	return isc_symtab_define_and_return(symtab, key, type, value,
					    exists_policy, NULL);
}

isc_result_t
isc_symtab_define_and_return(isc_symtab_t *symtab, const char *key,
			     unsigned int type, isc_symvalue_t value,
			     isc_symexists_t exists_policy,
			     isc_symvalue_t *valuep) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(key != NULL);
	REQUIRE(type != 0);

	elt_t *found = NULL;
	elt_t *elt = isc_mem_get(symtab->mctx, sizeof(*elt));
	*elt = (elt_t){
		.key = UNCONST(key),
		.type = type,
		.value = value,
	};
again:
	found = isc_rust_hashmap_insert(symtab->hashmap, key, type, elt);

	if (found == NULL) {
		SET_IF_NOT_NULL(valuep, elt->value);
		return ISC_R_SUCCESS;
	}

	switch (exists_policy) {
	case isc_symexists_reject:
		SET_IF_NOT_NULL(valuep, found->value);
		isc_mem_put(symtab->mctx, elt, sizeof(*elt));
		return ISC_R_EXISTS;
	case isc_symexists_replace: {
		elt_t *removed = isc_rust_hashmap_remove(symtab->hashmap, key,
							 type);
		INSIST(removed == found);
		elt_destroy(symtab, found);
		goto again;
	}
	default:
		UNREACHABLE();
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_symtab_undefine(isc_symtab_t *symtab, const char *key, unsigned int type) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(key != NULL);
	REQUIRE(type != 0);

	elt_t *found = isc_rust_hashmap_remove(symtab->hashmap, key, type);
	if (found == NULL) {
		return ISC_R_NOTFOUND;
	}

	elt_destroy(symtab, found);

	return ISC_R_SUCCESS;
}

unsigned int
isc_symtab_count(isc_symtab_t *symtab) {
	REQUIRE(VALID_SYMTAB(symtab));

	return isc_rust_hashmap_len(symtab->hashmap);
}

typedef struct {
	isc_symtab_t *symtab;
	isc_symtabforeachaction_t action;
	void *arg;
} foreach_ctx_t;

static bool
elt_foreach_action(void *value, void *arg) {
	elt_t *elt = value;
	foreach_ctx_t *ctx = arg;
	if (ctx->action(elt->key, elt->type, elt->value, ctx->arg)) {
		elt_destroy(ctx->symtab, elt);
		return true;
	}
	return false;
}

void
isc_symtab_foreach(isc_symtab_t *symtab, isc_symtabforeachaction_t action,
		   void *arg) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(action != NULL);

	foreach_ctx_t ctx = { .symtab = symtab, .action = action, .arg = arg };
	isc_rust_hashmap_foreach(symtab->hashmap, elt_foreach_action, &ctx);
}
