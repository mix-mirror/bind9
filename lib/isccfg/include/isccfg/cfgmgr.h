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

#include <isc/sockaddr.h>
#include <isc/types.h>

/*
 * Supported data types for read/write operations from/to cfgmgr.
 */
typedef enum {
	ISC_CFGMGR_UNDEFINED = 0,
	ISC_CFGMGR_STRING,
	ISC_CFGMGR_BOOLEAN,
	ISC_CFGMGR_NONE,
	ISC_CFGMGR_SOCKADDR,
	ISC_CFGMGR_UINT32
} isc_cfgmgr_type_t;

/*
 * Generic value holding the actual value and type value for
 * read/write from/to cfgmgr.
 *
 * cfgmgr_type_t::NONE doesn't have associated value,
 */
typedef struct {
	isc_cfgmgr_type_t type;
	union {
		const char    *string;
		bool	       boolean;
		isc_sockaddr_t sockaddr;
		uint32_t       uint32;
	};
} isc_cfgmgr_val_t;

/*
 * Get the property "name" in the opened clause into the caller
 * allocated "value" and returns ISC_R_SUCCESS. Returns ISC_R_NOTFOUND
 * and "*value" is not mutated if "name" is not found. Changes being
 * made by other threads aren't visible until the clause (and its
 * parent, if nested) is closed. If "name" is a list property, get its
 * head.
 */
isc_result_t
isc_cfgmgr_getval(const char *name, isc_cfgmgr_val_t *value);

/*
 * Write "value" into the property "name" in the opened clause and
 * returns ISC_R_SUCCESS. If the property already exists, it is
 * overridden and even if the type is different. If "value" is NULL
 * and the property exists, it will be deleted (applies for list
 * properties as well), otherwise, it returns ISC_R_NOTFOUND. Changes
 * being made can be visible only by the current thread until the
 * clause (and its parent, if nested) is closed.
 */
isc_result_t
isc_cfgmgr_setval(const char *name, const isc_cfgmgr_val_t *value);

/*
 * Same as isc_cfgmgr_getval but applies for elements after the head
 * of a list property. The head is read using isc_cfgmgr_getval as any
 * other value, then subsequents calls to isc_cfgmgr_getnextlistval
 * will get the next elements in the list. When the end of the list is
 * reached, ISC_R_NOMORE is returned. Calls to
 * isc_cfgmgr_getnextlistval name has to be made in immediate sequence
 * (without intermediate isc_cfgmgr_{set,get}val calls) to retrieve
 * each list element.
 */
isc_result_t
isc_cfgmgr_getnextlistval(isc_cfgmgr_val_t *value);

/*
 * Same as isc_cfgmgr_setval but applies for a list property. Writes
 * by appending "*value" at the end of the list property "name" in the
 * opened clause and returns ISC_R_SUCCESS. If "name" property wasn't
 * existing before (or wasn't a list) it's overriden. It is not
 * possible to delete individual list element, only the whole list can
 * be removed using isc_cfgmgr_setval.
 */
isc_result_t
isc_cfgmgr_setnextlistval(const char *name, const isc_cfgmgr_val_t *value);

/*
 * If the opened clause is a repeatable clause (i.e. view, acl, etc.),
 * internally closes the opened clause and open the next clause of the
 * same type and returns ISC_R_SUCCESS. When there is no next clause
 * of the same type, ISC_R_NOMORE is returned.
 */
isc_result_t
isc_cfgmgr_nextclause(void);

/*
 * If used at top-level, create and open as read-write a new clause
 * "name". If used inside an opened parent clause, then the parent (or
 * parent or the parent, recursively) clause must have been opened
 * read-write (so using isc_cfgmgr_openrw or isc_cfgmgr_newclause).
 *
 * Returns ISC_R_SUCCESS or ISC_R_FAILURE if there is no transaction
 * and it fails creating one. Note that in order to have the new
 * clause actually written in cfgmgr, at least one property needs to
 * be set to that clause.
 */
isc_result_t
isc_cfgmgr_newclause(const char *name);

/*
 * Delete and close the opened clause. (And thus all its properties,
 * including nested clauses). If the clause was nested, the currently
 * opened clause is now the parent clause. Otherwise, no clause is
 * opened. Returns ISC_R_SUCCESS.
 */
isc_result_t
isc_cfgmgr_delclause(void);

/*
 * Close the currently opened clause and returns ISC_R_SUCCESS. If the
 * closed clause was nested, the currently opened clause is now the
 * parent clause. If top-level clause was opened with
 * isc_cfgmgr_openrw or isc_cfgmgr_newclause, closing the top-level
 * clause will applies all modifications done inside the clause (and
 * inside the nested clauses). If something is going wrong while
 * writing the modifications ISC_R_FAILURE is returned and all
 * modification made are discarded.
 */
isc_result_t
isc_cfgmgr_close(void);

/*
 * Open the top-level clause "name" for reading and writing and
 * returns ISC_R_SUCCESS. If the clause "name" is not found, returns
 * ISC_R_NOTFOUND. If there is an issue creating a transaction, it
 * returns ISC_R_FAILURE.
 *
 * This call will block if another thread has already a clause opened
 * for reading and writting. Use isc_cfgmgr_openro for reading only.
 */
isc_result_t
isc_cfgmgr_openrw(const char *name);

/*
 * Open the clause "name" and returns ISC_R_SUCCES or ISC_R_NOTFOUND
 * is the clause is not found. Two possible cases:
 *
 * - if called at top-level, it open the top-level clause as read
 *   only. Returns ISC_R_FAILURE if there is an issue creating the
 *   transaction.
 *
 * - if called form within an opened clause, it open it with the same
 *   access than the already opened clause.
 */
isc_result_t
isc_cfgmgr_open(const char *name);

/*
 * Initialize cfgmgr. Must be called before any other function. It is
 * possible to re-initialize cfgmgr only after calling
 * isc_cfgmgr_deinit (this drops all the data written in
 * cfgmgr). Returns ISC_R_SUCCESS or ISC_R_FAILURE if there is an
 * issue initializing the internal database.
 */
isc_result_t
isc_cfgmgr_init(isc_mem_t *mctx, const char *dbpath);

/*
 * Destroy all cfgmgr data and free memory. Must be called only after
 * isc_cfgmgr_init and no function must be called after that one
 * (except isc_cfgmgr_init to re-initialize cfgmgr again).
 */
void
isc_cfgmgr_deinit(void);
