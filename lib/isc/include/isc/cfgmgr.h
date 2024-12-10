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
 * See isc_cfgmgr_mode() comment below.
 */
typedef enum isc_cfgmgr_mode isc_cfgmgr_mode_t;
enum isc_cfgmgr_mode {
	ISC_CFGMGR_MODERUNNING = 0,
	ISC_CFGMGR_MODEUSER,
	ISC_CFGMGR_MODEBUILTIN,
} __attribute__((__packed__));

/*
 * Supported data types for read/write operations from/to cfgmgr.
 */
typedef enum isc_cfgmgr_type isc_cfgmgr_type_t;
enum isc_cfgmgr_type {
	ISC_CFGMGR_UNDEFINED = 0,
	ISC_CFGMGR_STRING,
	ISC_CFGMGR_BOOLEAN,
	ISC_CFGMGR_NONE,
	ISC_CFGMGR_SOCKADDR,
	ISC_CFGMGR_UINT32,
	ISC_CFGMGR_REF,
} __attribute__((__packed__));

/*
 * Generic value holding the actual value and type value for
 * read/write from/to cfgmgr.
 *
 * cfgmgr_type_t::NONE doesn't have associated value.
 *
 * attach and detach callbacks are used (if non-NULL) to reference and
 * de-reference a ISC_CFGMGR_REF object when getting added and removed from
 * cfgmgr, after a write transaction succesfully commits.
 */
typedef struct isc_cfgmgr_val {
	isc_cfgmgr_type_t type;
	union {
		const char    *string;
		bool	       boolean;
		isc_sockaddr_t sockaddr;
		uint32_t       uint32;
		void	      *ptr;
	};
	void (*attach)(void *ptr);
	void (*detach)(void *ptr);
} isc_cfgmgr_val_t;

/*
 * cfgmgr have 3 modes:
 *
 * - builtin: stores the configuration which is hard-coded inside named source
 *   code.
 *
 * - user: stores the configuration which is provided by the user named.conf
 *   file.
 *
 * - runnning: the actual configuration used by cfgmgr consumers. It is
 *   initially built from a copy of the builtin configuration, then applies on
 *   top of it the user configuration (so, possibly overriding values). Changes
 *   made to cfgmgr afterwards are then applied to the running configuration, so
 *   on the top of the "merge" of the buitin and user configuration.
 *
 * When cfgmgr is initialized, the only mode which can be used is the builtin.
 * For this, the consumer must call "isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN)",
 * then open a write transaction and set the builtin values.
 *
 * Then, the next step is to set the user mode. The consumer must call
 * "isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER)" then open a write transaction and set
 * the user config values.
 *
 * From that point, the running mode is ready to be used, and any other
 * transaction used the running mode by default.
 *
 * While it is still possible to open a read-only transaction on builtin or user
 * mode (for instance, to dump the content), those are "frozen": it is not
 * possible to open a write-transaction on such mode anymore.
 *
 * What happens in case of named.conf configuration reload? cfgmgr needs to be
 * deinitializer/reinitialised, builtin mode re-built, then user mode
 * re-built, and so on.
 */
void
isc_cfgmgr_mode(isc_cfgmgr_mode_t mode);

/*
 * Read the property at "path" in the caller "value" and returns ISC_R_SUCCESS.
 * Returns ISC_R_NOTFOUND and "*value" is not mutated if "path" is not found.
 * Must be called under a transaction.
 *
 * The path must be a valid NULL-terminated string starting with "/" not ending
 * with "/"
 *
 * If the path format is "/view/<viewname>/<tail>" and if the value is not
 * found, the function callback itself with the path "/options/<tail>".
 *
 * If the path format is "/view/<viewname>/zones/<zonename>/<tail> and if the
 * value is not found, the function callback itself with the path
 * "/view/<viewname>/<tail>"
 */
isc_result_t
isc_cfgmgr_read(const char *path, isc_cfgmgr_val_t *value);

/*
 * Write "value" into the property at "path" and returns ISC_R_SUCCESS. If the
 * property already exists, it is overridden and even if the type is different.
 * If "value" is NULL and the property exists, it will be deleted,  otherwise it
 * returns ISC_R_NOTFOUND. Must be called under a write transaction.
 *
 * The path must be a valid NULL-terminated string starting with "/" not ending
 * with "/"
 */
isc_result_t
isc_cfgmgr_write(const char *path, const isc_cfgmgr_val_t *value);

/*
 * Delete everything under the given path. Return ISC_R_SUCCESS or
 * ISC_R_NOTFOUND if the path is not found. Must be called under a
 * write transaction.
 *
 * The path must be a valid NULL-terminated string starting and ending with "/".
 */
isc_result_t
isc_cfgmgr_delete(const char *path);

/*
 * Iterate over all properties as well as all nested properties from "path",
 * which must be a valid NULL-terminated string starting and ending with "/".
 *
 * For each property, callback "property" is called with user provided "state"
 * and the "name" of the property.
 *
 * Each time it moves one label down in the path, "labeldown" is called with
 * the user provided "state" and the entered "label".
 *
 * Each time it moves one label up in the path, "labelup" is called with the
 * user provided "state" and the left "label".
 *
 * "property", "labeldown" and "labelup" are optional callbacks. "depth"
 * indicates how deep in the path the function must call those callbacks.
 * A depth of 0 means no limit (typically useful, called from path "/" to dump
 * the whole configuration), 1 means the callbacks will be called only to the
 * directs properties of "path" and direct nested path level. Seeing the
 * configuration as a tree, a "depth" of 1 and a NULL "property" and
 * "labeldown" can be typically used to list all direct children of the current
 * node.
 *
 * The function is not re-entrant: it can't be called from one of its callbacks.
 *
 * The ISC_CFGMGR_PTR types are excluded from this listing.
 */
void
isc_cfgmgr_foreach(const char *path, size_t maxdepth, void *state,
		   void (*property)(void *state, const char *name,
				    const isc_cfgmgr_val_t *value),
		   void (*labeldown)(void *state, const char *label),
		   void (*labelup)(void *state));

/*
 * Open a read-only transaction and returns ISC_R_SUCCESS. If there is an
 * issue creating a transaction, ISC_R_FAILURE is returned. There must not be
 * any opened transaction from the current thread.
 */
isc_result_t
isc_cfgmgr_txn(void);

/*
 * Close a read-only transaction. A read-only transaction must be opened in the
 * current thread.
 */
void
isc_cfgmgr_closetxn(void);

/*
 * Open read-write transaction and returns ISC_R_SUCCESS. If there is an
 * issue creating a transaction, ISC_R_FAILURE is returned. There must not be
 * any opened transaction from the current thread. If another thread has an
 * opened read-write transaction, this call will block until the other
 * transaction is terminated.
 */
isc_result_t
isc_cfgmgr_rwtxn(void);

/*
 * Atomically make visible all the changes made during this transaction to any
 * new transaction, close the current transaction and return ISC_R_SUCCESS. A
 * read-write transaction must be opened in the current thread. If something
 * goes wrong, ISC_R_FAILURE is returned and the changes made during the
 * transaction are discarded.
 *
 * Details about the error are provided by "isc_cfgmgr_lasterror()".
 *
 */
isc_result_t
isc_cfgmgr_commit(void);

/*
 * Discard all the changes made during the read-write transaction and close it.
 * A read-write transaction must be opened from the current thread.
 */
void
isc_cfgmgr_rollback(void);

/*
 * Return a NULL-terminated string explaining why the last commit fails. If no
 * error occured so far, return an empty string.
 *
 * This is a thread-local string and it is valid until the next opened
 * transaction on this thread.
 */
const char *
isc_cfgmgr_lasterror(void);

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
