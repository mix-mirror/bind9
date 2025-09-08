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

#define DNS_CFGMGR_MAXKEYLEN 512

/*
 * See dns_cfgmgr_mode() comment below.
 */
typedef enum dns_cfgmgr_mode dns_cfgmgr_mode_t;
enum dns_cfgmgr_mode {
	DNS_CFGMGR_MODERUNNING = 0,
	DNS_CFGMGR_MODEUSER,
	DNS_CFGMGR_MODEBUILTIN,
} __attribute__((__packed__));

/*
 * Supported data types for read/write operations from/to cfgmgr.
 */
typedef enum dns_cfgmgr_type dns_cfgmgr_type_t;
enum dns_cfgmgr_type {
	DNS_CFGMGR_UNDEFINED = 0,
	DNS_CFGMGR_STRING,
	DNS_CFGMGR_BOOLEAN,
	DNS_CFGMGR_NONE,
	DNS_CFGMGR_SOCKADDR,
	DNS_CFGMGR_UINT32,
	DNS_CFGMGR_REF,
} __attribute__((__packed__));

/*
 * Generic value holding the actual value and type value for
 * read/write from/to cfgmgr.
 *
 * cfgmgr_type_t::NONE doesn't have associated value.
 *
 * attach and detach callbacks are used (if non-NULL) to reference and
 * de-reference a DNS_CFGMGR_REF object when getting added and removed from
 * cfgmgr, after a write transaction succesfully commits.
 */
typedef struct dns_cfgmgr_val {
	dns_cfgmgr_type_t type;
	union {
		const char    *string;
		bool	       boolean;
		isc_sockaddr_t sockaddr;
		uint32_t       uint32;
		void	      *ptr;
	};
	void (*attach)(void *ptr);
	void (*detach)(void *ptr);
} dns_cfgmgr_val_t;

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
 * For this, the consumer must call "dns_cfgmgr_mode(DNS_CFGMGR_MODEBUILTIN)",
 * then open a write transaction and set the builtin values.
 *
 * Then, the next step is to set the user mode. The consumer must call
 * "dns_cfgmgr_mode(DNS_CFGMGR_MODEUSER)" then open a write transaction and set
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
dns_cfgmgr_mode(dns_cfgmgr_mode_t mode);

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
 *
 * Non scalar values are read-only and _must not_ be modified. If consumer needs
 * to "hold" those values, they must be copied. (As they can be removed from
 * cfgmgr at any moment once the current transaction is done).
 */
isc_result_t
dns_cfgmgr_read(const char *path, dns_cfgmgr_val_t *value);

/*
 * Sames as dns_cfgmgr_read() but specific for DNS_CFGMGR_REF type. Also,
 * there is no inheritance. If a value exists at `path` but is not of a
 * DNS_CFGMGR_REF type, ISC_R_NOTFOUND is returned.
 *
 * As for _setref version, `owner` is the live object pointer which "holds" this
 * reference, i.e. which create the object, adds in the DB then remove it from
 * the DB when the object is deinitialized. The reason we need its pointer is to
 * create a unique path (i.e. "%p/%s", owner, path) so we're sure the object in
 * the DB is never overriden, typically in the flows when the owner is a view or
 * a zone, and when reloading the server, the new view and zones are first
 * created before the old ones gets deleted (to support rollback). It is
 * possible to have multiples "owners", i.e. a zone re-using its view ACL,
 * because when the zone will add the ACL pointer to the DB, it will be done as
 * a different "owner" and the reference count of the pointer will be incemented
 * when added in the DB.
 */
isc_result_t
dns_cfgmgr_getref(const void *owner, const char *path, void **ptr);

/*
 * Write "value" into the property at "path". If the property already exists, it
 * is overridden and even if the type is different. If "value" is NULL and the
 * property exists, it is deleted. Must be called under a write transaction.
 */
void
dns_cfgmgr_write(const char *path, const dns_cfgmgr_val_t *value);

/*
 * Same as dns_cfgmgr_write() but specific for DNS_CFGMGR_REF type. When `ptr`
 * is NULL, `attach` and `detach` must be NULL as well. Otherwise, `attach` can
 * be NULL. If `attach` is not NULL, `detach` must not be NULL.
 */
void
dns_cfgmgr_setref(const void *owner, const char *path, void *ptr,
		  void (*attach)(void *ptr), void (*detach)(void *ptr));

/*
 * Delete everything under a given path. Must be called under a write
 * transaction.
 *
 * The path must be a valid NULL-terminated string starting and ending with "/".
 */
void
dns_cfgmgr_delete(const char *path);

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
 * The DNS_CFGMGR_PTR types are excluded from this listing.
 */
void
dns_cfgmgr_foreach(const char *path, size_t maxdepth, void *state,
		   void (*property)(void *state, const char *name,
				    const dns_cfgmgr_val_t *value),
		   void (*labeldown)(void *state, const char *label),
		   void (*labelup)(void *state));

/*
 * Open a read-only transaction. There must not be any opened transaction from
 * the current thread.
 */
void
dns_cfgmgr_txn(void);

/*
 * Close a read-only transaction. A read-only transaction must be opened in the
 * current thread.
 */
void
dns_cfgmgr_closetxn(void);

/*
 * Open read-write transaction. There must not be any opened transaction from
 * the current thread. If another thread has an opened read-write transaction,
 * this call will block until the other transaction is terminated.
 */
void
dns_cfgmgr_rwtxn(void);

/*
 * Atomically make visible all the changes made during this transaction to any
 * new transaction, close the current transaction and return ISC_R_SUCCESS. A
 * read-write transaction must be opened in the current thread. If something
 * goes wrong, ISC_R_FAILURE is returned and the changes made during the
 * transaction are discarded.
 *
 * Details about the error are provided by "dns_cfgmgr_lasterror()".
 *
 */
isc_result_t
dns_cfgmgr_commit(void);

/*
 * Discard all the changes made during the read-write transaction and close it.
 * A read-write transaction must be opened from the current thread.
 */
void
dns_cfgmgr_rollback(void);

/*
 * Return a NULL-terminated string explaining why the last commit fails. If no
 * error occured so far, return an empty string.
 *
 * This is a thread-local string and it is valid until the next opened
 * transaction on this thread.
 */
const char *
dns_cfgmgr_lasterror(void);

/*
 * Initialize cfgmgr. Must be called before any other function. It is
 * possible to re-initialize cfgmgr only after calling
 * dns_cfgmgr_deinit (this drops all the data written in
 * cfgmgr).
 */
void
dns_cfgmgr_init(isc_mem_t *mctx);

/*
 * Destroy all cfgmgr data and free memory. Must be called only after
 * dns_cfgmgr_init and no function must be called after that one
 * (except dns_cfgmgr_init to re-initialize cfgmgr again).
 */
void
dns_cfgmgr_deinit(void);
