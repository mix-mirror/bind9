#pragma once

#include <isc/mem.h>
#include <dns/cfgmgr.h>

#ifdef CFGMGR_LMDB
#define CFGMGR_LMDB_ENABLED 1
#else
#define CFGMGR_LMDB_ENABLED 0
#endif

/*
 * Quick hack to be able to fallback on LMDB-based cfgmgr and compare performances
 */

void 
dns_cfgmgr_lmdb_init(isc_mem_t *mctx);

void
dns_cfgmgr_lmdb_deinit(void);

void
dns_cfgmgr_lmdb_mode(dns_cfgmgr_mode_t mode);

void
dns_cfgmgr_lmdb_txn(void);

void
dns_cfgmgr_lmdb_closetxn(void);

void
dns_cfgmgr_lmdb_rwtxn(void);

isc_result_t
dns_cfgmgr_lmdb_commit(void);

void
dns_cfgmgr_lmdb_rollback(void);

isc_result_t
dns_cfgmgr_lmdb_read(const char *path, dns_cfgmgr_val_t *value);

void
dns_cfgmgr_lmdb_write(const char *path, const dns_cfgmgr_val_t *value);

void
dns_cfgmgr_lmdb_delete(const char *path);

void
dns_cfgmgr_lmdb_foreach(const char *path, size_t maxdepth, void *state,
			void (*property)(void *state, const char *name,
					 const dns_cfgmgr_val_t *value),
			void (*labeldown)(void *state, const char *label),
			void (*labelup)(void *state));

const char *
dns_cfgmgr_lmdb_lasterror(void);

void
dns_cfgmgr_lmdb_setref(const void *owner, const char *path, void *ptr,
		       void (*attach)(void *ptr), void (*detach)(void *ptr));

isc_result_t
dns_cfgmgr_lmdb_getref(const void *owner, const char *path, void **ptr);
