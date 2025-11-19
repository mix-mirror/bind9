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

/* aliases for the exported symbols */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/async.h>
#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/ht.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/hooks.h>

#include <ns/client.h>
#include <ns/query.h>
#include <ns/types.h>

#define CHECK(op)                              \
	do {                                   \
		result = (op);                 \
		if (result != ISC_R_SUCCESS) { \
			goto cleanup;          \
		}                              \
	} while (0)

/*
 * Persistent data for use by this module. This will be associated
 * with client object address in the hash table, and will remain
 * accessible until the client object is detached.
 */
typedef struct async_instance {
	dns_plugin_t *module;
	isc_mem_t *mctx;
	isc_ht_t *ht;
	isc_mutex_t hlock;
} async_instance_t;

typedef struct state {
	bool async;
	dns_hook_resume_t *rev;
	dns_hookpoint_t hookpoint;
	isc_result_t origresult;
} state_t;

/*
 * Forward declarations of functions referenced in install_hooks().
 */
static dns_hookresult_t
async_query_setup(void *arg, void *cbdata, isc_result_t *resp);
static dns_hookresult_t
async_query_done_begin(void *arg, void *cbdata, isc_result_t *resp);
static dns_hookresult_t
async_query_reset(void *arg, void *cbdata, isc_result_t *resp);

/*%
 * Register the functions to be called at each hook point in 'hooktable', using
 * memory context 'mctx' for allocating copies of stack-allocated structures
 * passed to dns_hook_add().  Make sure 'inst' will be passed as the 'cbdata'
 * argument to every callback.
 */
static void
install_hooks(dns_hooktable_t *hooktable, isc_mem_t *mctx,
	      async_instance_t *inst) {
	const dns_hook_t async_setup = {
		.action = async_query_setup,
		.action_data = inst,
	};
	const dns_hook_t async_donebegin = {
		.action = async_query_done_begin,
		.action_data = inst,
	};
	const dns_hook_t async_reset = {
		.action = async_query_reset,
		.action_data = inst,
	};

	dns_hook_add(hooktable, mctx, NS_QUERY_SETUP, &async_setup);
	dns_hook_add(hooktable, mctx, NS_QUERY_DONE_BEGIN, &async_donebegin);
	dns_hook_add(hooktable, mctx, NS_QUERY_CLEANUP, &async_reset);
}

static void
logmsg(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      fmt, ap);
	va_end(ap);
}

/**
** Mandatory plugin API functions:
**
** - plugin_destroy
** - plugin_register
** - plugin_version
** - plugin_check
**/

/*
 * Called by dns_plugin_register() to initialize the plugin and
 * register hook functions into the view hook table.
 */
isc_result_t
plugin_register(const char *parameters, const void *cfg, const char *cfg_file,
		unsigned long cfg_line, isc_mem_t *mctx, void *aclctx,
		dns_hooktable_t *hooktable, const dns_pluginctx_t *ctx,
		void **instp) {
	async_instance_t *inst = NULL;

	UNUSED(parameters);
	UNUSED(cfg);
	UNUSED(aclctx);
	UNUSED(ctx);

	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "registering 'test-async' module from %s:%lu", cfg_file,
		      cfg_line);

	inst = isc_mem_get(mctx, sizeof(*inst));
	*inst = (async_instance_t){ .mctx = NULL };
	isc_mem_attach(mctx, &inst->mctx);

	isc_ht_init(&inst->ht, mctx, 1, ISC_HT_CASE_SENSITIVE);
	isc_mutex_init(&inst->hlock);

	/*
	 * Set hook points in the view's hooktable.
	 */
	install_hooks(hooktable, mctx, inst);

	*instp = inst;

	return ISC_R_SUCCESS;
}

isc_result_t
plugin_check(const char *parameters, const void *cfg, const char *cfg_file,
	     unsigned long cfg_line, isc_mem_t *mctx, void *aclctx,
	     const dns_pluginctx_t *ctx) {
	UNUSED(parameters);
	UNUSED(cfg);
	UNUSED(cfg_file);
	UNUSED(cfg_line);
	UNUSED(mctx);
	UNUSED(aclctx);
	UNUSED(ctx);

	return ISC_R_SUCCESS;
}

/*
 * Called by dns_plugins_free(); frees memory allocated by
 * the module when it was registered.
 */
void
plugin_destroy(void **instp) {
	async_instance_t *inst = (async_instance_t *)*instp;

	if (inst->ht != NULL) {
		isc_ht_destroy(&inst->ht);
		isc_mutex_destroy(&inst->hlock);
	}

	isc_mem_putanddetach(&inst->mctx, inst, sizeof(*inst));
	*instp = NULL;

	return;
}

/*
 * Returns plugin API version for compatibility checks.
 */
int
plugin_version(void) {
	return DNS_PLUGIN_VERSION;
}

static state_t *
client_state_get(const query_ctx_t *qctx, async_instance_t *inst) {
	state_t *state = NULL;
	isc_result_t result;

	LOCK(&inst->hlock);
	result = isc_ht_find(inst->ht, (const unsigned char *)&qctx->client,
			     sizeof(qctx->client), (void **)&state);
	UNLOCK(&inst->hlock);

	return result == ISC_R_SUCCESS ? state : NULL;
}

static void
client_state_create(const query_ctx_t *qctx, async_instance_t *inst) {
	state_t *state = NULL;
	isc_result_t result;

	state = isc_mem_get(inst->mctx, sizeof(*state));
	*state = (state_t){ .async = false };

	LOCK(&inst->hlock);
	result = isc_ht_add(inst->ht, (const unsigned char *)&qctx->client,
			    sizeof(qctx->client), state);
	UNLOCK(&inst->hlock);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

static void
client_state_destroy(const query_ctx_t *qctx, async_instance_t *inst) {
	state_t *state = client_state_get(qctx, inst);
	isc_result_t result;

	if (state == NULL) {
		return;
	}

	LOCK(&inst->hlock);
	result = isc_ht_delete(inst->ht, (const unsigned char *)&qctx->client,
			       sizeof(qctx->client));
	UNLOCK(&inst->hlock);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	isc_mem_put(inst->mctx, state, sizeof(*state));
}

static dns_hookresult_t
async_query_setup(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *)arg;
	async_instance_t *inst = (async_instance_t *)cbdata;
	state_t *state = NULL;

	logmsg("query setup hook");
	*resp = ISC_R_UNSET;

	state = client_state_get(qctx, inst);
	if (state == NULL) {
		client_state_create(qctx, inst);
	}

	return DNS_HOOK_CONTINUE;
}

static void
cancelasync(dns_hookasync_t *hctx) {
	UNUSED(hctx);
	logmsg("cancelasync");
}

static void
destroyasync(dns_hookasync_t **ctxp) {
	dns_hookasync_t *ctx = *ctxp;

	logmsg("destroyasync");
	*ctxp = NULL;
	isc_mem_putanddetach(&ctx->mctx, ctx, sizeof(*ctx));
}

static isc_result_t
doasync(query_ctx_t *qctx, isc_mem_t *mctx, void *arg, isc_loop_t *loop,
	isc_job_cb cb, void *evarg, dns_hookasync_t **ctxp) {
	dns_hook_resume_t *rev = isc_mem_get(mctx, sizeof(*rev));
	dns_hookasync_t *ctx = isc_mem_get(mctx, sizeof(*ctx));
	state_t *state = (state_t *)arg;

	logmsg("doasync");
	*ctx = (dns_hookasync_t){
		.cancel = cancelasync,
		.destroy = destroyasync,
	};
	isc_mem_attach(mctx, &ctx->mctx);

	qctx->result = DNS_R_NOTIMP;
	*rev = (dns_hook_resume_t){
		.hookpoint = state->hookpoint,
		.origresult = qctx->result,
		.context = qctx,
		.ctx = ctx,
		.arg = evarg,
	};

	state->rev = rev;

	isc_async_run(loop, cb, rev);

	*ctxp = ctx;
	return ISC_R_SUCCESS;
}

static dns_hookresult_t
async_query_done_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *)arg;
	async_instance_t *inst = (async_instance_t *)cbdata;
	state_t *state = client_state_get(qctx, inst);

	UNUSED(qctx);
	UNUSED(cbdata);
	UNUSED(state);

	logmsg("done begin hook");
	if (state->async) {
		/* resuming */
		state->async = false;
		return DNS_HOOK_CONTINUE;
	}

	/* initial call */
	state->async = true;
	state->hookpoint = NS_QUERY_DONE_BEGIN;
	state->origresult = *resp;
	ns_query_hookasync(qctx, doasync, state);
	return DNS_HOOK_RETURN;
}

static dns_hookresult_t
async_query_reset(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *)arg;
	async_instance_t *inst = (async_instance_t *)cbdata;

	logmsg("query reset hook");
	*resp = ISC_R_UNSET;
	client_state_destroy(qctx, inst);

	return DNS_HOOK_CONTINUE;
}
