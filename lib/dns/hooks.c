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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <isc/errno.h>
#include <isc/file.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <isc/uv.h>

#include <dns/hooks.h>

#define CHECK(op)                              \
	do {                                   \
		result = (op);                 \
		if (result != ISC_R_SUCCESS) { \
			goto cleanup;          \
		}                              \
	} while (0)

struct dns_plugin {
	isc_mem_t *mctx;
	uv_lib_t handle;
	void *inst;
	char *modpath;
	dns_plugin_check_t *check_func;
	dns_plugin_register_t *register_func;
	dns_plugin_destroy_t *destroy_func;
	ISC_LINK(dns_plugin_t) link;
};

static dns_hooklist_t default_hooktable[DNS_HOOKPOINTS_COUNT];
dns_hooktable_t *dns__hook_table = &default_hooktable;

static isc_result_t
plugin_expandpath(const char *src, char *dst, size_t dstsize, bool appendext) {
	int result;
	const char *ext = appendext ? NAMED_PLUGINEXT : "";

	/*
	 * On Unix systems, differentiate between paths and filenames.
	 */
	if (strchr(src, '/') != NULL) {
		/*
		 * 'src' is an absolute or relative path.  Copy it verbatim.
		 */
		result = snprintf(dst, dstsize, "%s%s", src, ext);
	} else {
		/*
		 * 'src' is a filename.  Prepend default plugin directory path.
		 */
		result = snprintf(dst, dstsize, "%s/%s%s", NAMED_PLUGINDIR, src,
				  ext);
	}

	if (result < 0) {
		return isc_errno_toresult(errno);
	} else if ((size_t)result >= dstsize) {
		return ISC_R_NOSPACE;
	} else {
		return ISC_R_SUCCESS;
	}
}

isc_result_t
dns_plugin_expandpath(const char *src, char *dst, size_t dstsize) {
	isc_result_t result;

	result = plugin_expandpath(src, dst, dstsize, false);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (isc_file_exists(dst) == false) {
		result = plugin_expandpath(src, dst, dstsize, true);
	}

	return result;
}

static isc_result_t
load_symbol(uv_lib_t *handle, const char *modpath, const char *symbol_name,
	    void **symbolp) {
	void *symbol = NULL;
	int r;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	r = uv_dlsym(handle, symbol_name, &symbol);
	if (r != 0) {
		const char *errmsg = uv_dlerror(handle);
		if (errmsg == NULL) {
			errmsg = "returned function pointer is NULL";
		}
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "failed to look up symbol %s in "
			      "plugin '%s': %s",
			      symbol_name, modpath, errmsg);
		return ISC_R_FAILURE;
	}

	*symbolp = symbol;

	return ISC_R_SUCCESS;
}

static void
unload_plugin(dns_plugin_t **pluginp);

static isc_result_t
load_plugin(isc_mem_t *mctx, const char *modpath, dns_plugin_t **pluginp) {
	isc_result_t result;
	dns_plugin_t *plugin = NULL;
	dns_plugin_version_t *version_func = NULL;
	int version;
	int r;

	REQUIRE(pluginp != NULL && *pluginp == NULL);

	plugin = isc_mem_get(mctx, sizeof(*plugin));
	*plugin = (dns_plugin_t){
		.modpath = isc_mem_strdup(mctx, modpath),
	};

	isc_mem_attach(mctx, &plugin->mctx);

	ISC_LINK_INIT(plugin, link);

	r = uv_dlopen(modpath, &plugin->handle);
	if (r != 0) {
		const char *errmsg = uv_dlerror(&plugin->handle);
		if (errmsg == NULL) {
			errmsg = "unknown error";
		}
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "failed to dlopen() plugin '%s': %s", modpath,
			      errmsg);
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(&plugin->handle, modpath, "plugin_version",
			  (void **)&version_func));

	version = version_func();
	if (version < (DNS_PLUGIN_VERSION - DNS_PLUGIN_AGE) ||
	    version > DNS_PLUGIN_VERSION)
	{
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "plugin API version mismatch: %d/%d", version,
			      DNS_PLUGIN_VERSION);
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(&plugin->handle, modpath, "plugin_check",
			  (void **)&plugin->check_func));
	CHECK(load_symbol(&plugin->handle, modpath, "plugin_register",
			  (void **)&plugin->register_func));
	CHECK(load_symbol(&plugin->handle, modpath, "plugin_destroy",
			  (void **)&plugin->destroy_func));

	*pluginp = plugin;

	return ISC_R_SUCCESS;

cleanup:
	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
		      "failed to dynamically load plugin '%s': %s", modpath,
		      isc_result_totext(result));

	unload_plugin(&plugin);

	return result;
}

static void
unload_plugin(dns_plugin_t **pluginp) {
	dns_plugin_t *plugin = NULL;

	REQUIRE(pluginp != NULL && *pluginp != NULL);

	plugin = *pluginp;
	*pluginp = NULL;

	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
		      ISC_LOG_DEBUG(1), "unloading plugin '%s'",
		      plugin->modpath);

	if (plugin->inst != NULL) {
		plugin->destroy_func(&plugin->inst);
	}

	uv_dlclose(&plugin->handle);
	isc_mem_free(plugin->mctx, plugin->modpath);
	isc_mem_putanddetach(&plugin->mctx, plugin, sizeof(*plugin));
}

isc_result_t
dns_plugin_register(const char *modpath, const char *parameters,
		    const void *cfg, const char *cfg_file,
		    unsigned long cfg_line, isc_mem_t *mctx, void *aclctx,
		    dns_hook_data_t *hookdata) {
	isc_result_t result;
	dns_plugin_t *plugin = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(hookdata != NULL);

	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading plugin '%s'", modpath);

	CHECK(load_plugin(mctx, modpath, &plugin));

	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "registering plugin '%s'", modpath);

	INSIST(hookdata->pluginctx.source != DNS_HOOKSOURCE_UNDEFINED);

	CHECK(plugin->check_func(parameters, cfg, cfg_file, cfg_line, mctx,
				 aclctx, &hookdata->pluginctx));
	CHECK(plugin->register_func(parameters, cfg, cfg_file, cfg_line, mctx,
				    aclctx, hookdata->hooktable,
				    &hookdata->pluginctx, &plugin->inst));

	ISC_LIST_APPEND(*hookdata->plugins, plugin, link);

cleanup:
	if (result != ISC_R_SUCCESS && plugin != NULL) {
		unload_plugin(&plugin);
	}

	return result;
}

isc_result_t
dns_plugin_check(const char *modpath, const char *parameters, const void *cfg,
		 const char *cfg_file, unsigned long cfg_line, isc_mem_t *mctx,
		 void *aclctx, const dns_pluginctx_t *ctx) {
	isc_result_t result;
	dns_plugin_t *plugin = NULL;

	CHECK(load_plugin(mctx, modpath, &plugin));

	result = plugin->check_func(parameters, cfg, cfg_file, cfg_line, mctx,
				    aclctx, ctx);

cleanup:
	if (plugin != NULL) {
		unload_plugin(&plugin);
	}

	return result;
}

void
dns_hooktable_init(dns_hooktable_t *hooktable) {
	int i;

	for (i = 0; i < DNS_HOOKPOINTS_COUNT; i++) {
		ISC_LIST_INIT((*hooktable)[i]);
	}
}

void
dns_hooktable_create(isc_mem_t *mctx, dns_hooktable_t **tablep) {
	dns_hooktable_t *hooktable = NULL;

	REQUIRE(tablep != NULL && *tablep == NULL);

	hooktable = isc_mem_get(mctx, sizeof(*hooktable));

	dns_hooktable_init(hooktable);

	*tablep = hooktable;
}

void
dns_hooktable_free(isc_mem_t *mctx, dns_hooktable_t **tablep) {
	dns_hooktable_t *table = NULL;
	int i = 0;

	REQUIRE(tablep != NULL && *tablep != NULL);

	table = *tablep;
	*tablep = NULL;

	for (i = 0; i < DNS_HOOKPOINTS_COUNT; i++) {
		ISC_LIST_FOREACH((*table)[i], hook, link) {
			ISC_LIST_UNLINK((*table)[i], hook, link);
			if (hook->mctx != NULL) {
				isc_mem_putanddetach(&hook->mctx, hook,
						     sizeof(*hook));
			}
		}
	}

	isc_mem_put(mctx, table, sizeof(*table));
}

void
dns_hook_add(dns_hooktable_t *hooktable, isc_mem_t *mctx,
	     dns_hookpoint_t hookpoint, const dns_hook_t *hook) {
	dns_hook_t *copy = NULL;

	REQUIRE(hooktable != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(hookpoint < DNS_HOOKPOINTS_COUNT);
	REQUIRE(hook != NULL);

	copy = isc_mem_get(mctx, sizeof(*copy));
	*copy = (dns_hook_t){
		.action = hook->action,
		.action_data = hook->action_data,
	};
	isc_mem_attach(mctx, &copy->mctx);

	ISC_LINK_INIT(copy, link);
	ISC_LIST_APPEND((*hooktable)[hookpoint], copy, link);
}

void
dns_plugins_create(isc_mem_t *mctx, dns_plugins_t **listp) {
	dns_plugins_t *plugins = NULL;

	REQUIRE(listp != NULL && *listp == NULL);

	plugins = isc_mem_get(mctx, sizeof(*plugins));
	*plugins = (dns_plugins_t){ 0 };
	ISC_LIST_INIT(*plugins);

	*listp = plugins;
}

void
dns_plugins_free(isc_mem_t *mctx, void **listp) {
	dns_plugins_t *list = NULL;

	REQUIRE(listp != NULL && *listp != NULL);

	list = *listp;
	*listp = NULL;

	ISC_LIST_FOREACH(*list, plugin, link) {
		ISC_LIST_UNLINK(*list, plugin, link);
		unload_plugin(&plugin);
	}

	isc_mem_put(mctx, list, sizeof(*list));
}
