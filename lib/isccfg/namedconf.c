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

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <isc/lex.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/ttl.h>

#include <isccfg/cfg.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#define TOKEN_STRING(pctx) (pctx->token.value.as_textregion.base)

/*% Check a return value. */
#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

/*% Clean up a configuration object if non-NULL. */
#define CLEANUP_OBJ(obj)                        \
	do {                                    \
		if ((obj) != NULL)              \
			cfg_obj_detach(&(obj)); \
	} while (0)

/*%
 * Forward declarations of static functions.
 */

static isc_result_t
parse_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

static isc_result_t
parse_optional_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret);

static isc_result_t
parse_updatepolicy(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);
static void
print_updatepolicy(cfg_printer_t *pctx, const cfg_obj_t *obj);

static void
merge_prepend(cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj);
static void
merge_append(cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj);

static void
doc_updatepolicy(cfg_printer_t *pctx, const cfg_type_t *type);

static void
print_keyvalue(cfg_printer_t *pctx, const cfg_obj_t *obj);

static void
doc_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type);

static void
doc_optional_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type);

static isc_result_t
cfg_parse_kv_tuple(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

static void
cfg_print_kv_tuple(cfg_printer_t *pctx, const cfg_obj_t *obj);

static void
cfg_doc_kv_tuple(cfg_printer_t *pctx, const cfg_type_t *type);

static cfg_type_t cfg_type_acl;
static cfg_type_t cfg_type_bracketed_namesockaddrkeylist;
static cfg_type_t cfg_type_bracketed_netaddrlist;
static cfg_type_t cfg_type_bracketed_sockaddrnameportlist;
static cfg_type_t cfg_type_bracketed_sockaddrtlslist;
static cfg_type_t cfg_type_bracketed_http_endpoint_list;
static cfg_type_t cfg_type_checkdstype;
static cfg_type_t cfg_type_controls;
static cfg_type_t cfg_type_controls_sockaddr;
static cfg_type_t cfg_type_destinationlist;
static cfg_type_t cfg_type_dlz;
static cfg_type_t cfg_type_dnssecpolicy;
static cfg_type_t cfg_type_dnstap;
static cfg_type_t cfg_type_dnstapoutput;
static cfg_type_t cfg_type_dyndb;
static cfg_type_t cfg_type_http_description;
static cfg_type_t cfg_type_ixfrdifftype;
static cfg_type_t cfg_type_ixfrratio;
static cfg_type_t cfg_type_key;
static cfg_type_t cfg_type_keystore;
static cfg_type_t cfg_type_logfile;
static cfg_type_t cfg_type_logging;
static cfg_type_t cfg_type_logseverity;
static cfg_type_t cfg_type_logsuffix;
static cfg_type_t cfg_type_logversions;
static cfg_type_t cfg_type_remoteselement;
static cfg_type_t cfg_type_maxcachesize;
static cfg_type_t cfg_type_maxduration;
static cfg_type_t cfg_type_minimal;
static cfg_type_t cfg_type_nameportiplist;
static cfg_type_t cfg_type_notifytype;
static cfg_type_t cfg_type_optional_allow;
static cfg_type_t cfg_type_optional_class;
static cfg_type_t cfg_type_optional_facility;
static cfg_type_t cfg_type_optional_keyref;
static cfg_type_t cfg_type_optional_port;
static cfg_type_t cfg_type_optional_sourceaddr4;
static cfg_type_t cfg_type_optional_sourceaddr6;
static cfg_type_t cfg_type_optional_uint32;
static cfg_type_t cfg_type_optional_tls;
static cfg_type_t cfg_type_options;
static cfg_type_t cfg_type_plugin;
static cfg_type_t cfg_type_portiplist;
static cfg_type_t cfg_type_printtime;
static cfg_type_t cfg_type_qminmethod;
static cfg_type_t cfg_type_querysource4;
static cfg_type_t cfg_type_querysource6;
static cfg_type_t cfg_type_server_querysource4;
static cfg_type_t cfg_type_server_querysource6;
static cfg_type_t cfg_type_querysource;
static cfg_type_t cfg_type_server;
static cfg_type_t cfg_type_server_key_kludge;
static cfg_type_t cfg_type_size;
static cfg_type_t cfg_type_sizenodefault;
static cfg_type_t cfg_type_sizeval;
static cfg_type_t cfg_type_sockaddr4wild;
static cfg_type_t cfg_type_sockaddr6wild;
static cfg_type_t cfg_type_statschannels;
static cfg_type_t cfg_type_template;
static cfg_type_t cfg_type_templateopts;
static cfg_type_t cfg_type_tlsconf;
static cfg_type_t cfg_type_view;
static cfg_type_t cfg_type_viewopts;
static cfg_type_t cfg_type_zone;

/*% listen-on */

static cfg_tuplefielddef_t listenon_tuple_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	/*
	 * Let's follow the protocols encapsulation order (lower->upper), at
	 * least roughly.
	 */
	{ "proxy", &cfg_type_astring, CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "tls", &cfg_type_astring, 0 },
#if HAVE_LIBNGHTTP2
	{ "http", &cfg_type_astring, CFG_CLAUSEFLAG_OPTIONAL },
#else
	{ "http", &cfg_type_astring, CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_listen_tuple = { .name = "listenon tuple",
					    .methods.parse = cfg_parse_kv_tuple,
					    .methods.print = cfg_print_kv_tuple,
					    .methods.doc = cfg_doc_kv_tuple,
					    .rep = &cfg_rep_tuple,
					    .of = listenon_tuple_fields };

static cfg_tuplefielddef_t listenon_fields[] = {
	{ "tuple", &cfg_type_listen_tuple, 0 },
	{ "acl", &cfg_type_bracketed_aml, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_listenon = { .name = "listenon",
					.methods.parse = cfg_parse_tuple,
					.methods.print = cfg_print_tuple,
					.methods.doc = cfg_doc_tuple,
					.rep = &cfg_rep_tuple,
					.of = listenon_fields };

/*% acl */

/*
 * Encrypted transfer related definitions
 */

static cfg_tuplefielddef_t cfg_transport_acl_tuple_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "transport", &cfg_type_astring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_transport_acl_tuple = {
	.name = "transport-acl tuple",
	.methods.parse = cfg_parse_kv_tuple,
	.methods.print = cfg_print_kv_tuple,
	.methods.doc = cfg_doc_kv_tuple,
	.rep = &cfg_rep_tuple,
	.of = cfg_transport_acl_tuple_fields
};

static cfg_tuplefielddef_t cfg_transport_acl_fields[] = {
	{ "port-transport", &cfg_transport_acl_tuple, 0 },
	{ "aml", &cfg_type_bracketed_aml, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_transport_acl = { .name = "transport-acl",
					     .methods.parse = cfg_parse_tuple,
					     .methods.print = cfg_print_tuple,
					     .methods.doc = cfg_doc_tuple,
					     .rep = &cfg_rep_tuple,
					     .of = cfg_transport_acl_fields };

/*
 * NOTE: To enable syntax which allows specifying port and protocol,
 * replace 'cfg_type_bracketed_aml' with
 * 'cfg_type_transport_acl'.
 *
 * Example: acl port 853 protocol tls { ... };
 */
static cfg_tuplefielddef_t acl_fields[] = { { "name", &cfg_type_astring, 0 },
					    { "value", &cfg_type_bracketed_aml,
					      0 },
					    { NULL, NULL, 0 } };

static cfg_type_t cfg_type_acl = { .name = "acl",
				   .methods.parse = cfg_parse_tuple,
				   .methods.print = cfg_print_tuple,
				   .methods.doc = cfg_doc_tuple,
				   .rep = &cfg_rep_tuple,
				   .of = acl_fields };

/*% remote servers, used for primaries and parental agents */
static cfg_tuplefielddef_t remotes_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "port", &cfg_type_optional_port, 0 },
	{ "source", &cfg_type_optional_sourceaddr4, 0 },
	{ "source-v6", &cfg_type_optional_sourceaddr6, 0 },
	{ "addresses", &cfg_type_bracketed_namesockaddrkeylist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_serverlist = { .name = "server-list",
					  .methods.parse = cfg_parse_tuple,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = remotes_fields };

/*%
 * "sockaddrkeylist", a list of socket addresses with optional keys
 * and an optional default port, as used in the remote-servers option.
 * E.g.,
 *   "port 1234 { myservers; 10.0.0.1 key foo; 1::2 port 69; }"
 */

static cfg_tuplefielddef_t namesockaddrkey_fields[] = {
	{ "remoteselement", &cfg_type_remoteselement, 0 },
	{ "key", &cfg_type_optional_keyref, 0 },
	{ "tls", &cfg_type_optional_tls, 0 },
	{ NULL, NULL, 0 },
};

static cfg_type_t cfg_type_namesockaddrkey = { .name = "namesockaddrkey",
					       .methods.parse = cfg_parse_tuple,
					       .methods.print = cfg_print_tuple,
					       .methods.doc = cfg_doc_tuple,
					       .rep = &cfg_rep_tuple,
					       .of = namesockaddrkey_fields };

static cfg_type_t cfg_type_bracketed_namesockaddrkeylist = {
	.name = "bracketed_namesockaddrkeylist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_namesockaddrkey
};

static cfg_tuplefielddef_t namesockaddrkeylist_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "source", &cfg_type_optional_sourceaddr4, 0 },
	{ "source-v6", &cfg_type_optional_sourceaddr6, 0 },
	{ "addresses", &cfg_type_bracketed_namesockaddrkeylist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_namesockaddrkeylist = {
	.name = "sockaddrkeylist",
	.methods.parse = cfg_parse_tuple,
	.methods.print = cfg_print_tuple,
	.methods.doc = cfg_doc_tuple,
	.rep = &cfg_rep_tuple,
	.of = namesockaddrkeylist_fields
};

/*%
 * A list of socket addresses with an optional default port, as used
 * in the 'forwarders' option.  E.g., "{ 10.0.0.1; 1::2 port 69; }"
 */
static cfg_tuplefielddef_t portiplist_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "tls", &cfg_type_optional_tls, 0 },
	{ "addresses", &cfg_type_bracketed_sockaddrtlslist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_portiplist = { .name = "portiplist",
					  .methods.parse = cfg_parse_tuple,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = portiplist_fields };

/*%
 * A list of RR types, used in grant statements.
 * Note that the old parser allows quotes around the RR type names.
 */
static cfg_type_t cfg_type_rrtypelist = { .name = "rrtypelist",
					  .methods.parse = cfg_parse_spacelist,
					  .methods.print = cfg_print_spacelist,
					  .methods.doc = cfg_doc_terminal,
					  .rep = &cfg_rep_list,
					  .of = &cfg_type_astring };

static const char *mode_enums[] = { "deny", "grant", NULL };
static cfg_type_t cfg_type_mode = { .name = "mode",
				    .methods.parse = cfg_parse_enum,
				    .methods.print = cfg_print_ustring,
				    .methods.doc = cfg_doc_enum,
				    .rep = &cfg_rep_string,
				    .of = &mode_enums };

static isc_result_t
parse_matchtype(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "zonesub") == 0)
	{
		pctx->flags |= CFG_PCTX_SKIP;
	}
	return cfg_parse_enum(pctx, type, ret);

cleanup:
	return result;
}

static isc_result_t
parse_matchname(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;

	if ((pctx->flags & CFG_PCTX_SKIP) != 0) {
		pctx->flags &= ~CFG_PCTX_SKIP;
		CHECK(cfg_parse_void(pctx, NULL, &obj));
	} else {
		result = cfg_parse_astring(pctx, type, &obj);
	}

	*ret = obj;
cleanup:
	return result;
}

static void
doc_matchname(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_print_cstr(pctx, "[ ");
	cfg_doc_obj(pctx, type->of);
	cfg_print_cstr(pctx, " ]");
}

static const char *matchtype_enums[] = { "6to4-self",
					 "external",
					 "krb5-self",
					 "krb5-selfsub",
					 "krb5-subdomain",
					 "krb5-subdomain-self-rhs",
					 "ms-self",
					 "ms-selfsub",
					 "ms-subdomain",
					 "ms-subdomain-self-rhs",
					 "name",
					 "self",
					 "selfsub",
					 "selfwild",
					 "subdomain",
					 "tcp-self",
					 "wildcard",
					 "zonesub",
					 NULL };

static cfg_type_t cfg_type_matchtype = { .name = "matchtype",
					 .methods.parse = parse_matchtype,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = cfg_doc_enum,
					 .rep = &cfg_rep_string,
					 .of = &matchtype_enums };

static cfg_type_t cfg_type_matchname = { .name = "optional_matchname",
					 .methods.parse = parse_matchname,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = doc_matchname,
					 .rep = &cfg_rep_tuple,
					 .of = &cfg_type_ustring };

/*%
 * A grant statement, used in the update policy.
 */
static cfg_tuplefielddef_t grant_fields[] = {
	{ "mode", &cfg_type_mode, 0 },
	{ "identity", &cfg_type_astring, 0 }, /* domain name */
	{ "matchtype", &cfg_type_matchtype, 0 },
	{ "name", &cfg_type_matchname, 0 }, /* domain name */
	{ "types", &cfg_type_rrtypelist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_grant = { .name = "grant",
				     .methods.parse = cfg_parse_tuple,
				     .methods.print = cfg_print_tuple,
				     .methods.doc = cfg_doc_tuple,
				     .rep = &cfg_rep_tuple,
				     .of = grant_fields };

static cfg_type_t cfg_type_updatepolicy = { .name = "update_policy",
					    .methods.parse = parse_updatepolicy,
					    .methods.print = print_updatepolicy,
					    .methods.doc = doc_updatepolicy,
					    .rep = &cfg_rep_list,
					    .of = &cfg_type_grant };

static isc_result_t
parse_updatepolicy(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	isc_result_t result;
	CHECK(cfg_gettoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_special &&
	    pctx->token.value.as_char == '{')
	{
		cfg_ungettoken(pctx);
		return cfg_parse_bracketed_list(pctx, type, ret);
	}

	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "local") == 0)
	{
		cfg_obj_t *obj = NULL;
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_ustring, &obj);
		obj->value.string.length = strlen("local");
		obj->value.string.base =
			isc_mem_get(pctx->mctx, obj->value.string.length + 1);
		memmove(obj->value.string.base, "local", 5);
		obj->value.string.base[5] = '\0';
		*ret = obj;
		return ISC_R_SUCCESS;
	}

	cfg_ungettoken(pctx);
	return ISC_R_UNEXPECTEDTOKEN;

cleanup:
	return result;
}

static void
print_updatepolicy(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	if (cfg_obj_isstring(obj)) {
		cfg_print_ustring(pctx, obj);
	} else {
		cfg_print_bracketed_list(pctx, obj);
	}
}

static void
doc_updatepolicy(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_print_cstr(pctx, "( local | { ");
	cfg_doc_obj(pctx, type->of);
	cfg_print_cstr(pctx, "; ... } )");
}

/*%
 * A view statement.
 */
static cfg_tuplefielddef_t view_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "class", &cfg_type_optional_class, 0 },
	{ "options", &cfg_type_viewopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_view = { .name = "view",
				    .methods.parse = cfg_parse_tuple,
				    .methods.print = cfg_print_tuple,
				    .methods.doc = cfg_doc_tuple,
				    .methods.merge = merge_append,
				    .rep = &cfg_rep_tuple,
				    .of = view_fields };

/*%
 * A zone statement.
 */
static cfg_tuplefielddef_t zone_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "class", &cfg_type_optional_class, 0 },
	{ "options", &cfg_type_zoneopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_zone = { .name = "zone",
				    .methods.parse = cfg_parse_tuple,
				    .methods.print = cfg_print_tuple,
				    .methods.doc = cfg_doc_tuple,
				    .rep = &cfg_rep_tuple,
				    .of = zone_fields };

/*%
 * A zone statement.
 */
static cfg_tuplefielddef_t template_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "options", &cfg_type_templateopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_template = { .name = "template",
					.methods.parse = cfg_parse_tuple,
					.methods.print = cfg_print_tuple,
					.methods.doc = cfg_doc_tuple,
					.rep = &cfg_rep_tuple,
					.of = template_fields };

/*%
 * A dnssec-policy statement.
 */
static cfg_tuplefielddef_t dnssecpolicy_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "options", &cfg_type_dnssecpolicyopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_dnssecpolicy = { .name = "dnssec-policy",
					    .methods.parse = cfg_parse_tuple,
					    .methods.print = cfg_print_tuple,
					    .methods.doc = cfg_doc_tuple,
					    .methods.merge = merge_prepend,
					    .rep = &cfg_rep_tuple,
					    .of = dnssecpolicy_fields };

/*%
 * A "category" clause in the "logging" statement.
 */
static cfg_tuplefielddef_t category_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "destinations", &cfg_type_destinationlist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_category = { .name = "category",
					.methods.parse = cfg_parse_tuple,
					.methods.print = cfg_print_tuple,
					.methods.doc = cfg_doc_tuple,
					.rep = &cfg_rep_tuple,
					.of = category_fields };

static isc_result_t
parse_maxduration(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_duration, ret);
}

static void
doc_maxduration(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_duration);
}

/*%
 * A duration or "unlimited", but not "default".
 */
static const char *maxduration_enums[] = { "unlimited", NULL };
static cfg_type_t cfg_type_maxduration = { .name = "maxduration_no_default",
					   .methods.parse = parse_maxduration,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = doc_maxduration,
					   .rep = &cfg_rep_duration,
					   .of = maxduration_enums };

/*%
 * Optional enums.
 *
 */
static isc_result_t
parse_optional_enum(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_void, ret);
}

static void
doc_optional_enum(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ ");
	cfg_doc_enum(pctx, type);
	cfg_print_cstr(pctx, " ]");
}

/*%
 * A key initialization specifier, as used in the "trust-anchors" statement.
 */
static const char *anchortype_enums[] = { "static-key", "initial-key",
					  "static-ds", "initial-ds", NULL };
static cfg_type_t cfg_type_anchortype = { .name = "anchortype",
					  .methods.parse = cfg_parse_enum,
					  .methods.print = cfg_print_ustring,
					  .methods.doc = cfg_doc_enum,
					  .rep = &cfg_rep_string,
					  .of = anchortype_enums };
static cfg_tuplefielddef_t managedkey_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "anchortype", &cfg_type_anchortype, 0 },
	{ "rdata1", &cfg_type_uint32, 0 },
	{ "rdata2", &cfg_type_uint32, 0 },
	{ "rdata3", &cfg_type_uint32, 0 },
	{ "data", &cfg_type_qstring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_managedkey = { .name = "managedkey",
					  .methods.parse = cfg_parse_tuple,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = managedkey_fields };

/*%
 * DNSSEC key roles.
 */
static const char *dnsseckeyrole_enums[] = { "csk", "ksk", "zsk", NULL };
static cfg_type_t cfg_type_dnsseckeyrole = { .name = "dnssec-key-role",
					     .methods.parse = cfg_parse_enum,
					     .methods.print = cfg_print_ustring,
					     .methods.doc = cfg_doc_enum,
					     .rep = &cfg_rep_string,
					     .of = &dnsseckeyrole_enums };

/*%
 * DNSSEC key storage types.
 */
static keyword_type_t keystore_kw = { "key-store", &cfg_type_astring };
static cfg_type_t cfg_type_keystorage = { .name = "keystorage",
					  .methods.parse = parse_keyvalue,
					  .methods.print = print_keyvalue,
					  .methods.doc = doc_keyvalue,
					  .rep = &cfg_rep_string,
					  .of = &keystore_kw };

static isc_result_t
parse_keystore(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;

	UNUSED(type);

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "key-directory") == 0)
	{
		CHECK(cfg_parse_obj(pctx, &cfg_type_ustring, &obj));
	} else if (pctx->token.type == isc_tokentype_string &&
		   strcasecmp(TOKEN_STRING(pctx), "key-store") == 0)
	{
		CHECK(cfg_parse_obj(pctx, &cfg_type_keystorage, &obj));
	} else {
		CHECK(cfg_parse_void(pctx, NULL, &obj));
	}

	*ret = obj;
cleanup:
	return result;
}

static void
doc_keystore(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);

	cfg_print_cstr(pctx, "[ key-directory | key-store <string> ]");
}

static void
print_keystore(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	REQUIRE(pctx != NULL);
	REQUIRE(obj != NULL);
	REQUIRE(obj->type->rep == &cfg_rep_string);

	if (strcasecmp(cfg_obj_asstring(obj), "key-directory") != 0) {
		cfg_print_cstr(pctx, "key-store ");
	}
	cfg_print_ustring(pctx, obj);
}

static cfg_type_t cfg_type_optional_keystore = {
	.name = "optionalkeystorage",
	.methods.parse = parse_keystore,
	.methods.print = print_keystore,
	.methods.doc = doc_keystore,
	.rep = &cfg_rep_string,
	.of = &keystore_kw
};

/*%
 * A dnssec key, as used in the "keys" statement in a "dnssec-policy".
 */
static keyword_type_t algorithm_kw = { "algorithm", &cfg_type_ustring };
static cfg_type_t cfg_type_algorithm = { .name = "algorithm",
					 .methods.parse = parse_keyvalue,
					 .methods.print = print_keyvalue,
					 .methods.doc = doc_keyvalue,
					 .rep = &cfg_rep_string,
					 .of = &algorithm_kw };

static keyword_type_t lifetime_kw = { "lifetime",
				      &cfg_type_duration_or_unlimited };
static cfg_type_t cfg_type_lifetime = { .name = "lifetime",
					.methods.parse = parse_keyvalue,
					.methods.print = print_keyvalue,
					.methods.doc = doc_keyvalue,
					.rep = &cfg_rep_duration,
					.of = &lifetime_kw };
/*
 *
 */
static void
print_tagrange(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	REQUIRE(pctx != NULL);
	REQUIRE(obj != NULL);
	REQUIRE(obj->type->rep == &cfg_rep_tuple);

	if (cfg_obj_istuple(obj)) {
		cfg_print_cstr(pctx, "tag-range ");
		cfg_print_tuple(pctx, obj);
	}
}

static cfg_tuplefielddef_t tagrange_fields[] = {
	{ "tag-min", &cfg_type_uint32, 0 },
	{ "tag-max", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_tagrange = { .name = "tagrange",
					.methods.parse = cfg_parse_tuple,
					print_tagrange,
					.methods.doc = cfg_doc_tuple,
					.rep = &cfg_rep_tuple,
					.of = tagrange_fields };

static keyword_type_t tagrange_kw = { "tag-range", &cfg_type_tagrange };
static void
doc_optionaltagrange(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);

	cfg_print_cstr(pctx, "[ tag-range <integer> <integer> ]");
}

static isc_result_t
parse_optionaltagrange(cfg_parser_t *pctx, const cfg_type_t *type,
		       cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;

	UNUSED(type);

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "tag-range") == 0)
	{
		CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
		CHECK(cfg_parse_obj(pctx, &cfg_type_tagrange, &obj));
	} else {
		CHECK(cfg_parse_void(pctx, NULL, &obj));
	}

	*ret = obj;
cleanup:
	return result;
}

static cfg_type_t cfg_type_optional_tagrange = {
	.name = "optionaltagrange",
	.methods.parse = parse_optionaltagrange,
	.methods.doc = doc_optionaltagrange,
	.rep = &cfg_rep_tuple,
	.of = &tagrange_kw
};

static cfg_tuplefielddef_t kaspkey_fields[] = {
	{ "role", &cfg_type_dnsseckeyrole, 0 },
	{ "keystorage", &cfg_type_optional_keystore, 0 },
	{ "lifetime", &cfg_type_lifetime, 0 },
	{ "algorithm", &cfg_type_algorithm, 0 },
	{ "tag-range", &cfg_type_optional_tagrange, 0 },
	{ "length", &cfg_type_optional_uint32, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_kaspkey = { .name = "kaspkey",
				       .methods.parse = cfg_parse_tuple,
				       .methods.print = cfg_print_tuple,
				       .methods.doc = cfg_doc_tuple,
				       .rep = &cfg_rep_tuple,
				       .of = kaspkey_fields };

/*%
 * NSEC3 parameters.
 */
static keyword_type_t nsec3iter_kw = { "iterations", &cfg_type_uint32 };
static cfg_type_t cfg_type_nsec3iter = { .name = "iterations",
					 .methods.parse =
						 parse_optional_keyvalue,
					 .methods.print = print_keyvalue,
					 .methods.doc = doc_optional_keyvalue,
					 .rep = &cfg_rep_uint32,
					 .of = &nsec3iter_kw };

static keyword_type_t nsec3optout_kw = { "optout", &cfg_type_boolean };
static cfg_type_t cfg_type_nsec3optout = { .name = "optout",
					   .methods.parse =
						   parse_optional_keyvalue,
					   .methods.print = print_keyvalue,
					   .methods.doc = doc_optional_keyvalue,
					   .rep = &cfg_rep_boolean,
					   .of = &nsec3optout_kw };

static keyword_type_t nsec3salt_kw = { "salt-length", &cfg_type_uint32 };
static cfg_type_t cfg_type_nsec3salt = { .name = "salt-length",
					 .methods.parse =
						 parse_optional_keyvalue,
					 .methods.print = print_keyvalue,
					 .methods.doc = doc_optional_keyvalue,
					 .rep = &cfg_rep_uint32,
					 .of = &nsec3salt_kw };

static cfg_tuplefielddef_t nsec3param_fields[] = {
	{ "iterations", &cfg_type_nsec3iter, 0 },
	{ "optout", &cfg_type_nsec3optout, 0 },
	{ "salt-length", &cfg_type_nsec3salt, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_nsec3 = { .name = "nsec3param",
				     .methods.parse = cfg_parse_tuple,
				     .methods.print = cfg_print_tuple,
				     .methods.doc = cfg_doc_tuple,
				     .rep = &cfg_rep_tuple,
				     .of = nsec3param_fields };

/*%
 * Wild class, type, name.
 */
static keyword_type_t wild_class_kw = { "class", &cfg_type_ustring };

static cfg_type_t cfg_type_optional_wild_class = {
	.name = "optional_wild_class",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_string,
	.of = &wild_class_kw
};

static keyword_type_t wild_type_kw = { "type", &cfg_type_ustring };

static cfg_type_t cfg_type_optional_wild_type = {
	.name = "optional_wild_type",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_string,
	.of = &wild_type_kw
};

static keyword_type_t wild_name_kw = { "name", &cfg_type_qstring };

static cfg_type_t cfg_type_optional_wild_name = {
	.name = "optional_wild_name",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_string,
	.of = &wild_name_kw
};

/*%
 * An rrset ordering element.
 */
static cfg_tuplefielddef_t rrsetorderingelement_fields[] = {
	{ "class", &cfg_type_optional_wild_class, 0 },
	{ "type", &cfg_type_optional_wild_type, 0 },
	{ "name", &cfg_type_optional_wild_name, 0 },
	{ "order", &cfg_type_ustring, 0 }, /* must be literal "order" */
	{ "ordering", &cfg_type_ustring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rrsetorderingelement = {
	.name = "rrsetorderingelement",
	.methods.parse = cfg_parse_tuple,
	.methods.print = cfg_print_tuple,
	.methods.doc = cfg_doc_tuple,
	.rep = &cfg_rep_tuple,
	.of = rrsetorderingelement_fields
};

/*%
 * A global or view "check-names" option.  Note that the zone
 * "check-names" option has a different syntax.
 */

static void
checknames_merge(cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj) {
	/*
	 * Applies only to the top-level option `check-names` statement.
	 * The view and zone-level versions aren't merged into the defaults
	 * the way global options are.
	 */
	REQUIRE(cfg_obj_islist(effectiveobj));
	REQUIRE(cfg_obj_islist(defaultobj));

	CFG_LIST_FOREACH(defaultobj, delt) {
		const cfg_obj_t *checkname = cfg_listelt_value(delt);
		const cfg_obj_t *type = cfg_tuple_get(checkname, "type");
		bool found = false;

		CFG_LIST_FOREACH(effectiveobj, eelt) {
			const cfg_obj_t *echeckname = cfg_listelt_value(eelt);
			const cfg_obj_t *etype = cfg_tuple_get(echeckname,
							       "type");

			if (strcasecmp(type->value.string.base,
				       etype->value.string.base) == 0)
			{
				found = true;
				break;
			}
		}

		if (found == false) {
			cfg_listelt_t *eelt = isc_mem_get(effectiveobj->mctx,
							  sizeof(*eelt));

			*eelt = (cfg_listelt_t){ .link = ISC_LINK_INITIALIZER };
			cfg_obj_clone(checkname, &eelt->obj);
			ISC_LIST_APPEND(effectiveobj->value.list, eelt, link);
		}
	}
}

static const char *checktype_enums[] = { "primary", "master",	"secondary",
					 "slave",   "response", NULL };
static cfg_type_t cfg_type_checktype = { .name = "checktype",
					 .methods.parse = cfg_parse_enum,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = cfg_doc_enum,
					 .rep = &cfg_rep_string,
					 .of = &checktype_enums };

static const char *checkmode_enums[] = { "fail", "warn", "ignore", NULL };
static cfg_type_t cfg_type_checkmode = { .name = "checkmode",
					 .methods.parse = cfg_parse_enum,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = cfg_doc_enum,
					 .rep = &cfg_rep_string,
					 .of = &checkmode_enums };

static const char *warn_enums[] = { "warn", "ignore", NULL };
static cfg_type_t cfg_type_warn = { .name = "warn",
				    .methods.parse = cfg_parse_enum,
				    .methods.print = cfg_print_ustring,
				    .methods.doc = cfg_doc_enum,
				    .rep = &cfg_rep_string,
				    .of = &warn_enums };

static cfg_tuplefielddef_t checknames_fields[] = {
	{ "type", &cfg_type_checktype, 0 },
	{ "mode", &cfg_type_checkmode, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_checknames = { .name = "checknames",
					  .methods.parse = cfg_parse_tuple,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .methods.merge = checknames_merge,
					  .rep = &cfg_rep_tuple,
					  .of = checknames_fields };

static cfg_type_t cfg_type_bracketed_netaddrlist = {
	.name = "bracketed_netaddrlist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_netaddr
};

static cfg_type_t cfg_type_bracketed_sockaddrtlslist = {
	.name = "bracketed_sockaddrtlslist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_sockaddrtls
};

static const char *dnssecupdatemode_enums[] = { "maintain", "no-resign", NULL };
static cfg_type_t cfg_type_dnssecupdatemode = { .name = "dnssecupdatemode",
						.methods.parse = cfg_parse_enum,
						.methods.print =
							cfg_print_ustring,
						.methods.doc = cfg_doc_enum,
						.rep = &cfg_rep_string,
						.of = &dnssecupdatemode_enums };

static const char *updatemethods_enums[] = { "date", "increment", "unixtime",
					     NULL };
static cfg_type_t cfg_type_updatemethod = { .name = "updatemethod",
					    .methods.parse = cfg_parse_enum,
					    .methods.print = cfg_print_ustring,
					    .methods.doc = cfg_doc_enum,
					    .rep = &cfg_rep_string,
					    .of = &updatemethods_enums };

/*
 * zone-statistics: full, terse, or none.
 *
 * for backward compatibility, we also support boolean values.
 * yes represents "full", no represents "terse". in the future we
 * may change no to mean "none".
 */
static const char *zonestat_enums[] = { "full", "terse", "none", NULL };
static isc_result_t
parse_zonestat(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_zonestat(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_zonestat = { .name = "zonestat",
					.methods.parse = parse_zonestat,
					.methods.print = cfg_print_ustring,
					.methods.doc = doc_zonestat,
					.rep = &cfg_rep_string,
					.of = zonestat_enums };

static cfg_type_t cfg_type_rrsetorder = {
	.name = "rrsetorder",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_rrsetorderingelement
};

static keyword_type_t port_kw = { "port", &cfg_type_uint32 };

static cfg_type_t cfg_type_optional_port = {
	.name = "optional_port",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_uint32,
	.of = &port_kw
};

/*% A list of keys, as in the "key" clause of the controls statement. */
static cfg_type_t cfg_type_keylist = {
	.name = "keylist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_astring
};

/*%
 * A list of managed trust anchors.  Each entry contains a name, a keyword
 * ("static-key", initial-key", "static-ds" or "initial-ds"), and the
 * fields associated with either a DNSKEY or a DS record.
 */
static cfg_type_t cfg_type_dnsseckeys = {
	.name = "dnsseckeys",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_managedkey
};

cfg_type_t cfg_type_builtin_dnsseckeys = { .name = "builtin-dnsseckeys",
					   .methods.parse =
						   cfg_parse_bracketed_list,
					   .rep = &cfg_rep_list,
					   .of = &cfg_type_managedkey };

/*%
 * A list of key entries, used in a DNSSEC Key and Signing Policy.
 */
static cfg_type_t cfg_type_kaspkeys = {
	.name = "kaspkeys",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_kaspkey
};

static const char *forwardtype_enums[] = { "first", "only", NULL };
static cfg_type_t cfg_type_forwardtype = { .name = "forwardtype",
					   .methods.parse = cfg_parse_enum,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = cfg_doc_enum,
					   .rep = &cfg_rep_string,
					   .of = &forwardtype_enums };

static const char *zonetype_enums[] = { "primary", "master",   "secondary",
					"slave",   "mirror",   "forward",
					"hint",	   "redirect", "static-stub",
					"stub",	   NULL };
static cfg_type_t cfg_type_zonetype = { .name = "zonetype",
					.methods.parse = cfg_parse_enum,
					.methods.print = cfg_print_ustring,
					.methods.doc = cfg_doc_enum,
					.rep = &cfg_rep_string,
					.of = &zonetype_enums };

static const char *loglevel_enums[] = { "critical", "error", "warning",
					"notice",   "info",  "dynamic",
					NULL };
static cfg_type_t cfg_type_loglevel = { .name = "loglevel",
					.methods.parse = cfg_parse_enum,
					.methods.print = cfg_print_ustring,
					.methods.doc = cfg_doc_enum,
					.rep = &cfg_rep_string,
					.of = &loglevel_enums };

static const char *transferformat_enums[] = { "many-answers", "one-answer",
					      NULL };
static cfg_type_t cfg_type_transferformat = { .name = "transferformat",
					      .methods.parse = cfg_parse_enum,
					      .methods.print =
						      cfg_print_ustring,
					      .methods.doc = cfg_doc_enum,
					      .rep = &cfg_rep_string,
					      .of = &transferformat_enums };

/*%
 * The special keyword "none", as used in the pid-file option.
 */

static void
print_none(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	UNUSED(obj);
	cfg_print_cstr(pctx, "none");
}

static cfg_type_t cfg_type_none = {
	.name = "none",
	.methods.print = print_none,
	.rep = &cfg_rep_void,
};

/*%
 * A quoted string or the special keyword "none".  Used in the pid-file option.
 */
static isc_result_t
parse_qstringornone(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret) {
	isc_result_t result;

	CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "none") == 0)
	{
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_none, ret);
		return ISC_R_SUCCESS;
	}
	cfg_ungettoken(pctx);
	return cfg_parse_qstring(pctx, type, ret);
cleanup:
	return result;
}

static void
doc_qstringornone(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( <quoted_string> | none )");
}

static cfg_type_t cfg_type_qstringornone = {
	.name = "qstringornone",
	.methods.parse = parse_qstringornone,
	.methods.doc = doc_qstringornone,
};

/*%
 * A boolean ("yes" or "no"), or the special keyword "auto".
 * Used in the dnssec-validation option.
 */
static void
print_auto(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	UNUSED(obj);
	cfg_print_cstr(pctx, "auto");
}

static cfg_type_t cfg_type_auto = {
	.name = "auto",
	.methods.print = print_auto,
	.rep = &cfg_rep_void,
};

static isc_result_t
parse_boolorauto(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;

	CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "auto") == 0)
	{
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_auto, ret);
		return ISC_R_SUCCESS;
	}
	cfg_ungettoken(pctx);
	return cfg_parse_boolean(pctx, type, ret);
cleanup:
	return result;
}

static void
print_boolorauto(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	if (obj->type->rep == &cfg_rep_void) {
		cfg_print_cstr(pctx, "auto");
	} else if (obj->value.boolean) {
		cfg_print_cstr(pctx, "yes");
	} else {
		cfg_print_cstr(pctx, "no");
	}
}

static void
doc_boolorauto(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( yes | no | auto )");
}

static cfg_type_t cfg_type_boolorauto = {
	.name = "boolorauto",
	.methods.parse = parse_boolorauto,
	.methods.print = print_boolorauto,
	.methods.doc = doc_boolorauto,
};

/*%
 * keyword hostname
 */
static void
print_hostname(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	UNUSED(obj);
	cfg_print_cstr(pctx, "hostname");
}

static cfg_type_t cfg_type_hostname = {
	.name = "hostname",
	.methods.print = print_hostname,
	.rep = &cfg_rep_boolean,
};

/*%
 * "server-id" argument.
 */

static isc_result_t
parse_serverid(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "none") == 0)
	{
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_none, ret);
		return ISC_R_SUCCESS;
	}
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "hostname") == 0)
	{
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_hostname, ret);
		(*ret)->value.boolean = true;
		return ISC_R_SUCCESS;
	}
	cfg_ungettoken(pctx);
	return cfg_parse_qstring(pctx, type, ret);
cleanup:
	return result;
}

static void
doc_serverid(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( <quoted_string> | none | hostname )");
}

static cfg_type_t cfg_type_serverid = {
	.name = "serverid",
	.methods.parse = parse_serverid,
	.methods.doc = doc_serverid,
};

static const char *cookiealg_enums[] = { "siphash24", NULL };
static cfg_type_t cfg_type_cookiealg = { .name = "cookiealg",
					 .methods.parse = cfg_parse_enum,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = cfg_doc_enum,
					 .rep = &cfg_rep_string,
					 .of = &cookiealg_enums };

/*%
 * fetch-quota-params
 */

static cfg_tuplefielddef_t fetchquota_fields[] = {
	{ "frequency", &cfg_type_uint32, 0 },
	{ "low", &cfg_type_fixedpoint, 0 },
	{ "high", &cfg_type_fixedpoint, 0 },
	{ "discount", &cfg_type_fixedpoint, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_fetchquota = { .name = "fetchquota",
					  .methods.parse = cfg_parse_tuple,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = fetchquota_fields };

/*%
 * fetches-per-server or fetches-per-zone
 */

static const char *response_enums[] = { "drop", "fail", NULL };

static cfg_type_t cfg_type_responsetype = { .name = "responsetype",
					    .methods.parse =
						    parse_optional_enum,
					    .methods.print = cfg_print_ustring,
					    .methods.doc = doc_optional_enum,
					    .rep = &cfg_rep_string,
					    .of = response_enums };

static cfg_tuplefielddef_t fetchesper_fields[] = {
	{ "fetches", &cfg_type_uint32, 0 },
	{ "response", &cfg_type_responsetype, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_fetchesper = { .name = "fetchesper",
					  .methods.parse = cfg_parse_tuple,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = fetchesper_fields };

static void
map_merge(cfg_obj_t *effectivemap, const cfg_obj_t *defaultmap) {
	const void *clauses = NULL;
	const cfg_clausedef_t *clause = NULL;
	unsigned int i = 0;

	for (clause = cfg_map_firstclause(effectivemap->type, &clauses, &i);
	     clause != NULL;
	     clause = cfg_map_nextclause(effectivemap->type, &clauses, &i))
	{
		isc_result_t defaultres;
		isc_result_t effectiveres;
		cfg_obj_t *effectiveobj = NULL;
		const cfg_obj_t *defaultobj = NULL;

		defaultres = cfg_map_get(defaultmap, clause->name, &defaultobj);
		INSIST(defaultres == ISC_R_NOTFOUND ||
		       defaultres == ISC_R_SUCCESS);

		effectiveres = cfg_map_get(effectivemap, clause->name,
					   (const cfg_obj_t **)&effectiveobj);
		INSIST(effectiveres == ISC_R_NOTFOUND ||
		       effectiveres == ISC_R_SUCCESS);

		/*
		 * If there's a type-specific merge function, use it.
		 */
		if (effectiveobj != NULL && defaultobj != NULL &&
		    clause->type->methods.merge != NULL)
		{
			clause->type->methods.merge(effectiveobj, defaultobj);
			continue;
		}

		/*
		 * Default merge behavior: if the clause is defined in
		 * the default but not in the user config, clone it inside
		 * the user config.
		 */
		if (effectiveres == ISC_R_NOTFOUND &&
		    defaultres == ISC_R_SUCCESS)
		{
			INSIST(cfg_map_addclone(effectivemap, defaultobj,
						clause) == ISC_R_SUCCESS);
			continue;
		}

		/*
		 * Otherwise, the clause is defined in user, so the default
		 * (if it exists) is ignored.
		 */
	}
}

/*
 * These are used when merging clauses with CFG_CLAUSEFLAG_MULTI, where
 * the entries from the user configuration and the default configuration
 * are added together, rather than the user configuration overriding the
 * default.  merge_prepend() puts the default configuration at the
 * beginning of the cloned object (for example, for dnssec-policy), and
 * merge_append() puts it at the end (for example, for views).
 */
static void
merge_prepend(cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj) {
	cfg_list_addclone(effectiveobj, defaultobj, true);
}

static void
merge_append(cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj) {
	cfg_list_addclone(effectiveobj, defaultobj, false);
}

static void
options_merge_defaultacl(cfg_obj_t *effectiveoptions,
			 const cfg_obj_t *defaultoptions, const char *aclname,
			 bool needsdefault) {
	const cfg_obj_t *obj = NULL;
	isc_result_t result;

	if (needsdefault == false) {
		return;
	}

	result = cfg_map_get(defaultoptions, aclname, &obj);
	INSIST(result == ISC_R_SUCCESS);

	cfg_obj_ref(UNCONST(obj));
	result = cfg_map_add(effectiveoptions, UNCONST(obj), aclname);
	INSIST(result == ISC_R_SUCCESS);
}

static void
options_merge(cfg_obj_t *effectiveoptions, const cfg_obj_t *defaultoptions) {
	const cfg_obj_t *obj = NULL;
	isc_result_t result;
	bool noquerycacheacl = false;
	bool norecursionacl = false;
	bool noquerycacheonacl = false;
	bool norecursiononacl = false;

	/*
	 * ACLs allow-query-cache, allow-recursion, allow-query-cache-on and
	 * allow-recursion-on need to be "merged" at once because there
	 * are implicit dependency rules between them. After all those
	 * dependency rules have been applied, the default values are used
	 * _only_ if they are still undefined in the user configuration.
	 *
	 * This need to be done only for the global options, because the views
	 * and zone ACL initialization code will look in the global options
	 * as fallback, and they'll be defined there.
	 *
	 * This is useless (and shouldn't have any effect) for views with
	 * recursion=false, but needed for those with recursion=true
	 */
	result = cfg_map_get(effectiveoptions, "allow-query-cache", &obj);
	if (result != ISC_R_SUCCESS) {
		result = cfg_map_get(effectiveoptions, "allow-recursion", &obj);
		if (result == ISC_R_SUCCESS) {
			cfg_obj_ref(UNCONST(obj));
			result = cfg_map_add(effectiveoptions, UNCONST(obj),
					     "allow-query-cache");
			INSIST(result == ISC_R_SUCCESS);
		} else {
			result = cfg_map_get(effectiveoptions, "allow-query",
					     &obj);
			if (result == ISC_R_SUCCESS) {
				cfg_obj_ref(UNCONST(obj));
				result = cfg_map_add(effectiveoptions,
						     UNCONST(obj),
						     "allow-query-cache");
				INSIST(result == ISC_R_SUCCESS);
			} else {
				noquerycacheacl = true;
			}
		}
	}

	obj = NULL;
	result = cfg_map_get(effectiveoptions, "allow-recursion", &obj);
	if (result != ISC_R_SUCCESS) {
		result = cfg_map_get(effectiveoptions, "allow-query-cache",
				     &obj);
		if (result == ISC_R_SUCCESS) {
			cfg_obj_ref(UNCONST(obj));
			result = cfg_map_add(effectiveoptions, UNCONST(obj),
					     "allow-recursion");
			INSIST(result == ISC_R_SUCCESS);
		} else {
			result = cfg_map_get(effectiveoptions, "allow-query",
					     &obj);
			if (result == ISC_R_SUCCESS) {
				cfg_obj_ref(UNCONST(obj));
				result = cfg_map_add(effectiveoptions,
						     UNCONST(obj),
						     "allow-recursion");
				INSIST(result == ISC_R_SUCCESS);
			} else {
				norecursionacl = true;
			}
		}
	}

	obj = NULL;
	result = cfg_map_get(effectiveoptions, "allow-query-cache-on", &obj);
	if (result != ISC_R_SUCCESS) {
		result = cfg_map_get(effectiveoptions, "allow-recursion-on",
				     &obj);
		if (result == ISC_R_SUCCESS) {
			cfg_obj_ref(UNCONST(obj));
			result = cfg_map_add(effectiveoptions, UNCONST(obj),
					     "allow-query-cache-on");
			INSIST(result == ISC_R_SUCCESS);
		} else {
			noquerycacheonacl = true;
		}
	}

	obj = NULL;
	result = cfg_map_get(effectiveoptions, "allow-recursion-on", &obj);
	if (result != ISC_R_SUCCESS) {
		result = cfg_map_get(effectiveoptions, "allow-query-cache-on",
				     &obj);
		if (result == ISC_R_SUCCESS) {
			cfg_obj_ref(UNCONST(obj));
			result = cfg_map_add(effectiveoptions, UNCONST(obj),
					     "allow-recursion-on");
			INSIST(result == ISC_R_SUCCESS);
		} else {
			norecursiononacl = true;
		}
	}

	options_merge_defaultacl(effectiveoptions, defaultoptions,
				 "allow-query-cache", noquerycacheacl);
	options_merge_defaultacl(effectiveoptions, defaultoptions,
				 "allow-recursion", norecursionacl);
	options_merge_defaultacl(effectiveoptions, defaultoptions,
				 "allow-query-cache-on", noquerycacheonacl);
	options_merge_defaultacl(effectiveoptions, defaultoptions,
				 "allow-recursion-on", norecursiononacl);

	map_merge(effectiveoptions, defaultoptions);
}

/*%
 * Clauses that can be found within the top level of the named.conf
 * file only.
 */
static cfg_clausedef_t namedconf_clauses[] = {
	{ "acl", &cfg_type_acl, CFG_CLAUSEFLAG_MULTI },
	{ "controls", &cfg_type_controls, CFG_CLAUSEFLAG_MULTI },
	{ "dnssec-policy", &cfg_type_dnssecpolicy, CFG_CLAUSEFLAG_MULTI },
#if HAVE_LIBNGHTTP2
	{ "http", &cfg_type_http_description,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_OPTIONAL },
#else
	{ "http", &cfg_type_http_description,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif
	{ "key-store", &cfg_type_keystore, CFG_CLAUSEFLAG_MULTI },
	{ "logging", &cfg_type_logging, 0 },
	{ "lwres", NULL, CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ "masters", &cfg_type_serverlist,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC },
	{ "options", &cfg_type_options, 0 },
	{ "parental-agents", &cfg_type_serverlist,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC },
	{ "primaries", &cfg_type_serverlist,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC },
	{ "remote-servers", &cfg_type_serverlist, CFG_CLAUSEFLAG_MULTI },
#if defined(HAVE_LIBXML2) || defined(HAVE_JSON_C)
	{ "statistics-channels", &cfg_type_statschannels,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_OPTIONAL },
#else
	{ "statistics-channels", &cfg_type_statschannels,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif
	{ "template", &cfg_type_template, CFG_CLAUSEFLAG_MULTI },
	{ "builtin-trust-anchors", &cfg_type_builtin_dnsseckeys,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_BUILTINONLY |
		  CFG_CLAUSEFLAG_NODOC },
	{ "tls", &cfg_type_tlsconf, CFG_CLAUSEFLAG_MULTI },
	{ "view", &cfg_type_view, CFG_CLAUSEFLAG_MULTI },
	{ NULL, NULL, 0 }
};

/*%
 * Clauses that can occur at the top level or in the view
 * statement, but not in the options block.
 */
static cfg_clausedef_t namedconf_or_view_clauses[] = {
	{ "dlz", &cfg_type_dlz, CFG_CLAUSEFLAG_MULTI },
	{ "dyndb", &cfg_type_dyndb, CFG_CLAUSEFLAG_MULTI },
	{ "key", &cfg_type_key, CFG_CLAUSEFLAG_MULTI },
	{ "managed-keys", &cfg_type_dnsseckeys,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ "plugin", &cfg_type_plugin, CFG_CLAUSEFLAG_MULTI },
	{ "server", &cfg_type_server, CFG_CLAUSEFLAG_MULTI },
	{ "trust-anchors", &cfg_type_dnsseckeys, CFG_CLAUSEFLAG_MULTI },
	{ "trusted-keys", NULL, CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ "zone", &cfg_type_zone, CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC },
	{ NULL, NULL, 0 }
};

/*%
 * Clauses that can occur in a trust anchor file (previously
 * called bind.keys).
 */
static cfg_clausedef_t bindkeys_clauses[] = {
	{ "managed-keys", &cfg_type_dnsseckeys,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ "trust-anchors", &cfg_type_dnsseckeys, CFG_CLAUSEFLAG_MULTI },
	{ "trusted-keys", NULL, CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ NULL, NULL, 0 }
};

static const char *fstrm_model_enums[] = { "mpsc", "spsc", NULL };
static cfg_type_t cfg_type_fstrm_model = { .name = "model",
					   .methods.parse = cfg_parse_enum,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = cfg_doc_enum,
					   .rep = &cfg_rep_string,
					   .of = &fstrm_model_enums };

/*%
 * Clauses that can be found within the 'options' statement.
 */
static cfg_clausedef_t options_clauses[] = {
	{ "answer-cookie", &cfg_type_boolean, 0 },
	{ "automatic-interface-scan", &cfg_type_boolean, 0 },
	{ "avoid-v4-udp-ports", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "avoid-v6-udp-ports", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "bindkeys-file", &cfg_type_qstring, CFG_CLAUSEFLAG_ANCIENT },
	{ "blackhole", &cfg_type_bracketed_aml, 0 },
	{ "cookie-algorithm", &cfg_type_cookiealg, 0 },
	{ "cookie-secret", &cfg_type_sstring, CFG_CLAUSEFLAG_MULTI },
	{ "coresize", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "datasize", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "deallocate-on-exit", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "directory", &cfg_type_qstring, CFG_CLAUSEFLAG_CHDIR },
	{ "dnsrps-library", &cfg_type_qstring, CFG_CLAUSEFLAG_OBSOLETE },
#ifdef HAVE_DNSTAP
	{ "dnstap-output", &cfg_type_dnstapoutput, CFG_CLAUSEFLAG_OPTIONAL },
	{ "dnstap-identity", &cfg_type_serverid, CFG_CLAUSEFLAG_OPTIONAL },
	{ "dnstap-version", &cfg_type_qstringornone, CFG_CLAUSEFLAG_OPTIONAL },
#else  /* ifdef HAVE_DNSTAP */
	{ "dnstap-output", &cfg_type_dnstapoutput,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "dnstap-identity", &cfg_type_serverid, CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "dnstap-version", &cfg_type_qstringornone,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif /* ifdef HAVE_DNSTAP */
	{ "dscp", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "dump-file", &cfg_type_qstring, 0 },
	{ "fake-iquery", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "files", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "flush-zones-on-shutdown", &cfg_type_boolean, 0 },
#ifdef HAVE_DNSTAP
	{ "fstrm-set-buffer-hint", &cfg_type_uint32, CFG_CLAUSEFLAG_OPTIONAL },
	{ "fstrm-set-flush-timeout", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL },
	{ "fstrm-set-input-queue-size", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL },
	{ "fstrm-set-output-notify-threshold", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL },
	{ "fstrm-set-output-queue-model", &cfg_type_fstrm_model,
	  CFG_CLAUSEFLAG_OPTIONAL },
	{ "fstrm-set-output-queue-size", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL },
	{ "fstrm-set-reopen-interval", &cfg_type_duration,
	  CFG_CLAUSEFLAG_OPTIONAL },
#else  /* ifdef HAVE_DNSTAP */
	{ "fstrm-set-buffer-hint", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "fstrm-set-flush-timeout", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "fstrm-set-input-queue-size", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "fstrm-set-output-notify-threshold", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "fstrm-set-output-queue-model", &cfg_type_fstrm_model,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "fstrm-set-output-queue-size", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "fstrm-set-reopen-interval", &cfg_type_duration,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif /* HAVE_DNSTAP */
#if defined(HAVE_GEOIP2)
	{ "geoip-directory", &cfg_type_qstringornone, 0 },
#else  /* if defined(HAVE_GEOIP2) */
	{ "geoip-directory", &cfg_type_qstringornone,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif /* HAVE_GEOIP2 */
	{ "geoip-use-ecs", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "has-old-clients", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "heartbeat-interval", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "host-statistics", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "host-statistics-max", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "hostname", &cfg_type_qstringornone, 0 },
	{ "interface-interval", &cfg_type_duration, 0 },
	{ "keep-response-order", &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_OBSOLETE },
	{ "listen-on", &cfg_type_listenon, CFG_CLAUSEFLAG_MULTI },
	{ "listen-on-v6", &cfg_type_listenon, CFG_CLAUSEFLAG_MULTI },
	{ "lock-file", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "managed-keys-directory", &cfg_type_qstring, 0 },
	{ "match-mapped-addresses", &cfg_type_boolean, 0 },
	{ "max-rsa-exponent-size", &cfg_type_uint32, 0 },
	{ "memstatistics", &cfg_type_boolean, 0 },
	{ "memstatistics-file", &cfg_type_qstring, 0 },
	{ "multiple-cnames", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "named-xfer", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "notify-rate", &cfg_type_uint32, 0 },
	{ "pid-file", &cfg_type_qstringornone, 0 },
	{ "port", &cfg_type_uint32, 0 },
	{ "tls-port", &cfg_type_uint32, 0 },
#if HAVE_LIBNGHTTP2
	{ "http-port", &cfg_type_uint32, CFG_CLAUSEFLAG_OPTIONAL },
	{ "http-listener-clients", &cfg_type_uint32, CFG_CLAUSEFLAG_OPTIONAL },
	{ "http-streams-per-connection", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL },
	{ "https-port", &cfg_type_uint32, CFG_CLAUSEFLAG_OPTIONAL },
#else
	{ "http-port", &cfg_type_uint32, CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "http-listener-clients", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "http-streams-per-connection", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED },
	{ "https-port", &cfg_type_uint32, CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif
	{ "querylog", &cfg_type_boolean, 0 },
	{ "random-device", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "recursing-file", &cfg_type_qstring, 0 },
	{ "recursive-clients", &cfg_type_uint32, 0 },
	{ "reuseport", &cfg_type_boolean, 0 },
	{ "reserved-sockets", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "responselog", &cfg_type_boolean, 0 },
	{ "secroots-file", &cfg_type_qstring, 0 },
	{ "serial-queries", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "serial-query-rate", &cfg_type_uint32, 0 },
	{ "server-id", &cfg_type_serverid, 0 },
	{ "session-keyalg", &cfg_type_astring, 0 },
	{ "session-keyfile", &cfg_type_qstringornone, 0 },
	{ "session-keyname", &cfg_type_astring, 0 },
	{ "sig0checks-quota", &cfg_type_uint32, CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "sig0checks-quota-exempt", &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "sit-secret", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "stacksize", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "startup-notify-rate", &cfg_type_uint32, 0 },
	{ "statistics-file", &cfg_type_qstring, 0 },
	{ "statistics-interval", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "tcp-advertised-timeout", &cfg_type_uint32, 0 },
	{ "tcp-clients", &cfg_type_uint32, 0 },
	{ "tcp-idle-timeout", &cfg_type_uint32, 0 },
	{ "tcp-initial-timeout", &cfg_type_uint32, 0 },
	{ "tcp-keepalive-timeout", &cfg_type_uint32, 0 },
	{ "tcp-listen-queue", &cfg_type_uint32, 0 },
	{ "tcp-primaries-timeout", &cfg_type_uint32, 0 },
	{ "tcp-receive-buffer", &cfg_type_uint32, 0 },
	{ "tcp-send-buffer", &cfg_type_uint32, 0 },
	{ "tkey-dhkey", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "tkey-domain", &cfg_type_qstring, CFG_CLAUSEFLAG_ANCIENT },
	{ "tkey-gssapi-credential", &cfg_type_qstring, CFG_CLAUSEFLAG_ANCIENT },
	{ "tkey-gssapi-keytab", &cfg_type_qstring, 0 },
	{ "transfer-message-size", &cfg_type_uint32, 0 },
	{ "transfers-in", &cfg_type_uint32, 0 },
	{ "transfers-out", &cfg_type_uint32, 0 },
	{ "transfers-per-ns", &cfg_type_uint32, 0 },
	{ "treat-cr-as-space", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "udp-receive-buffer", &cfg_type_uint32, 0 },
	{ "udp-send-buffer", &cfg_type_uint32, 0 },
	{ "update-quota", &cfg_type_uint32, 0 },
	{ "use-id-pool", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "use-ixfr", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "use-v4-udp-ports", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "use-v6-udp-ports", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "version", &cfg_type_qstringornone, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_namelist = {
	.name = "namelist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_astring
};

static keyword_type_t exceptionnames_kw = { "except-from", &cfg_type_namelist };

static cfg_type_t cfg_type_optional_exceptionnames = {
	.name = "optional_allow",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_list,
	.of = &exceptionnames_kw
};

static cfg_tuplefielddef_t denyaddresses_fields[] = {
	{ "acl", &cfg_type_bracketed_aml, 0 },
	{ "except-from", &cfg_type_optional_exceptionnames, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_denyaddresses = { .name = "denyaddresses",
					     .methods.parse = cfg_parse_tuple,
					     .methods.print = cfg_print_tuple,
					     .methods.doc = cfg_doc_tuple,
					     .rep = &cfg_rep_tuple,
					     .of = denyaddresses_fields };

static cfg_tuplefielddef_t denyaliases_fields[] = {
	{ "name", &cfg_type_namelist, 0 },
	{ "except-from", &cfg_type_optional_exceptionnames, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_denyaliases = { .name = "denyaliases",
					   .methods.parse = cfg_parse_tuple,
					   .methods.print = cfg_print_tuple,
					   .methods.doc = cfg_doc_tuple,
					   .rep = &cfg_rep_tuple,
					   .of = denyaliases_fields };

static cfg_type_t cfg_type_algorithmlist = {
	.name = "algorithmlist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_astring
};

static cfg_tuplefielddef_t disablealgorithm_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "algorithms", &cfg_type_algorithmlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_disablealgorithm = {
	.name = "disablealgorithm",
	.methods.parse = cfg_parse_tuple,
	.methods.print = cfg_print_tuple,
	.methods.doc = cfg_doc_tuple,
	.rep = &cfg_rep_tuple,
	.of = disablealgorithm_fields
};

static cfg_type_t cfg_type_dsdigestlist = {
	.name = "dsdigestlist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_astring
};

static cfg_tuplefielddef_t disabledsdigest_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "digests", &cfg_type_dsdigestlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_disabledsdigest = { .name = "disabledsdigest",
					       .methods.parse = cfg_parse_tuple,
					       .methods.print = cfg_print_tuple,
					       .methods.doc = cfg_doc_tuple,
					       .rep = &cfg_rep_tuple,
					       .of = disabledsdigest_fields };

static const char *masterformat_enums[] = { "raw", "text", NULL };
static cfg_type_t cfg_type_masterformat = { .name = "masterformat",
					    .methods.parse = cfg_parse_enum,
					    .methods.print = cfg_print_ustring,
					    .methods.doc = cfg_doc_enum,
					    .rep = &cfg_rep_string,
					    .of = &masterformat_enums };

static const char *masterstyle_enums[] = { "full", "relative", NULL };
static cfg_type_t cfg_type_masterstyle = { .name = "masterstyle",
					   .methods.parse = cfg_parse_enum,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = cfg_doc_enum,
					   .rep = &cfg_rep_string,
					   .of = &masterstyle_enums };

static keyword_type_t blocksize_kw = { "block-size", &cfg_type_uint32 };

static cfg_type_t cfg_type_blocksize = { .name = "blocksize",
					 .methods.parse = parse_keyvalue,
					 .methods.print = print_keyvalue,
					 .methods.doc = doc_keyvalue,
					 .rep = &cfg_rep_uint32,
					 .of = &blocksize_kw };

static cfg_tuplefielddef_t resppadding_fields[] = {
	{ "acl", &cfg_type_bracketed_aml, 0 },
	{ "block-size", &cfg_type_blocksize, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_resppadding = { .name = "resppadding",
					   .methods.parse = cfg_parse_tuple,
					   .methods.print = cfg_print_tuple,
					   .methods.doc = cfg_doc_tuple,
					   .rep = &cfg_rep_tuple,
					   .of = resppadding_fields };

/*%
 *  dnstap {
 *      &lt;message type&gt; [query | response] ;
 *      ...
 *  }
 *
 *  ... where message type is one of: client, resolver, auth, forwarder,
 *                                    update, all
 */
static const char *dnstap_types[] = { "all",	   "auth",     "client",
				      "forwarder", "resolver", "update",
				      NULL };

static const char *dnstap_modes[] = { "query", "response", NULL };

static cfg_type_t cfg_type_dnstap_type = { .name = "dnstap_type",
					   .methods.parse = cfg_parse_enum,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = cfg_doc_enum,
					   .rep = &cfg_rep_string,
					   .of = dnstap_types };

static cfg_type_t cfg_type_dnstap_mode = { .name = "dnstap_mode",
					   .methods.parse = parse_optional_enum,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = doc_optional_enum,
					   .rep = &cfg_rep_string,
					   .of = dnstap_modes };

static cfg_tuplefielddef_t dnstap_fields[] = {
	{ "type", &cfg_type_dnstap_type, 0 },
	{ "mode", &cfg_type_dnstap_mode, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_dnstap_entry = { .name = "dnstap_value",
					    .methods.parse = cfg_parse_tuple,
					    .methods.print = cfg_print_tuple,
					    .methods.doc = cfg_doc_tuple,
					    .rep = &cfg_rep_tuple,
					    .of = dnstap_fields };

static cfg_type_t cfg_type_dnstap = { .name = "dnstap",
				      .methods.parse = cfg_parse_bracketed_list,
				      .methods.print = cfg_print_bracketed_list,
				      .methods.doc = cfg_doc_bracketed_list,
				      .rep = &cfg_rep_list,
				      .of = &cfg_type_dnstap_entry };

/*%
 * dnstap-output
 */
static isc_result_t
parse_dtout(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const cfg_tuplefielddef_t *fields = type->of;

	cfg_tuple_create(pctx, type, &obj);

	/* Parse the mandatory "mode" and "path" fields */
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));
	CHECK(cfg_parse_obj(pctx, fields[1].type, &obj->value.tuple[1]));

	/* Parse "versions" and "size" fields in any order. */
	for (;;) {
		CHECK(cfg_peektoken(pctx, 0));
		if (pctx->token.type == isc_tokentype_string) {
			CHECK(cfg_gettoken(pctx, 0));
			if (strcasecmp(TOKEN_STRING(pctx), "size") == 0 &&
			    obj->value.tuple[2] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[2].type,
						    &obj->value.tuple[2]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "versions") ==
					   0 &&
				   obj->value.tuple[3] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[3].type,
						    &obj->value.tuple[3]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "suffix") ==
					   0 &&
				   obj->value.tuple[4] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[4].type,
						    &obj->value.tuple[4]));
			} else {
				cfg_parser_error(pctx, CFG_LOG_NEAR,
						 "unexpected token");
				result = ISC_R_UNEXPECTEDTOKEN;
				goto cleanup;
			}
		} else {
			break;
		}
	}

	/* Create void objects for missing optional values. */
	if (obj->value.tuple[2] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[2]));
	}
	if (obj->value.tuple[3] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[3]));
	}
	if (obj->value.tuple[4] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[4]));
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static void
print_dtout(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	cfg_print_obj(pctx, obj->value.tuple[0]); /* mode */
	cfg_print_obj(pctx, obj->value.tuple[1]); /* file */
	if (obj->value.tuple[2]->type->methods.print != cfg_print_void) {
		cfg_print_cstr(pctx, " size ");
		cfg_print_obj(pctx, obj->value.tuple[2]);
	}
	if (obj->value.tuple[3]->type->methods.print != cfg_print_void) {
		cfg_print_cstr(pctx, " versions ");
		cfg_print_obj(pctx, obj->value.tuple[3]);
	}
	if (obj->value.tuple[4]->type->methods.print != cfg_print_void) {
		cfg_print_cstr(pctx, " suffix ");
		cfg_print_obj(pctx, obj->value.tuple[4]);
	}
}

static void
doc_dtout(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( file | unix ) <quoted_string>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ size ( unlimited | <size> ) ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ versions ( unlimited | <integer> ) ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ suffix ( increment | timestamp ) ]");
}

static const char *dtoutmode_enums[] = { "file", "unix", NULL };
static cfg_type_t cfg_type_dtmode = { .name = "dtmode",
				      .methods.parse = cfg_parse_enum,
				      .methods.print = cfg_print_ustring,
				      .methods.doc = cfg_doc_enum,
				      .rep = &cfg_rep_string,
				      .of = &dtoutmode_enums };

static cfg_tuplefielddef_t dtout_fields[] = {
	{ "mode", &cfg_type_dtmode, 0 },
	{ "path", &cfg_type_qstring, 0 },
	{ "size", &cfg_type_sizenodefault, 0 },
	{ "versions", &cfg_type_logversions, 0 },
	{ "suffix", &cfg_type_logsuffix, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_dnstapoutput = { .name = "dnstapoutput",
					    .methods.parse = parse_dtout,
					    .methods.print = print_dtout,
					    .methods.doc = doc_dtout,
					    .rep = &cfg_rep_tuple,
					    .of = dtout_fields };

/*%
 *  response-policy {
 *	zone &lt;string&gt; [ policy (given|disabled|passthru|drop|tcp-only|
 *					nxdomain|nodata|cname &lt;domain&gt; ) ]
 *		      [ recursive-only yes|no ] [ log yes|no ]
 *		      [ max-policy-ttl number ]
 *		      [ nsip-enable yes|no ] [ nsdname-enable yes|no ];
 *  } [ recursive-only yes|no ] [ max-policy-ttl number ]
 *	 [ min-update-interval number ]
 *	 [ break-dnssec yes|no ] [ min-ns-dots number ]
 *	 [ qname-wait-recurse yes|no ] [ servfail-until-ready yes|no ]
 *	 [ nsip-enable yes|no ] [ nsdname-enable yes|no ]
 */

static void
doc_rpz_policy(cfg_printer_t *pctx, const cfg_type_t *type) {
	const char *const *p;
	/*
	 * This is cfg_doc_enum() without the trailing " )".
	 */
	cfg_print_cstr(pctx, "( ");
	for (p = type->of; *p != NULL; p++) {
		cfg_print_cstr(pctx, *p);
		if (p[1] != NULL) {
			cfg_print_cstr(pctx, " | ");
		}
	}
}

static void
doc_rpz_cname(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_terminal(pctx, type);
	cfg_print_cstr(pctx, " )");
}

/*
 * Parse
 *	given|disabled|passthru|drop|tcp-only|nxdomain|nodata|cname <domain>
 */
static isc_result_t
cfg_parse_rpz_policy(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const cfg_tuplefielddef_t *fields;

	cfg_tuple_create(pctx, type, &obj);

	fields = type->of;
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));
	/*
	 * parse cname domain only after "policy cname"
	 */
	if (strcasecmp("cname", cfg_obj_asstring(obj->value.tuple[0])) != 0) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[1]));
	} else {
		CHECK(cfg_parse_obj(pctx, fields[1].type,
				    &obj->value.tuple[1]));
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

/*
 * Parse a tuple consisting of any kind of required field followed
 * by 2 or more optional keyvalues that can be in any order.
 */
static isc_result_t
cfg_parse_kv_tuple(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	const cfg_tuplefielddef_t *fields, *f;
	cfg_obj_t *obj = NULL;
	int fn;
	isc_result_t result;

	cfg_tuple_create(pctx, type, &obj);

	/*
	 * The zone first field is required and always first.
	 */
	fields = type->of;
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));

	for (;;) {
		CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
		if (pctx->token.type != isc_tokentype_string) {
			break;
		}

		for (fn = 1, f = &fields[1];; ++fn, ++f) {
			if (f->name == NULL) {
				cfg_parser_error(pctx, 0, "unexpected '%s'",
						 TOKEN_STRING(pctx));
				result = ISC_R_UNEXPECTEDTOKEN;
				goto cleanup;
			}
			if (obj->value.tuple[fn] == NULL &&
			    strcasecmp(f->name, TOKEN_STRING(pctx)) == 0)
			{
				break;
			}
		}

		CHECK(cfg_gettoken(pctx, 0));
		CHECK(cfg_parse_obj(pctx, f->type, &obj->value.tuple[fn]));
	}

	for (fn = 1, f = &fields[1]; f->name != NULL; ++fn, ++f) {
		if (obj->value.tuple[fn] == NULL) {
			CHECK(cfg_parse_void(pctx, NULL,
					     &obj->value.tuple[fn]));
		}
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static void
cfg_print_kv_tuple(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	unsigned int i;
	const cfg_tuplefielddef_t *fields, *f;
	const cfg_obj_t *fieldobj;

	fields = obj->type->of;
	for (f = fields, i = 0; f->name != NULL; f++, i++) {
		fieldobj = obj->value.tuple[i];
		if (fieldobj->type->methods.print == cfg_print_void) {
			continue;
		}
		if (i != 0) {
			cfg_print_cstr(pctx, " ");
			cfg_print_cstr(pctx, f->name);
			cfg_print_cstr(pctx, " ");
		}
		cfg_print_obj(pctx, fieldobj);
	}
}

static void
cfg_doc_kv_tuple(cfg_printer_t *pctx, const cfg_type_t *type) {
	const cfg_tuplefielddef_t *fields, *f;

	fields = type->of;
	for (f = fields; f->name != NULL; f++) {
		if ((f->flags & CFG_CLAUSEFLAG_NODOC) != 0) {
			continue;
		}
		if (f != fields) {
			cfg_print_cstr(pctx, " [ ");
			cfg_print_cstr(pctx, f->name);
			if (f->type->methods.doc != cfg_doc_void) {
				cfg_print_cstr(pctx, " ");
			}
		}
		cfg_doc_obj(pctx, f->type);
		if (f != fields) {
			cfg_print_cstr(pctx, " ]");
		}
	}
}

static keyword_type_t zone_kw = { "zone", &cfg_type_astring };
static cfg_type_t cfg_type_rpz_zone = { .name = "zone",
					.methods.parse = parse_keyvalue,
					.methods.print = print_keyvalue,
					.methods.doc = doc_keyvalue,
					.rep = &cfg_rep_string,
					.of = &zone_kw };
/*
 * "no-op" is an obsolete equivalent of "passthru".
 */
static const char *rpz_policies[] = { "cname",	  "disabled", "drop",
				      "given",	  "no-op",    "nodata",
				      "nxdomain", "passthru", "tcp-only",
				      NULL };
static cfg_type_t cfg_type_rpz_policy_name = { .name = "policy name",
					       .methods.parse = cfg_parse_enum,
					       .methods.print =
						       cfg_print_ustring,
					       .methods.doc = doc_rpz_policy,
					       .rep = &cfg_rep_string,
					       .of = &rpz_policies };
static cfg_type_t cfg_type_rpz_cname = { .name = "quoted_string",
					 .methods.parse = cfg_parse_astring,
					 NULL,
					 .methods.doc = doc_rpz_cname,
					 .rep = &cfg_rep_string,
					 .of = NULL };
static cfg_tuplefielddef_t rpz_policy_fields[] = {
	{ "policy name", &cfg_type_rpz_policy_name, 0 },
	{ "cname", &cfg_type_rpz_cname, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rpz_policy = { .name = "policy tuple",
					  .methods.parse = cfg_parse_rpz_policy,
					  .methods.print = cfg_print_tuple,
					  .methods.doc = cfg_doc_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = rpz_policy_fields };
static cfg_tuplefielddef_t rpz_zone_fields[] = {
	{ "zone name", &cfg_type_rpz_zone, 0 },
	{ "add-soa", &cfg_type_boolean, 0 },
	{ "log", &cfg_type_boolean, 0 },
	{ "max-policy-ttl", &cfg_type_duration, 0 },
	{ "min-update-interval", &cfg_type_duration, 0 },
	{ "policy", &cfg_type_rpz_policy, 0 },
	{ "recursive-only", &cfg_type_boolean, 0 },
	{ "nsip-enable", &cfg_type_boolean, 0 },
	{ "nsdname-enable", &cfg_type_boolean, 0 },
	{ "ede", &cfg_type_ustring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rpz_tuple = { .name = "rpz tuple",
					 .methods.parse = cfg_parse_kv_tuple,
					 .methods.print = cfg_print_kv_tuple,
					 .methods.doc = cfg_doc_kv_tuple,
					 .rep = &cfg_rep_tuple,
					 .of = rpz_zone_fields };
static cfg_type_t cfg_type_rpz_list = {
	.name = "zone list",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_rpz_tuple
};
static cfg_tuplefielddef_t rpz_fields[] = {
	{ "zone list", &cfg_type_rpz_list, 0 },
	{ "add-soa", &cfg_type_boolean, 0 },
	{ "break-dnssec", &cfg_type_boolean, 0 },
	{ "max-policy-ttl", &cfg_type_duration, 0 },
	{ "min-update-interval", &cfg_type_duration, 0 },
	{ "min-ns-dots", &cfg_type_uint32, 0 },
	{ "nsip-wait-recurse", &cfg_type_boolean, 0 },
	{ "nsdname-wait-recurse", &cfg_type_boolean, 0 },
	{ "qname-wait-recurse", &cfg_type_boolean, 0 },
	{ "recursive-only", &cfg_type_boolean, 0 },
	{ "servfail-until-ready", &cfg_type_boolean, 0 },
	{ "nsip-enable", &cfg_type_boolean, 0 },
	{ "nsdname-enable", &cfg_type_boolean, 0 },
	{ "dnsrps-enable", &cfg_type_boolean, CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnsrps-options", &cfg_type_bracketed_text, CFG_CLAUSEFLAG_OBSOLETE },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rpz = { .name = "rpz",
				   .methods.parse = cfg_parse_kv_tuple,
				   .methods.print = cfg_print_kv_tuple,
				   .methods.doc = cfg_doc_kv_tuple,
				   .rep = &cfg_rep_tuple,
				   .of = rpz_fields };

/*
 * Catalog zones
 */
static cfg_type_t cfg_type_catz_zone = { .name = "zone",
					 .methods.parse = parse_keyvalue,
					 .methods.print = print_keyvalue,
					 .methods.doc = doc_keyvalue,
					 .rep = &cfg_rep_string,
					 .of = &zone_kw };

static cfg_tuplefielddef_t catz_zone_fields[] = {
	{ "zone name", &cfg_type_catz_zone, 0 },
	{ "default-masters", &cfg_type_namesockaddrkeylist,
	  CFG_CLAUSEFLAG_NODOC },
	{ "default-primaries", &cfg_type_namesockaddrkeylist, 0 },
	{ "zone-directory", &cfg_type_qstring, 0 },
	{ "in-memory", &cfg_type_boolean, 0 },
	{ "min-update-interval", &cfg_type_duration, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_catz_tuple = { .name = "catz tuple",
					  .methods.parse = cfg_parse_kv_tuple,
					  .methods.print = cfg_print_kv_tuple,
					  .methods.doc = cfg_doc_kv_tuple,
					  .rep = &cfg_rep_tuple,
					  .of = catz_zone_fields };
static cfg_type_t cfg_type_catz_list = {
	.name = "zone list",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_catz_tuple
};
static cfg_tuplefielddef_t catz_fields[] = {
	{ "zone list", &cfg_type_catz_list, 0 }, { NULL, NULL, 0 }
};
static cfg_type_t cfg_type_catz = { .name = "catz",
				    .methods.parse = cfg_parse_kv_tuple,
				    .methods.print = cfg_print_kv_tuple,
				    .methods.doc = cfg_doc_kv_tuple,
				    .rep = &cfg_rep_tuple,
				    .of = catz_fields };

/*
 * rate-limit
 */
static cfg_clausedef_t rrl_clauses[] = {
	{ "all-per-second", &cfg_type_uint32, 0 },
	{ "errors-per-second", &cfg_type_uint32, 0 },
	{ "exempt-clients", &cfg_type_bracketed_aml, 0 },
	{ "ipv4-prefix-length", &cfg_type_uint32, 0 },
	{ "ipv6-prefix-length", &cfg_type_uint32, 0 },
	{ "log-only", &cfg_type_boolean, 0 },
	{ "max-table-size", &cfg_type_uint32, 0 },
	{ "min-table-size", &cfg_type_uint32, 0 },
	{ "nodata-per-second", &cfg_type_uint32, 0 },
	{ "nxdomains-per-second", &cfg_type_uint32, 0 },
	{ "qps-scale", &cfg_type_uint32, 0 },
	{ "referrals-per-second", &cfg_type_uint32, 0 },
	{ "responses-per-second", &cfg_type_uint32, 0 },
	{ "slip", &cfg_type_uint32, 0 },
	{ "window", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *rrl_clausesets[] = { rrl_clauses, NULL };

static cfg_type_t cfg_type_rrl = { .name = "rate-limit",
				   .methods.parse = cfg_parse_map,
				   .methods.print = cfg_print_map,
				   .methods.doc = cfg_doc_map,
				   .rep = &cfg_rep_map,
				   .of = rrl_clausesets };

static void
prefetch_merge(cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj) {
	cfg_obj_t *trigger = NULL;
	cfg_obj_t *eligible = NULL;

	trigger = (cfg_obj_t *)cfg_tuple_get(effectiveobj, "trigger");
	INSIST(cfg_obj_isuint32(trigger));
	if (cfg_obj_asuint32(trigger) > 10) {
		trigger->value.uint32 = 10;
	}

	eligible = (cfg_obj_t *)cfg_tuple_get(effectiveobj, "eligible");
	if (cfg_obj_isvoid(eligible)) {
		const cfg_obj_t *defaulteligible = NULL;

		defaulteligible = cfg_tuple_get(defaultobj, "eligible");
		INSIST(cfg_obj_isuint32(defaulteligible));

		eligible->value.uint32 = cfg_obj_asuint32(defaulteligible);
		eligible->type = &cfg_type_uint32;
	}

	INSIST(cfg_obj_isuint32(eligible));
	if (cfg_obj_asuint32(eligible) < cfg_obj_asuint32(trigger) + 6) {
		eligible->value.uint32 = cfg_obj_asuint32(trigger) + 6;
	}
}

static isc_result_t
parse_optional_uint32(cfg_parser_t *pctx, const cfg_type_t *type,
		      cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, ISC_LEXOPT_NUMBER | ISC_LEXOPT_CNUMBER));
	if (pctx->token.type == isc_tokentype_number) {
		CHECK(cfg_parse_obj(pctx, &cfg_type_uint32, ret));
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_void, ret));
	}
cleanup:
	return result;
}

static void
doc_optional_uint32(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ <integer> ]");
}

static cfg_type_t cfg_type_optional_uint32 = {
	.name = "optional_uint32",
	.methods.parse = parse_optional_uint32,
	.methods.doc = doc_optional_uint32,
};

static cfg_tuplefielddef_t prefetch_fields[] = {
	{ "trigger", &cfg_type_uint32, 0 },
	{ "eligible", &cfg_type_optional_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_prefetch = { .name = "prefetch",
					.methods.parse = cfg_parse_tuple,
					.methods.print = cfg_print_tuple,
					.methods.doc = cfg_doc_tuple,
					.methods.merge = prefetch_merge,
					.rep = &cfg_rep_tuple,
					.of = prefetch_fields };
/*
 * DNS64.
 */
static cfg_clausedef_t dns64_clauses[] = {
	{ "break-dnssec", &cfg_type_boolean, 0 },
	{ "clients", &cfg_type_bracketed_aml, 0 },
	{ "exclude", &cfg_type_bracketed_aml, 0 },
	{ "mapped", &cfg_type_bracketed_aml, 0 },
	{ "recursive-only", &cfg_type_boolean, 0 },
	{ "suffix", &cfg_type_netaddr6, 0 },
	{ NULL, NULL, 0 },
};

static cfg_clausedef_t *dns64_clausesets[] = { dns64_clauses, NULL };

static cfg_type_t cfg_type_dns64 = { .name = "dns64",
				     .methods.parse = cfg_parse_netprefix_map,
				     .methods.print = cfg_print_map,
				     .methods.doc = cfg_doc_map,
				     .rep = &cfg_rep_map,
				     .of = dns64_clausesets };

static const char *staleanswerclienttimeout_enums[] = { "disabled", "off",
							NULL };
static isc_result_t
parse_staleanswerclienttimeout(cfg_parser_t *pctx, const cfg_type_t *type,
			       cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_uint32, ret);
}

static void
doc_staleanswerclienttimeout(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_uint32);
}

static cfg_type_t cfg_type_staleanswerclienttimeout = {
	.name = "staleanswerclienttimeout",
	.methods.parse = parse_staleanswerclienttimeout,
	.methods.print = cfg_print_ustring,
	.methods.doc = doc_staleanswerclienttimeout,
	.rep = &cfg_rep_string,
	.of = staleanswerclienttimeout_enums
};

/*%
 * Clauses that can be found within the 'view' statement,
 * with defaults in the 'options' statement.
 */

static cfg_clausedef_t view_clauses[] = {
	{ "acache-cleaning-interval", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "acache-enable", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "additional-from-auth", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "additional-from-cache", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "allow-new-zones", &cfg_type_boolean, 0 },
	{ "allow-proxy", &cfg_type_bracketed_aml, CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "allow-proxy-on", &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "allow-query-cache", &cfg_type_bracketed_aml, 0 },
	{ "allow-query-cache-on", &cfg_type_bracketed_aml, 0 },
	{ "allow-recursion", &cfg_type_bracketed_aml, 0 },
	{ "allow-recursion-on", &cfg_type_bracketed_aml, 0 },
	{ "allow-v6-synthesis", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "attach-cache", &cfg_type_astring, 0 },
	{ "auth-nxdomain", &cfg_type_boolean, 0 },
	{ "cache-file", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "catalog-zones", &cfg_type_catz, 0 },
	{ "check-names", &cfg_type_checknames, CFG_CLAUSEFLAG_MULTI },
	{ "cleaning-interval", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "clients-per-query", &cfg_type_uint32, 0 },
	{ "deny-answer-addresses", &cfg_type_denyaddresses, 0 },
	{ "deny-answer-aliases", &cfg_type_denyaliases, 0 },
	{ "disable-algorithms", &cfg_type_disablealgorithm,
	  CFG_CLAUSEFLAG_MULTI },
	{ "disable-ds-digests", &cfg_type_disabledsdigest,
	  CFG_CLAUSEFLAG_MULTI },
	{ "disable-empty-zone", &cfg_type_astring, CFG_CLAUSEFLAG_MULTI },
	{ "dns64", &cfg_type_dns64, CFG_CLAUSEFLAG_MULTI },
	{ "dns64-contact", &cfg_type_astring, 0 },
	{ "dns64-server", &cfg_type_astring, 0 },
	{ "dnsrps-enable", &cfg_type_boolean, CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnsrps-options", &cfg_type_bracketed_text, CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnssec-accept-expired", &cfg_type_boolean, 0 },
	{ "dnssec-enable", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "dnssec-lookaside", NULL,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ "dnssec-must-be-secure", NULL,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT },
	{ "dnssec-validation", &cfg_type_boolorauto, 0 },
#ifdef HAVE_DNSTAP
	{ "dnstap", &cfg_type_dnstap, CFG_CLAUSEFLAG_OPTIONAL },
#else  /* ifdef HAVE_DNSTAP */
	{ "dnstap", &cfg_type_dnstap, CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif /* HAVE_DNSTAP */
	{ "dual-stack-servers", &cfg_type_nameportiplist, 0 },
	{ "edns-udp-size", &cfg_type_uint32, 0 },
	{ "empty-contact", &cfg_type_astring, 0 },
	{ "empty-server", &cfg_type_astring, 0 },
	{ "empty-zones-enable", &cfg_type_boolean, 0 },
	{ "fetch-glue", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "fetch-quota-params", &cfg_type_fetchquota, 0 },
	{ "fetches-per-server", &cfg_type_fetchesper, 0 },
	{ "fetches-per-zone", &cfg_type_fetchesper, 0 },
	{ "filter-aaaa", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "filter-aaaa-on-v4", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "filter-aaaa-on-v6", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "glue-cache", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "ipv4only-enable", &cfg_type_boolean, 0 },
	{ "ipv4only-contact", &cfg_type_astring, 0 },
	{ "ipv4only-server", &cfg_type_astring, 0 },
	{ "ixfr-from-differences", &cfg_type_ixfrdifftype, 0 },
	{ "lame-ttl", &cfg_type_duration, 0 },
#ifdef HAVE_LMDB
	{ "lmdb-mapsize", &cfg_type_sizeval, CFG_CLAUSEFLAG_OPTIONAL },
#else  /* ifdef HAVE_LMDB */
	{ "lmdb-mapsize", &cfg_type_sizeval, CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif /* ifdef HAVE_LMDB */
	{ "max-acache-size", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "max-cache-size", &cfg_type_maxcachesize, 0 },
	{ "max-cache-ttl", &cfg_type_duration, 0 },
	{ "max-clients-per-query", &cfg_type_uint32, 0 },
	{ "max-ncache-ttl", &cfg_type_duration, 0 },
	{ "max-recursion-depth", &cfg_type_uint32, 0 },
	{ "max-recursion-queries", &cfg_type_uint32, 0 },
	{ "max-query-count", &cfg_type_uint32, 0 },
	{ "max-query-restarts", &cfg_type_uint32, 0 },
	{ "max-stale-ttl", &cfg_type_duration, 0 },
	{ "max-udp-size", &cfg_type_uint32, 0 },
	{ "max-validations-per-fetch", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "max-validation-failures-per-fetch", &cfg_type_uint32,
	  CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "message-compression", &cfg_type_boolean, 0 },
	{ "min-cache-ttl", &cfg_type_duration, 0 },
	{ "min-ncache-ttl", &cfg_type_duration, 0 },
	{ "min-roots", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "minimal-any", &cfg_type_boolean, 0 },
	{ "minimal-responses", &cfg_type_minimal, 0 },
	{ "new-zones-directory", &cfg_type_qstring, 0 },
	{ "no-case-compress", &cfg_type_bracketed_aml, 0 },
	{ "nocookie-udp-size", &cfg_type_uint32, 0 },
	{ "nosit-udp-size", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "nta-lifetime", &cfg_type_duration, 0 },
	{ "nta-recheck", &cfg_type_duration, 0 },
	{ "nxdomain-redirect", &cfg_type_astring, 0 },
	{ "preferred-glue", &cfg_type_astring, 0 },
	{ "prefetch", &cfg_type_prefetch, 0 },
	{ "provide-ixfr", &cfg_type_boolean, 0 },
	{ "qname-minimization", &cfg_type_qminmethod, 0 },
	/*
	 * Note that the query-source option syntax is different
	 * from the other -source options.
	 */
	{ "query-source", &cfg_type_querysource4, 0 },
	{ "query-source-v6", &cfg_type_querysource6, 0 },
	{ "queryport-pool-ports", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "queryport-pool-updateinterval", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "rate-limit", &cfg_type_rrl, 0 },
	{ "recursion", &cfg_type_boolean, 0 },
	{ "request-nsid", &cfg_type_boolean, 0 },
	{ "request-sit", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "request-zoneversion", &cfg_type_boolean, 0 },
	{ "require-server-cookie", &cfg_type_boolean, 0 },
	{ "resolver-nonbackoff-tries", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "resolver-query-timeout", &cfg_type_uint32, 0 },
	{ "resolver-retry-interval", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "response-padding", &cfg_type_resppadding, 0 },
	{ "response-policy", &cfg_type_rpz, 0 },
	{ "rfc2308-type1", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "root-delegation-only", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "root-key-sentinel", &cfg_type_boolean, 0 },
	{ "rrset-order", &cfg_type_rrsetorder, 0 },
	{ "send-cookie", &cfg_type_boolean, 0 },
	{ "servfail-ttl", &cfg_type_duration, 0 },
	{ "sig0key-checks-limit", &cfg_type_uint32, 0 },
	{ "sig0message-checks-limit", &cfg_type_uint32, 0 },
	{ "sortlist", &cfg_type_bracketed_aml, CFG_CLAUSEFLAG_ANCIENT },
	{ "stale-answer-enable", &cfg_type_boolean, 0 },
	{ "stale-answer-client-timeout", &cfg_type_staleanswerclienttimeout,
	  0 },
	{ "stale-answer-ttl", &cfg_type_duration, 0 },
	{ "stale-cache-enable", &cfg_type_boolean, 0 },
	{ "stale-refresh-time", &cfg_type_duration, 0 },
	{ "suppress-initial-notify", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "synth-from-dnssec", &cfg_type_boolean, 0 },
	{ "topology", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "transfer-format", &cfg_type_transferformat, 0 },
	{ "trust-anchor-telemetry", &cfg_type_boolean, 0 },
	{ "resolver-use-dns64", &cfg_type_boolean, 0 },
	{ "use-queryport-pool", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "validate-except", &cfg_type_namelist, 0 },
	{ "v6-bias", &cfg_type_uint32, 0 },
	{ "zero-no-soa-ttl-cache", &cfg_type_boolean, 0 },
	{ NULL, NULL, 0 }
};

/*%
 * Clauses that can be found within the 'view' statement only.
 */
static cfg_clausedef_t view_only_clauses[] = {
	{ "match-clients", &cfg_type_bracketed_aml, 0 },
	{ "match-destinations", &cfg_type_bracketed_aml, 0 },
	{ "match-recursive-only", &cfg_type_boolean, 0 },
	{ NULL, NULL, 0 }
};

/*%
 * Sig-validity-interval.
 */

static cfg_tuplefielddef_t validityinterval_fields[] = {
	{ "validity", &cfg_type_uint32, 0 },
	{ "re-sign", &cfg_type_optional_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_validityinterval = {
	.name = "validityinterval",
	.methods.parse = cfg_parse_tuple,
	.methods.print = cfg_print_tuple,
	.methods.doc = cfg_doc_tuple,
	.rep = &cfg_rep_tuple,
	.of = validityinterval_fields
};

/*%
 * Checkds type.
 */
static const char *checkds_enums[] = { "explicit", NULL };
static isc_result_t
parse_checkds_type(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_checkds_type(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_checkdstype = {
	.name = "checkdstype",
	.methods.parse = parse_checkds_type,
	.methods.print = cfg_print_ustring,
	.methods.doc = doc_checkds_type,
	.rep = &cfg_rep_string,
	.of = checkds_enums,
};

/*%
 * Clauses that can be found in a 'dnssec-policy' statement.
 */
static cfg_clausedef_t dnssecpolicy_clauses[] = {
	{ "cdnskey", &cfg_type_boolean, 0 },
	{ "cds-digest-types", &cfg_type_algorithmlist, 0 },
	{ "dnskey-ttl", &cfg_type_duration, 0 },
	{ "inline-signing", &cfg_type_boolean, 0 },
	{ "keys", &cfg_type_kaspkeys, 0 },
	{ "manual-mode", &cfg_type_boolean, 0 },
	{ "max-zone-ttl", &cfg_type_duration, 0 },
	{ "nsec3param", &cfg_type_nsec3, 0 },
	{ "offline-ksk", &cfg_type_boolean, 0 },
	{ "parent-ds-ttl", &cfg_type_duration, 0 },
	{ "parent-propagation-delay", &cfg_type_duration, 0 },
	{ "parent-registration-delay", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "publish-safety", &cfg_type_duration, 0 },
	{ "purge-keys", &cfg_type_duration, 0 },
	{ "retire-safety", &cfg_type_duration, 0 },
	{ "signatures-jitter", &cfg_type_duration, 0 },
	{ "signatures-refresh", &cfg_type_duration, 0 },
	{ "signatures-validity", &cfg_type_duration, 0 },
	{ "signatures-validity-dnskey", &cfg_type_duration, 0 },
	{ "zone-propagation-delay", &cfg_type_duration, 0 },
	{ NULL, NULL, 0 }
};

/*
 * For min-transfer-rate-in.
 */
static cfg_tuplefielddef_t min_transfer_rate_fields[] = {
	{ "traffic_bytes", &cfg_type_uint32, 0 },
	{ "time_minutes", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_min_transfer_rate_in = {
	.name = "min-transfer-rate-"
		"in",
	.methods.parse = cfg_parse_tuple,
	.methods.print = cfg_print_tuple,
	.methods.doc = cfg_doc_tuple,
	.rep = &cfg_rep_tuple,
	.of = min_transfer_rate_fields
};

/*%
 * Clauses that can be found in a 'zone' statement,
 * with defaults in the 'view' or 'options' statement.
 *
 * Note: CFG_ZONE_* options indicate in which zone types this clause is
 * legal.
 */
/*
 * NOTE: To enable syntax which allows specifying port and protocol
 * within 'allow-*' clauses, replace 'cfg_type_bracketed_aml' with
 * 'cfg_type_transport_acl'.
 *
 * Example: allow-transfer port 853 protocol tls { ... };
 */
static cfg_clausedef_t zone_clauses[] = {
	{ "allow-notify", &cfg_type_bracketed_aml,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "allow-query", &cfg_type_bracketed_aml,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT | CFG_ZONE_STATICSTUB },
	{ "allow-query-on", &cfg_type_bracketed_aml,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT | CFG_ZONE_STATICSTUB },
	{ "allow-transfer", &cfg_type_transport_acl,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "allow-update", &cfg_type_bracketed_aml, CFG_ZONE_PRIMARY },
	{ "allow-update-forwarding", &cfg_type_bracketed_aml,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "also-notify", &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "alt-transfer-source", NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_CLAUSEFLAG_ANCIENT },
	{ "alt-transfer-source-v6", NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_CLAUSEFLAG_ANCIENT },
	{ "auto-dnssec", NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_ANCIENT },
	{ "check-dup-records", &cfg_type_checkmode, CFG_ZONE_PRIMARY },
	{ "check-integrity", &cfg_type_boolean, CFG_ZONE_PRIMARY },
	{ "check-mx", &cfg_type_checkmode, CFG_ZONE_PRIMARY },
	{ "check-mx-cname", &cfg_type_checkmode, CFG_ZONE_PRIMARY },
	{ "check-sibling", &cfg_type_boolean, CFG_ZONE_PRIMARY },
	{ "check-spf", &cfg_type_warn, CFG_ZONE_PRIMARY },
	{ "check-srv-cname", &cfg_type_checkmode, CFG_ZONE_PRIMARY },
	{ "check-svcb", &cfg_type_boolean, CFG_ZONE_PRIMARY },
	{ "check-wildcard", &cfg_type_boolean, CFG_ZONE_PRIMARY },
	{ "dialup", NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_STUB |
		  CFG_CLAUSEFLAG_ANCIENT },
	{ "dnssec-dnskey-kskonly", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnssec-loadkeys-interval", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "dnssec-policy", &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "dnssec-secure-to-insecure", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnssec-update-mode", &cfg_type_dnssecupdatemode,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE },
	{ "forward", &cfg_type_forwardtype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_STUB |
		  CFG_ZONE_STATICSTUB | CFG_ZONE_FORWARD },
	{ "forwarders", &cfg_type_portiplist,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_STUB |
		  CFG_ZONE_STATICSTUB | CFG_ZONE_FORWARD },
	{ "key-directory", &cfg_type_qstring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "maintain-ixfr-base", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "masterfile-format", &cfg_type_masterformat,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT },
	{ "masterfile-style", &cfg_type_masterstyle,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT },
	{ "max-ixfr-log-size", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "max-ixfr-ratio", &cfg_type_ixfrratio,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "max-journal-size", &cfg_type_size,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "max-records", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT },
	{ "max-records-per-type", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT },
	{ "max-types-per-name", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT },
	{ "max-refresh-time", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "max-retry-time", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "min-transfer-rate-in", &cfg_type_min_transfer_rate_in,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "max-transfer-idle-in", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "max-transfer-idle-out", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_MIRROR | CFG_ZONE_SECONDARY },
	{ "max-transfer-time-in", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "max-transfer-time-out", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_MIRROR | CFG_ZONE_SECONDARY },
	{ "max-zone-ttl", &cfg_type_maxduration,
	  CFG_ZONE_PRIMARY | CFG_ZONE_REDIRECT | CFG_CLAUSEFLAG_DEPRECATED },
	{ "min-refresh-time", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "min-retry-time", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "multi-master", &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "notify", &cfg_type_notifytype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "notify-defer", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "notify-delay", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "notify-source", &cfg_type_sockaddr4wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "notify-source-v6", &cfg_type_sockaddr6wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "notify-to-soa", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "nsec3-test-zone", &cfg_type_boolean,
	  CFG_CLAUSEFLAG_TESTONLY | CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "parental-source", &cfg_type_sockaddr4wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "parental-source-v6", &cfg_type_sockaddr6wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "provide-zoneversion", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "send-report-channel", &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "request-expire", &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "request-ixfr", &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "request-ixfr-max-diffs", &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "serial-update-method", &cfg_type_updatemethod, CFG_ZONE_PRIMARY },
	{ "sig-signing-nodes", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "sig-signing-signatures", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "sig-signing-type", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "sig-validity-interval", &cfg_type_validityinterval,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnskey-sig-validity", &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE },
	{ "transfer-source", &cfg_type_sockaddr4wild,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "transfer-source-v6", &cfg_type_sockaddr6wild,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB },
	{ "try-tcp-refresh", &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "update-check-ksk", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE },
	{ "use-alt-transfer-source", NULL,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB |
		  CFG_CLAUSEFLAG_ANCIENT },
	{ "zero-no-soa-ttl", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "zone-statistics", &cfg_type_zonestat,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT },
	{ NULL, NULL, 0 }
};

/*%
 * Clauses that can be found in a 'zone' statement only.
 *
 * Note: CFG_ZONE_* options indicate in which zone types this clause is
 * legal.
 */
static cfg_clausedef_t zone_only_clauses[] = {
	/*
	 * Note that the format of the check-names option is different between
	 * the zone options and the global/view options.  Ugh.
	 */
	{ "type", &cfg_type_zonetype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_HINT |
		  CFG_ZONE_REDIRECT | CFG_ZONE_FORWARD },
	{ "check-names", &cfg_type_checkmode,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_HINT | CFG_ZONE_STUB },
	{ "checkds", &cfg_type_checkdstype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "database", &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB },
	{ "delegation-only", NULL,
	  CFG_ZONE_HINT | CFG_ZONE_STUB | CFG_ZONE_FORWARD |
		  CFG_CLAUSEFLAG_ANCIENT },
	{ "dlz", &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_REDIRECT },
	{ "file", &cfg_type_qstring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_HINT | CFG_ZONE_REDIRECT },
	{ "initial-file", &cfg_type_qstring, CFG_ZONE_PRIMARY },
	{ "inline-signing", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "ixfr-base", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "ixfr-from-differences", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "ixfr-tmp-file", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "journal", &cfg_type_qstring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR },
	{ "log-report-channel", &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "masters", &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB |
		  CFG_ZONE_REDIRECT | CFG_CLAUSEFLAG_NODOC },
	{ "parental-agents", &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY },
	{ "plugin", &cfg_type_plugin,
	  CFG_CLAUSEFLAG_MULTI | CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY |
		  CFG_ZONE_REDIRECT | CFG_ZONE_MIRROR },
	{ "primaries", &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB |
		  CFG_ZONE_REDIRECT },
	{ "pubkey", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "server-addresses", &cfg_type_bracketed_netaddrlist,
	  CFG_ZONE_STATICSTUB },
	{ "server-names", &cfg_type_namelist, CFG_ZONE_STATICSTUB },
	{ "update-policy", &cfg_type_updatepolicy, CFG_ZONE_PRIMARY },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t non_template_clauses[] = {
	{ "in-view", &cfg_type_astring, CFG_ZONE_INVIEW },
	{ "template", &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_HINT |
		  CFG_ZONE_REDIRECT | CFG_ZONE_FORWARD },
	{ NULL, NULL, 0 }
};

/*% The top-level named.conf syntax. */

static cfg_clausedef_t *namedconf_clausesets[] = { namedconf_clauses,
						   namedconf_or_view_clauses,
						   NULL };
cfg_type_t cfg_type_namedconf = { .name = "namedconf",
				  .methods.parse = cfg_parse_mapbody,
				  .methods.print = cfg_print_mapbody,
				  .methods.doc = cfg_doc_mapbody,
				  .rep = &cfg_rep_map,
				  .of = namedconf_clausesets };

/*% The bind.keys syntax (trust-anchors). */
static cfg_clausedef_t *bindkeys_clausesets[] = { bindkeys_clauses, NULL };
cfg_type_t cfg_type_bindkeys = { .name = "bindkeys",
				 .methods.parse = cfg_parse_mapbody,
				 .methods.print = cfg_print_mapbody,
				 .methods.doc = cfg_doc_mapbody,
				 .rep = &cfg_rep_map,
				 .of = bindkeys_clausesets };

/*% The "options" statement syntax. */

static cfg_clausedef_t *options_clausesets[] = { options_clauses, view_clauses,
						 zone_clauses, NULL };
static cfg_type_t cfg_type_options = { .name = "options",
				       .methods.parse = cfg_parse_map,
				       .methods.print = cfg_print_map,
				       .methods.doc = cfg_doc_map,
				       .methods.merge = options_merge,
				       .rep = &cfg_rep_map,
				       .of = options_clausesets };

/*% The "view" statement syntax. */

static cfg_clausedef_t *view_clausesets[] = { view_only_clauses,
					      namedconf_or_view_clauses,
					      view_clauses, zone_clauses,
					      NULL };

static cfg_type_t cfg_type_viewopts = { .name = "view",
					.methods.parse = cfg_parse_map,
					.methods.print = cfg_print_map,
					.methods.doc = cfg_doc_map,
					.rep = &cfg_rep_map,
					.of = view_clausesets };

/*% The "zone" statement syntax. */

static cfg_clausedef_t *zone_clausesets[] = { non_template_clauses,
					      zone_only_clauses, zone_clauses,
					      NULL };
cfg_type_t cfg_type_zoneopts = { .name = "zoneopts",
				 .methods.parse = cfg_parse_map,
				 .methods.print = cfg_print_map,
				 .methods.doc = cfg_doc_map,
				 .rep = &cfg_rep_map,
				 .of = zone_clausesets };

/*%
 * The "template" statement syntax: any clause that "zone" can take,
 * except that zones can have a "template" option and templates cannot.
 */

static cfg_clausedef_t *template_clausesets[] = { zone_only_clauses,
						  zone_clauses, NULL };
static cfg_type_t cfg_type_templateopts = { .name = "templateopts",
					    .methods.parse = cfg_parse_map,
					    .methods.print = cfg_print_map,
					    .methods.doc = cfg_doc_map,
					    .rep = &cfg_rep_map,
					    .of = template_clausesets };

/*% The "dnssec-policy" statement syntax. */
static cfg_clausedef_t *dnssecpolicy_clausesets[] = { dnssecpolicy_clauses,
						      NULL };
cfg_type_t cfg_type_dnssecpolicyopts = { .name = "dnssecpolicyopts",
					 .methods.parse = cfg_parse_map,
					 .methods.print = cfg_print_map,
					 .methods.doc = cfg_doc_map,
					 .rep = &cfg_rep_map,
					 .of = dnssecpolicy_clausesets };

/*% The "dynamically loadable zones" statement syntax. */

static cfg_clausedef_t dlz_clauses[] = { { "database", &cfg_type_astring, 0 },
					 { "search", &cfg_type_boolean, 0 },
					 { NULL, NULL, 0 } };
static cfg_clausedef_t *dlz_clausesets[] = { dlz_clauses, NULL };
static cfg_type_t cfg_type_dlz = { .name = "dlz",
				   .methods.parse = cfg_parse_named_map,
				   .methods.print = cfg_print_map,
				   .methods.doc = cfg_doc_map,
				   .rep = &cfg_rep_map,
				   .of = dlz_clausesets };

/*%
 * The "dyndb" statement syntax.
 */

static cfg_tuplefielddef_t dyndb_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "library", &cfg_type_qstring, 0 },
	{ "parameters", &cfg_type_bracketed_text, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_dyndb = { .name = "dyndb",
				     .methods.parse = cfg_parse_tuple,
				     .methods.print = cfg_print_tuple,
				     .methods.doc = cfg_doc_tuple,
				     .rep = &cfg_rep_tuple,
				     .of = dyndb_fields };

/*%
 * The "plugin" statement syntax.
 * Currently only one plugin type is supported: query.
 */

static const char *plugin_enums[] = { "query", NULL };
static cfg_type_t cfg_type_plugintype = { .name = "plugintype",
					  .methods.parse = cfg_parse_enum,
					  .methods.print = cfg_print_ustring,
					  .methods.doc = cfg_doc_enum,
					  .rep = &cfg_rep_string,
					  .of = plugin_enums };
static cfg_tuplefielddef_t plugin_fields[] = {
	{ "type", &cfg_type_plugintype, 0 },
	{ "library", &cfg_type_astring, 0 },
	{ "parameters", &cfg_type_optional_bracketed_text, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_plugin = { .name = "plugin",
				      .methods.parse = cfg_parse_tuple,
				      .methods.print = cfg_print_tuple,
				      .methods.doc = cfg_doc_tuple,
				      .rep = &cfg_rep_tuple,
				      .of = plugin_fields };

/*%
 * Clauses that can be found within the 'key' statement.
 */
static cfg_clausedef_t key_clauses[] = { { "algorithm", &cfg_type_astring, 0 },
					 { "secret", &cfg_type_sstring, 0 },
					 { NULL, NULL, 0 } };

static cfg_clausedef_t *key_clausesets[] = { key_clauses, NULL };
static cfg_type_t cfg_type_key = { .name = "key",
				   .methods.parse = cfg_parse_named_map,
				   .methods.print = cfg_print_map,
				   .methods.doc = cfg_doc_map,
				   .rep = &cfg_rep_map,
				   .of = key_clausesets };

/*%
 * A key-store statement.
 */
static cfg_clausedef_t keystore_clauses[] = {
	{ "directory", &cfg_type_astring, 0 },
	{ "pkcs11-uri", &cfg_type_qstring, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *keystore_clausesets[] = { keystore_clauses, NULL };
static cfg_type_t cfg_type_keystoreopts = { .name = "keystoreopts",
					    .methods.parse = cfg_parse_map,
					    .methods.print = cfg_print_map,
					    .methods.doc = cfg_doc_map,
					    .rep = &cfg_rep_map,
					    .of = keystore_clausesets };

static cfg_tuplefielddef_t keystore_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "options", &cfg_type_keystoreopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_keystore = { .name = "key-store",
					.methods.parse = cfg_parse_tuple,
					.methods.print = cfg_print_tuple,
					.methods.doc = cfg_doc_tuple,
					.rep = &cfg_rep_tuple,
					.of = keystore_fields };

/*%
 * Clauses that can be found in a 'server' statement.
 *
 * Please update lib/isccfg/check.c and
 * bin/tests/system/checkconf/good-server-christmas-tree.conf.in to
 * exercise the new clause when adding new clauses.
 */
static cfg_clausedef_t server_clauses[] = {
	{ "bogus", &cfg_type_boolean, 0 },
	{ "edns", &cfg_type_boolean, 0 },
	{ "edns-udp-size", &cfg_type_uint32, 0 },
	{ "edns-version", &cfg_type_uint32, 0 },
	{ "keys", &cfg_type_server_key_kludge, 0 },
	{ "max-udp-size", &cfg_type_uint32, 0 },
	{ "notify-source", &cfg_type_sockaddr4wild, 0 },
	{ "notify-source-v6", &cfg_type_sockaddr6wild, 0 },
	{ "padding", &cfg_type_uint32, 0 },
	{ "provide-ixfr", &cfg_type_boolean, 0 },
	{ "query-source", &cfg_type_server_querysource4, 0 },
	{ "query-source-v6", &cfg_type_server_querysource6, 0 },
	{ "request-expire", &cfg_type_boolean, 0 },
	{ "request-ixfr", &cfg_type_boolean, 0 },
	{ "request-ixfr-max-diffs", &cfg_type_uint32, 0 },
	{ "request-nsid", &cfg_type_boolean, 0 },
	{ "request-zoneversion", &cfg_type_boolean, 0 },
	{ "request-sit", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "require-cookie", &cfg_type_boolean, 0 },
	{ "send-cookie", &cfg_type_boolean, 0 },
	{ "support-ixfr", NULL, CFG_CLAUSEFLAG_ANCIENT },
	{ "tcp-keepalive", &cfg_type_boolean, 0 },
	{ "tcp-only", &cfg_type_boolean, 0 },
	{ "transfer-format", &cfg_type_transferformat, 0 },
	{ "transfer-source", &cfg_type_sockaddr4wild, 0 },
	{ "transfer-source-v6", &cfg_type_sockaddr6wild, 0 },
	{ "transfers", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};
static cfg_clausedef_t *server_clausesets[] = { server_clauses, NULL };
static cfg_type_t cfg_type_server = { .name = "server",
				      .methods.parse = cfg_parse_netprefix_map,
				      .methods.print = cfg_print_map,
				      .methods.doc = cfg_doc_map,
				      .rep = &cfg_rep_map,
				      .of = server_clausesets };

/*%
 * Clauses that can be found in a 'channel' clause in the
 * 'logging' statement.
 *
 * These have some additional constraints that need to be
 * checked after parsing:
 *  - There must exactly one of file/syslog/null/stderr
 */

static const char *printtime_enums[] = { "iso8601", "iso8601-utc",
					 "iso8601-tzinfo", "local", NULL };
static isc_result_t
parse_printtime(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_printtime(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_printtime = { .name = "printtime",
					 .methods.parse = parse_printtime,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = doc_printtime,
					 .rep = &cfg_rep_string,
					 .of = printtime_enums };

static cfg_clausedef_t channel_clauses[] = {
	/* Destinations.  We no longer require these to be first. */
	{ "file", &cfg_type_logfile, 0 },
	{ "syslog", &cfg_type_optional_facility, 0 },
	{ "null", &cfg_type_void, 0 },
	{ "stderr", &cfg_type_void, 0 },
	/* Options.  We now accept these for the null channel, too. */
	{ "severity", &cfg_type_logseverity, 0 },
	{ "print-time", &cfg_type_printtime, 0 },
	{ "print-severity", &cfg_type_boolean, 0 },
	{ "print-category", &cfg_type_boolean, 0 },
	{ "buffered", &cfg_type_boolean, 0 },
	{ NULL, NULL, 0 }
};
static cfg_clausedef_t *channel_clausesets[] = { channel_clauses, NULL };
static cfg_type_t cfg_type_channel = { .name = "channel",
				       .methods.parse = cfg_parse_named_map,
				       .methods.print = cfg_print_map,
				       .methods.doc = cfg_doc_map,
				       .rep = &cfg_rep_map,
				       .of = channel_clausesets };

/*% A list of log destination, used in the "category" clause. */
static cfg_type_t cfg_type_destinationlist = {
	.name = "destinationlist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_astring
};

/*%
 * Clauses that can be found in a 'logging' statement.
 */
static cfg_clausedef_t logging_clauses[] = {
	{ "channel", &cfg_type_channel, CFG_CLAUSEFLAG_MULTI },
	{ "category", &cfg_type_category, CFG_CLAUSEFLAG_MULTI },
	{ NULL, NULL, 0 }
};
static cfg_clausedef_t *logging_clausesets[] = { logging_clauses, NULL };
static cfg_type_t cfg_type_logging = { .name = "logging",
				       .methods.parse = cfg_parse_map,
				       .methods.print = cfg_print_map,
				       .methods.doc = cfg_doc_map,
				       .rep = &cfg_rep_map,
				       .of = logging_clausesets };

/*%
 * For parsing an 'addzone' statement
 */
static cfg_tuplefielddef_t addzone_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "class", &cfg_type_optional_class, 0 },
	{ "view", &cfg_type_optional_class, 0 },
	{ "options", &cfg_type_zoneopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_addzone = { .name = "zone",
				       .methods.parse = cfg_parse_tuple,
				       .methods.print = cfg_print_tuple,
				       .methods.doc = cfg_doc_tuple,
				       .rep = &cfg_rep_tuple,
				       .of = addzone_fields };

static cfg_clausedef_t addzoneconf_clauses[] = {
	{ "zone", &cfg_type_addzone, CFG_CLAUSEFLAG_MULTI }, { NULL, NULL, 0 }
};

static cfg_clausedef_t *addzoneconf_clausesets[] = { addzoneconf_clauses,
						     NULL };

cfg_type_t cfg_type_addzoneconf = { .name = "addzoneconf",
				    .methods.parse = cfg_parse_mapbody,
				    .methods.print = cfg_print_mapbody,
				    .methods.doc = cfg_doc_mapbody,
				    .rep = &cfg_rep_map,
				    .of = addzoneconf_clausesets };

static isc_result_t
parse_unitstring(char *str, uint64_t *valuep) {
	char *endp;
	unsigned int len;
	uint64_t value;
	uint64_t unit;

	value = strtoull(str, &endp, 10);
	if (*endp == 0) {
		*valuep = value;
		return ISC_R_SUCCESS;
	}

	len = strlen(str);
	if (len < 2 || endp[1] != '\0') {
		return ISC_R_FAILURE;
	}

	switch (str[len - 1]) {
	case 'k':
	case 'K':
		unit = 1024;
		break;
	case 'm':
	case 'M':
		unit = 1024 * 1024;
		break;
	case 'g':
	case 'G':
		unit = 1024 * 1024 * 1024;
		break;
	default:
		return ISC_R_FAILURE;
	}
	if (value > ((uint64_t)UINT64_MAX / unit)) {
		return ISC_R_FAILURE;
	}
	*valuep = value * unit;
	return ISC_R_SUCCESS;
}

static isc_result_t
parse_sizeval(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	uint64_t val;

	UNUSED(type);

	CHECK(cfg_gettoken(pctx, 0));
	if (pctx->token.type != isc_tokentype_string) {
		result = ISC_R_UNEXPECTEDTOKEN;
		goto cleanup;
	}
	CHECK(parse_unitstring(TOKEN_STRING(pctx), &val));

	cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx), pctx->line,
		       &cfg_type_uint64, &obj);
	obj->value.uint64 = val;
	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	cfg_parser_error(pctx, CFG_LOG_NEAR,
			 "expected integer and optional unit");
	return result;
}

static isc_result_t
parse_sizeval_percent(cfg_parser_t *pctx, const cfg_type_t *type,
		      cfg_obj_t **ret) {
	char *endp;
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	uint64_t val;
	uint64_t percent;

	UNUSED(type);

	CHECK(cfg_gettoken(pctx, 0));
	if (pctx->token.type != isc_tokentype_string) {
		result = ISC_R_UNEXPECTEDTOKEN;
		goto cleanup;
	}

	percent = strtoull(TOKEN_STRING(pctx), &endp, 10);

	if (*endp == '%' && *(endp + 1) == 0) {
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_percentage, &obj);
		obj->value.uint32 = (uint32_t)percent;
		*ret = obj;
		return ISC_R_SUCCESS;
	} else {
		CHECK(parse_unitstring(TOKEN_STRING(pctx), &val));
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_uint64, &obj);
		obj->value.uint64 = val;
		*ret = obj;
		return ISC_R_SUCCESS;
	}

cleanup:
	cfg_parser_error(pctx, CFG_LOG_NEAR,
			 "expected integer and optional unit or percent");
	return result;
}

static void
doc_sizeval_percent(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);

	cfg_print_cstr(pctx, "( ");
	cfg_doc_terminal(pctx, &cfg_type_size);
	cfg_print_cstr(pctx, " | ");
	cfg_doc_terminal(pctx, &cfg_type_percentage);
	cfg_print_cstr(pctx, " )");
}

/*%
 * A size value (number + optional unit).
 */
static cfg_type_t cfg_type_sizeval = {
	.name = "sizeval",
	.methods.parse = parse_sizeval,
	.methods.print = cfg_print_uint64,
	.methods.doc = cfg_doc_terminal,
	.rep = &cfg_rep_uint64,
};

/*%
 * A size, "unlimited", or "default".
 */

static isc_result_t
parse_size(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_sizeval, ret);
}

static void
doc_size(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_sizeval);
}

static const char *size_enums[] = { "default", "unlimited", NULL };
static cfg_type_t cfg_type_size = { .name = "size",
				    .methods.parse = parse_size,
				    .methods.print = cfg_print_ustring,
				    .methods.doc = doc_size,
				    .rep = &cfg_rep_string,
				    .of = size_enums };

/*%
 * A size or "unlimited", but not "default".
 */
static const char *sizenodefault_enums[] = { "unlimited", NULL };
static cfg_type_t cfg_type_sizenodefault = { .name = "size_no_default",
					     .methods.parse = parse_size,
					     .methods.print = cfg_print_ustring,
					     .methods.doc = doc_size,
					     .rep = &cfg_rep_string,
					     .of = sizenodefault_enums };

/*%
 * A size in absolute values or percents.
 */
static cfg_type_t cfg_type_sizeval_percent = {
	.name = "sizeval_percent",
	.methods.parse = parse_sizeval_percent,
	.methods.print = cfg_print_ustring,
	.methods.doc = doc_sizeval_percent,
	.rep = &cfg_rep_string,
	NULL
};

/*%
 * A size in absolute values or percents, or "unlimited", or "default"
 */

static isc_result_t
parse_maxcachesize(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_sizeval_percent,
				       ret);
}

static void
doc_maxcachesize(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( default | unlimited | ");
	cfg_doc_terminal(pctx, &cfg_type_sizeval);
	cfg_print_cstr(pctx, " | ");
	cfg_doc_terminal(pctx, &cfg_type_percentage);
	cfg_print_cstr(pctx, " )");
}

static const char *maxcachesize_enums[] = { "default", "unlimited", NULL };
static cfg_type_t cfg_type_maxcachesize = { .name = "maxcachesize",
					    .methods.parse = parse_maxcachesize,
					    .methods.print = cfg_print_ustring,
					    .methods.doc = doc_maxcachesize,
					    .rep = &cfg_rep_string,
					    .of = maxcachesize_enums };

/*%
 * An IXFR size ratio: percentage, or "unlimited".
 */

static isc_result_t
parse_ixfrratio(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_percentage, ret);
}

static void
doc_ixfrratio(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( unlimited | ");
	cfg_doc_terminal(pctx, &cfg_type_percentage);
	cfg_print_cstr(pctx, " )");
}

static const char *ixfrratio_enums[] = { "unlimited", NULL };
static cfg_type_t cfg_type_ixfrratio = { .name = "ixfr_ratio",
					 .methods.parse = parse_ixfrratio,
					 .methods.doc = doc_ixfrratio,
					 .of = ixfrratio_enums };

/*%
 * optional_keyvalue
 */
static isc_result_t
parse_maybe_optional_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type,
			      bool optional, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const keyword_type_t *kw = type->of;

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), kw->name) == 0)
	{
		CHECK(cfg_gettoken(pctx, 0));
		CHECK(kw->type->methods.parse(pctx, kw->type, &obj));
		obj->type = type; /* XXX kludge */
	} else {
		if (optional) {
			CHECK(cfg_parse_void(pctx, NULL, &obj));
		} else {
			cfg_parser_error(pctx, CFG_LOG_NEAR, "expected '%s'",
					 kw->name);
			result = ISC_R_UNEXPECTEDTOKEN;
			goto cleanup;
		}
	}

	*ret = obj;
cleanup:
	return result;
}

static isc_result_t
parse_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return parse_maybe_optional_keyvalue(pctx, type, false, ret);
}

static isc_result_t
parse_optional_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret) {
	return parse_maybe_optional_keyvalue(pctx, type, true, ret);
}

static void
print_keyvalue(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	const keyword_type_t *kw = obj->type->of;
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	kw->type->methods.print(pctx, obj);
}

static void
doc_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type) {
	const keyword_type_t *kw = type->of;
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	cfg_doc_obj(pctx, kw->type);
}

static void
doc_optional_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type) {
	const keyword_type_t *kw = type->of;
	cfg_print_cstr(pctx, "[ ");
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	cfg_doc_obj(pctx, kw->type);
	cfg_print_cstr(pctx, " ]");
}

static const char *notify_enums[] = { "explicit", "master-only", "primary-only",
				      NULL };
static isc_result_t
parse_notify_type(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_notify_type(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_notifytype = {
	.name = "notifytype",
	.methods.parse = parse_notify_type,
	.methods.print = cfg_print_ustring,
	.methods.doc = doc_notify_type,
	.rep = &cfg_rep_string,
	.of = notify_enums,
};

static const char *minimal_enums[] = { "no-auth", "no-auth-recursive", NULL };
static isc_result_t
parse_minimal(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_minimal(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_minimal = {
	.name = "minimal",
	.methods.parse = parse_minimal,
	.methods.print = cfg_print_ustring,
	.methods.doc = doc_minimal,
	.rep = &cfg_rep_string,
	.of = minimal_enums,
};

static const char *ixfrdiff_enums[] = { "primary", "master", "secondary",
					"slave", NULL };
static isc_result_t
parse_ixfrdiff_type(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_ixfrdiff_type(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_ixfrdifftype = {
	.name = "ixfrdiff",
	.methods.parse = parse_ixfrdiff_type,
	.methods.print = cfg_print_ustring,
	.methods.doc = doc_ixfrdiff_type,
	.rep = &cfg_rep_string,
	.of = ixfrdiff_enums,
};

static keyword_type_t key_kw = { "key", &cfg_type_astring };

cfg_type_t cfg_type_keyref = { .name = "keyref",
			       .methods.parse = parse_keyvalue,
			       .methods.print = print_keyvalue,
			       .methods.doc = doc_keyvalue,
			       .rep = &cfg_rep_string,
			       .of = &key_kw };

static cfg_type_t cfg_type_optional_keyref = {
	.name = "optional_keyref",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_string,
	.of = &key_kw
};

static const char *qminmethod_enums[] = { "strict", "relaxed", "disabled",
					  "off", NULL };

static cfg_type_t cfg_type_qminmethod = { .name = "qminmethod",
					  .methods.parse = cfg_parse_enum,
					  .methods.print = cfg_print_ustring,
					  .methods.doc = cfg_doc_enum,
					  .rep = &cfg_rep_string,
					  .of = qminmethod_enums };

/*%
 * A "controls" statement is represented as a map with the multivalued
 * "inet" and "unix" clauses.
 */

static keyword_type_t controls_allow_kw = { "allow", &cfg_type_bracketed_aml };

static cfg_type_t cfg_type_controls_allow = { .name = "controls_allow",
					      .methods.parse = parse_keyvalue,
					      .methods.print = print_keyvalue,
					      .methods.doc = doc_keyvalue,
					      .rep = &cfg_rep_list,
					      .of = &controls_allow_kw };

static keyword_type_t controls_keys_kw = { "keys", &cfg_type_keylist };

static cfg_type_t cfg_type_controls_keys = {
	.name = "controls_keys",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_list,
	.of = &controls_keys_kw
};

static keyword_type_t controls_readonly_kw = { "read-only", &cfg_type_boolean };

static cfg_type_t cfg_type_controls_readonly = {
	.name = "controls_readonly",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_boolean,
	.of = &controls_readonly_kw
};

static cfg_tuplefielddef_t inetcontrol_fields[] = {
	{ "address", &cfg_type_controls_sockaddr, 0 },
	{ "allow", &cfg_type_controls_allow, 0 },
	{ "keys", &cfg_type_controls_keys, 0 },
	{ "read-only", &cfg_type_controls_readonly, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_inetcontrol = { .name = "inetcontrol",
					   .methods.parse = cfg_parse_tuple,
					   .methods.print = cfg_print_tuple,
					   .methods.doc = cfg_doc_tuple,
					   .rep = &cfg_rep_tuple,
					   .of = inetcontrol_fields };

static keyword_type_t controls_perm_kw = { "perm", &cfg_type_uint32 };

static cfg_type_t cfg_type_controls_perm = { .name = "controls_perm",
					     .methods.parse = parse_keyvalue,
					     .methods.print = print_keyvalue,
					     .methods.doc = doc_keyvalue,
					     .rep = &cfg_rep_uint32,
					     .of = &controls_perm_kw };

static keyword_type_t controls_owner_kw = { "owner", &cfg_type_uint32 };

static cfg_type_t cfg_type_controls_owner = { .name = "controls_owner",
					      .methods.parse = parse_keyvalue,
					      .methods.print = print_keyvalue,
					      .methods.doc = doc_keyvalue,
					      .rep = &cfg_rep_uint32,
					      .of = &controls_owner_kw };

static keyword_type_t controls_group_kw = { "group", &cfg_type_uint32 };

static cfg_type_t cfg_type_controls_group = { .name = "controls_allow",
					      .methods.parse = parse_keyvalue,
					      .methods.print = print_keyvalue,
					      .methods.doc = doc_keyvalue,
					      .rep = &cfg_rep_uint32,
					      .of = &controls_group_kw };

static cfg_tuplefielddef_t unixcontrol_fields[] = {
	{ "path", &cfg_type_qstring, 0 },
	{ "perm", &cfg_type_controls_perm, 0 },
	{ "owner", &cfg_type_controls_owner, 0 },
	{ "group", &cfg_type_controls_group, 0 },
	{ "keys", &cfg_type_controls_keys, 0 },
	{ "read-only", &cfg_type_controls_readonly, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_unixcontrol = { .name = "unixcontrol",
					   .methods.parse = cfg_parse_tuple,
					   .methods.print = cfg_print_tuple,
					   .methods.doc = cfg_doc_tuple,
					   .rep = &cfg_rep_tuple,
					   .of = unixcontrol_fields };

static cfg_clausedef_t controls_clauses[] = {
	{ "inet", &cfg_type_inetcontrol, CFG_CLAUSEFLAG_MULTI },
	{ "unix", &cfg_type_unixcontrol, CFG_CLAUSEFLAG_MULTI },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *controls_clausesets[] = { controls_clauses, NULL };
static cfg_type_t cfg_type_controls = { .name = "controls",
					.methods.parse = cfg_parse_map,
					.methods.print = cfg_print_map,
					.methods.doc = cfg_doc_map,
					.rep = &cfg_rep_map,
					.of = &controls_clausesets };

/*%
 * A "statistics-channels" statement is represented as a map with the
 * multivalued "inet" clauses.
 */
static void
doc_optional_bracketed_list(cfg_printer_t *pctx, const cfg_type_t *type) {
	const keyword_type_t *kw = type->of;
	cfg_print_cstr(pctx, "[ ");
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	cfg_doc_obj(pctx, kw->type);
	cfg_print_cstr(pctx, " ]");
}

static cfg_type_t cfg_type_optional_allow = {
	.name = "optional_allow",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &controls_allow_kw
};

static cfg_tuplefielddef_t statserver_fields[] = {
	{ "address", &cfg_type_controls_sockaddr, 0 }, /* reuse controls def */
	{ "allow", &cfg_type_optional_allow, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_statschannel = { .name = "statschannel",
					    .methods.parse = cfg_parse_tuple,
					    .methods.print = cfg_print_tuple,
					    .methods.doc = cfg_doc_tuple,
					    .rep = &cfg_rep_tuple,
					    .of = statserver_fields };

static cfg_clausedef_t statservers_clauses[] = {
	{ "inet", &cfg_type_statschannel, CFG_CLAUSEFLAG_MULTI },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *statservers_clausesets[] = { statservers_clauses,
						     NULL };

static cfg_type_t cfg_type_statschannels = { .name = "statistics-channels",
					     .methods.parse = cfg_parse_map,
					     .methods.print = cfg_print_map,
					     .methods.doc = cfg_doc_map,
					     .rep = &cfg_rep_map,
					     .of = &statservers_clausesets };

/*%
 * An optional class, as used in view and zone statements.
 */
static isc_result_t
parse_optional_class(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);
	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string) {
		CHECK(cfg_parse_obj(pctx, &cfg_type_ustring, ret));
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_void, ret));
	}
cleanup:
	return result;
}

static void
doc_optional_class(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ <class> ]");
}

static cfg_type_t cfg_type_optional_class = {
	.name = "optional_class",
	.methods.parse = parse_optional_class,
	.methods.doc = doc_optional_class,
};

static isc_result_t
parse_querysource(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;

	REQUIRE(type != NULL);
	CHECK(cfg_peektoken(pctx, 0));

	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "address") == 0)
	{
		CHECK(cfg_gettoken(pctx, 0));
		CHECK(cfg_peektoken(pctx, 0));
	}

	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "none") == 0)
	{
		CHECK(cfg_gettoken(pctx, 0));
		cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
			       pctx->line, &cfg_type_none, ret);
	} else {
		CHECK(cfg_parse_sockaddr_generic(pctx, &cfg_type_querysource,
						 type, ret));
	}

cleanup:
	if (result != ISC_R_SUCCESS) {
		cfg_parser_error(pctx, CFG_LOG_NEAR, "invalid query source");
	}

	return result;
}

static void
print_querysource(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	isc_netaddr_t na;
	isc_netaddr_fromsockaddr(&na, &obj->value.sockaddr);
	cfg_print_rawaddr(pctx, &na);
}

static void
doc__querysource(cfg_printer_t *pctx, const cfg_type_t *type, bool has_none) {
	const unsigned int *flagp = type->of;

	cfg_print_cstr(pctx, "[ address ] ( ");

	if ((*flagp & CFG_ADDR_V4OK) != 0) {
		cfg_print_cstr(pctx, "<ipv4_address>");
	} else if ((*flagp & CFG_ADDR_V6OK) != 0) {
		cfg_print_cstr(pctx, "<ipv6_address>");
	} else {
		UNREACHABLE();
	}

	cfg_print_cstr(pctx, " | *");
	if (has_none) {
		cfg_print_cstr(pctx, " | none");
	}
	cfg_print_cstr(pctx, " )");
}

static void
doc_querysource(cfg_printer_t *pctx, const cfg_type_t *type) {
	doc__querysource(pctx, type, true);
}

static void
doc_serverquerysource(cfg_printer_t *pctx, const cfg_type_t *type) {
	doc__querysource(pctx, type, false);
}

static unsigned int sockaddr4wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V4OK;
static unsigned int sockaddr6wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V6OK;

static unsigned int querysource4wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V4OK |
					     CFG_ADDR_TRAILINGOK;
static unsigned int querysource6wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V6OK |
					     CFG_ADDR_TRAILINGOK;

static cfg_type_t cfg_type_querysource4 = { .name = "querysource4",
					    .methods.parse = parse_querysource,
					    .methods.doc = doc_querysource,
					    .of = &querysource4wild_flags };

static cfg_type_t cfg_type_querysource6 = { .name = "querysource6",
					    .methods.parse = parse_querysource,
					    .methods.doc = doc_querysource,
					    .of = &querysource6wild_flags };

static cfg_type_t cfg_type_server_querysource4 = {
	.name = "querysource4",
	.methods.parse = parse_querysource,
	.methods.doc = doc_serverquerysource,
	.of = &querysource4wild_flags
};

static cfg_type_t cfg_type_server_querysource6 = {
	.name = "querysource6",
	.methods.parse = parse_querysource,
	.methods.doc = doc_serverquerysource,
	.of = &querysource6wild_flags
};

static cfg_type_t cfg_type_querysource = {
	.name = "querysource",
	.methods.print = print_querysource,
	.rep = &cfg_rep_sockaddr,
};

/*%
 * The socket address syntax in the "controls" statement is silly.
 * It allows both socket address families, but also allows "*",
 * which is gratuitously interpreted as the IPv4 wildcard address.
 */
static unsigned int controls_sockaddr_flags = CFG_ADDR_V4OK | CFG_ADDR_V6OK |
					      CFG_ADDR_WILDOK | CFG_ADDR_PORTOK;
static cfg_type_t cfg_type_controls_sockaddr = {
	.name = "controls_sockaddr",
	.methods.parse = cfg_parse_sockaddr,
	.methods.print = cfg_print_sockaddr,
	.methods.doc = cfg_doc_sockaddr,
	.rep = &cfg_rep_sockaddr,
	.of = &controls_sockaddr_flags
};

/*%
 * Handle the special kludge syntax of the "keys" clause in the "server"
 * statement, which takes a single key with or without braces and semicolon.
 */
static isc_result_t
parse_server_key_kludge(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret) {
	isc_result_t result;
	bool braces = false;
	UNUSED(type);

	/* Allow opening brace. */
	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_special &&
	    pctx->token.value.as_char == '{')
	{
		CHECK(cfg_gettoken(pctx, 0));
		braces = true;
	}

	CHECK(cfg_parse_obj(pctx, &cfg_type_astring, ret));

	if (braces) {
		/* Skip semicolon if present. */
		CHECK(cfg_peektoken(pctx, 0));
		if (pctx->token.type == isc_tokentype_special &&
		    pctx->token.value.as_char == ';')
		{
			CHECK(cfg_gettoken(pctx, 0));
		}

		CHECK(cfg_parse_special(pctx, '}'));
	}
cleanup:
	return result;
}
static cfg_type_t cfg_type_server_key_kludge = {
	.name = "server_key",
	.methods.parse = parse_server_key_kludge,
	.methods.doc = cfg_doc_terminal,
};

/*%
 * An optional logging facility.
 */

static isc_result_t
parse_optional_facility(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string ||
	    pctx->token.type == isc_tokentype_qstring)
	{
		CHECK(cfg_parse_obj(pctx, &cfg_type_astring, ret));
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_void, ret));
	}
cleanup:
	return result;
}

static void
doc_optional_facility(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ <syslog_facility> ]");
}

static cfg_type_t cfg_type_optional_facility = {
	.name = "optional_facility",
	.methods.parse = parse_optional_facility,
	.methods.doc = doc_optional_facility,
};

/*%
 * A log severity.  Return as a string, except "debug N",
 * which is returned as a keyword object.
 */

static keyword_type_t debug_kw = { "debug", &cfg_type_uint32 };
static cfg_type_t cfg_type_debuglevel = { .name = "debuglevel",
					  .methods.parse = parse_keyvalue,
					  .methods.print = print_keyvalue,
					  .methods.doc = doc_keyvalue,
					  .rep = &cfg_rep_uint32,
					  .of = &debug_kw };

static isc_result_t
parse_logseverity(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "debug") == 0)
	{
		CHECK(cfg_gettoken(pctx, 0)); /* read "debug" */
		CHECK(cfg_peektoken(pctx, ISC_LEXOPT_NUMBER));
		if (pctx->token.type == isc_tokentype_number) {
			CHECK(cfg_parse_uint32(pctx, NULL, ret));
		} else {
			/*
			 * The debug level is optional and defaults to 1.
			 * This makes little sense, but we support it for
			 * compatibility with BIND 8.
			 */
			cfg_obj_create(pctx->mctx, cfg_parser_currentfile(pctx),
				       pctx->line, &cfg_type_uint32, ret);
			(*ret)->value.uint32 = 1;
		}
		(*ret)->type = &cfg_type_debuglevel; /* XXX kludge */
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_loglevel, ret));
	}
cleanup:
	return result;
}

static cfg_type_t cfg_type_logseverity = {
	.name = "log_severity",
	.methods.parse = parse_logseverity,
	.methods.doc = cfg_doc_terminal,
};

/*%
 * The "file" clause of the "channel" statement.
 * This is yet another special case.
 */

static const char *logversions_enums[] = { "unlimited", NULL };
static isc_result_t
parse_logversions(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_uint32, ret);
}

static void
doc_logversions(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_uint32);
}

static cfg_type_t cfg_type_logversions = { .name = "logversions",
					   .methods.parse = parse_logversions,
					   .methods.print = cfg_print_ustring,
					   .methods.doc = doc_logversions,
					   .rep = &cfg_rep_string,
					   .of = logversions_enums };

static const char *logsuffix_enums[] = { "increment", "timestamp", NULL };
static cfg_type_t cfg_type_logsuffix = { .name = "logsuffix",
					 .methods.parse = cfg_parse_enum,
					 .methods.print = cfg_print_ustring,
					 .methods.doc = cfg_doc_enum,
					 .rep = &cfg_rep_string,
					 .of = &logsuffix_enums };

static cfg_tuplefielddef_t logfile_fields[] = {
	{ "file", &cfg_type_qstring, 0 },
	{ "versions", &cfg_type_logversions, 0 },
	{ "size", &cfg_type_size, 0 },
	{ "suffix", &cfg_type_logsuffix, 0 },
	{ NULL, NULL, 0 }
};

static isc_result_t
parse_logfile(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const cfg_tuplefielddef_t *fields = type->of;

	cfg_tuple_create(pctx, type, &obj);

	/* Parse the mandatory "file" field */
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));

	/* Parse "versions" and "size" fields in any order. */
	for (;;) {
		CHECK(cfg_peektoken(pctx, 0));
		if (pctx->token.type == isc_tokentype_string) {
			CHECK(cfg_gettoken(pctx, 0));
			if (strcasecmp(TOKEN_STRING(pctx), "versions") == 0 &&
			    obj->value.tuple[1] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[1].type,
						    &obj->value.tuple[1]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "size") ==
					   0 &&
				   obj->value.tuple[2] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[2].type,
						    &obj->value.tuple[2]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "suffix") ==
					   0 &&
				   obj->value.tuple[3] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[3].type,
						    &obj->value.tuple[3]));
			} else {
				break;
			}
		} else {
			break;
		}
	}

	/* Create void objects for missing optional values. */
	if (obj->value.tuple[1] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[1]));
	}
	if (obj->value.tuple[2] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[2]));
	}
	if (obj->value.tuple[3] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[3]));
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static void
print_logfile(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	cfg_print_obj(pctx, obj->value.tuple[0]); /* file */
	if (obj->value.tuple[1]->type->methods.print != cfg_print_void) {
		cfg_print_cstr(pctx, " versions ");
		cfg_print_obj(pctx, obj->value.tuple[1]);
	}
	if (obj->value.tuple[2]->type->methods.print != cfg_print_void) {
		cfg_print_cstr(pctx, " size ");
		cfg_print_obj(pctx, obj->value.tuple[2]);
	}
	if (obj->value.tuple[3]->type->methods.print != cfg_print_void) {
		cfg_print_cstr(pctx, " suffix ");
		cfg_print_obj(pctx, obj->value.tuple[3]);
	}
}

static void
doc_logfile(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "<quoted_string>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ versions ( unlimited | <integer> ) ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ size <size> ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ suffix ( increment | timestamp ) ]");
}

static cfg_type_t cfg_type_logfile = { .name = "log_file",
				       .methods.parse = parse_logfile,
				       .methods.print = print_logfile,
				       .methods.doc = doc_logfile,
				       .rep = &cfg_rep_tuple,
				       .of = logfile_fields };

/*% An IPv4 address, "*" accepted as wildcard. */
static cfg_type_t cfg_type_sockaddr4wild = {
	".name = sockaddr4wild",
	.methods.parse = cfg_parse_sockaddr,
	.methods.print = cfg_print_sockaddr,
	.methods.doc = cfg_doc_sockaddr,
	.rep = &cfg_rep_sockaddr,
	.of = &sockaddr4wild_flags
};

/*% An IPv6 address, "*" accepted as wildcard. */
static cfg_type_t cfg_type_sockaddr6wild = {
	.name = "v6addrportwild",
	.methods.parse = cfg_parse_sockaddr,
	.methods.print = cfg_print_sockaddr,
	.methods.doc = cfg_doc_sockaddr,
	.rep = &cfg_rep_sockaddr,
	.of = &sockaddr6wild_flags
};

static keyword_type_t sourceaddr4_kw = { "source", &cfg_type_sockaddr4wild };

static cfg_type_t cfg_type_optional_sourceaddr4 = {
	.name = "optional_sourceaddr4",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_sockaddr,
	.of = &sourceaddr4_kw
};

static keyword_type_t sourceaddr6_kw = { "source-v6", &cfg_type_sockaddr6wild };

static cfg_type_t cfg_type_optional_sourceaddr6 = {
	.name = "optional_sourceaddr6",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_sockaddr,
	.of = &sourceaddr6_kw
};

/*%
 * rndc
 */

static cfg_clausedef_t rndcconf_options_clauses[] = {
	{ "default-key", &cfg_type_astring, 0 },
	{ "default-port", &cfg_type_uint32, 0 },
	{ "default-server", &cfg_type_astring, 0 },
	{ "default-source-address", &cfg_type_netaddr4wild, 0 },
	{ "default-source-address-v6", &cfg_type_netaddr6wild, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *rndcconf_options_clausesets[] = {
	rndcconf_options_clauses, NULL
};

static cfg_type_t cfg_type_rndcconf_options = {
	.name = "rndcconf_options",
	.methods.parse = cfg_parse_map,
	.methods.print = cfg_print_map,
	.methods.doc = cfg_doc_map,
	.rep = &cfg_rep_map,
	.of = rndcconf_options_clausesets
};

static cfg_clausedef_t rndcconf_server_clauses[] = {
	{ "key", &cfg_type_astring, 0 },
	{ "port", &cfg_type_uint32, 0 },
	{ "source-address", &cfg_type_netaddr4wild, 0 },
	{ "source-address-v6", &cfg_type_netaddr6wild, 0 },
	{ "addresses", &cfg_type_bracketed_sockaddrnameportlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *rndcconf_server_clausesets[] = {
	rndcconf_server_clauses, NULL
};

static cfg_type_t cfg_type_rndcconf_server = {
	.name = "rndcconf_server",
	.methods.parse = cfg_parse_named_map,
	.methods.print = cfg_print_map,
	.methods.doc = cfg_doc_map,
	.rep = &cfg_rep_map,
	.of = rndcconf_server_clausesets
};

static cfg_clausedef_t rndcconf_clauses[] = {
	{ "key", &cfg_type_key, CFG_CLAUSEFLAG_MULTI },
	{ "server", &cfg_type_rndcconf_server, CFG_CLAUSEFLAG_MULTI },
	{ "options", &cfg_type_rndcconf_options, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *rndcconf_clausesets[] = { rndcconf_clauses, NULL };

cfg_type_t cfg_type_rndcconf = { .name = "rndcconf",
				 .methods.parse = cfg_parse_mapbody,
				 .methods.print = cfg_print_mapbody,
				 .methods.doc = cfg_doc_mapbody,
				 .rep = &cfg_rep_map,
				 .of = rndcconf_clausesets };

static cfg_clausedef_t rndckey_clauses[] = { { "key", &cfg_type_key, 0 },
					     { NULL, NULL, 0 } };

static cfg_clausedef_t *rndckey_clausesets[] = { rndckey_clauses, NULL };

cfg_type_t cfg_type_rndckey = { .name = "rndckey",
				.methods.parse = cfg_parse_mapbody,
				.methods.print = cfg_print_mapbody,
				.methods.doc = cfg_doc_mapbody,
				.rep = &cfg_rep_map,
				.of = rndckey_clausesets };

/*
 * session.key has exactly the same syntax as rndc.key, but it's defined
 * separately for clarity (and so we can extend it someday, if needed).
 */
cfg_type_t cfg_type_sessionkey = { .name = "sessionkey",
				   .methods.parse = cfg_parse_mapbody,
				   .methods.print = cfg_print_mapbody,
				   .methods.doc = cfg_doc_mapbody,
				   .rep = &cfg_rep_map,
				   .of = rndckey_clausesets };

static cfg_tuplefielddef_t nameport_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "port", &cfg_type_optional_port, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_nameport = { .name = "nameport",
					.methods.parse = cfg_parse_tuple,
					.methods.print = cfg_print_tuple,
					.methods.doc = cfg_doc_tuple,
					.rep = &cfg_rep_tuple,
					.of = nameport_fields };

static void
doc_sockaddrnameport(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( ");
	cfg_print_cstr(pctx, "<quoted_string>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv4_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv6_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " )");
}

static isc_result_t
parse_sockaddrnameport(cfg_parser_t *pctx, const cfg_type_t *type,
		       cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string ||
	    pctx->token.type == isc_tokentype_qstring)
	{
		if (cfg_lookingat_netaddr(pctx, CFG_ADDR_V4OK | CFG_ADDR_V6OK))
		{
			CHECK(cfg_parse_sockaddr(pctx, &cfg_type_sockaddr,
						 ret));
		} else {
			CHECK(cfg_parse_tuple(pctx, &cfg_type_nameport, ret));
		}
	} else {
		cfg_parser_error(pctx, CFG_LOG_NEAR,
				 "expected IP address or hostname");
		return ISC_R_UNEXPECTEDTOKEN;
	}
cleanup:
	return result;
}

static cfg_type_t cfg_type_sockaddrnameport = {
	.name = "sockaddrnameport_element",
	.methods.parse = parse_sockaddrnameport,
	.methods.doc = doc_sockaddrnameport,
};

static cfg_type_t cfg_type_bracketed_sockaddrnameportlist = {
	.name = "bracketed_sockaddrnameportlist",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_sockaddrnameport
};

/*%
 * A list of socket addresses or name with an optional default port,
 * as used in the dual-stack-servers option.  E.g.,
 * "port 1234 { dual-stack-servers.net; 10.0.0.1; 1::2 port 69; }"
 */
static cfg_tuplefielddef_t nameportiplist_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "addresses", &cfg_type_bracketed_sockaddrnameportlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_nameportiplist = { .name = "nameportiplist",
					      .methods.parse = cfg_parse_tuple,
					      .methods.print = cfg_print_tuple,
					      .methods.doc = cfg_doc_tuple,
					      .rep = &cfg_rep_tuple,
					      .of = nameportiplist_fields };

/*%
 * remote servers element.
 */

static void
doc_remoteselement(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( ");
	cfg_print_cstr(pctx, "<server-list>");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv4_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv6_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " )");
}

static isc_result_t
parse_remoteselement(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string ||
	    pctx->token.type == isc_tokentype_qstring)
	{
		if (cfg_lookingat_netaddr(pctx, CFG_ADDR_V4OK | CFG_ADDR_V6OK))
		{
			CHECK(cfg_parse_sockaddr(pctx, &cfg_type_sockaddr,
						 ret));
		} else {
			CHECK(cfg_parse_astring(pctx, &cfg_type_astring, ret));
		}
	} else {
		cfg_parser_error(pctx, CFG_LOG_NEAR,
				 "expected IP address or remote servers list "
				 "name");
		return ISC_R_UNEXPECTEDTOKEN;
	}
cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static cfg_type_t cfg_type_remoteselement = {
	.name = "remotes_element",
	.methods.parse = parse_remoteselement,
	.methods.doc = doc_remoteselement,
};

static int
cmp_clause(const void *ap, const void *bp) {
	const cfg_clausedef_t *a = (const cfg_clausedef_t *)ap;
	const cfg_clausedef_t *b = (const cfg_clausedef_t *)bp;
	return strcmp(a->name, b->name);
}

bool
cfg_clause_validforzone(const char *name, unsigned int ztype) {
	const cfg_clausedef_t *clause;
	bool valid = false;

	for (clause = zone_clauses; clause->name != NULL; clause++) {
		if ((clause->flags & ztype) == 0 ||
		    strcmp(clause->name, name) != 0)
		{
			continue;
		}
		valid = true;
	}
	for (clause = zone_only_clauses; clause->name != NULL; clause++) {
		if ((clause->flags & ztype) == 0 ||
		    strcmp(clause->name, name) != 0)
		{
			continue;
		}
		valid = true;
	}
	for (clause = non_template_clauses; clause->name != NULL; clause++) {
		if ((clause->flags & ztype) == 0 ||
		    strcmp(clause->name, name) != 0)
		{
			continue;
		}
		valid = true;
	}

	return valid;
}

void
cfg_print_zonegrammar(const unsigned int zonetype, unsigned int flags,
		      void (*f)(void *closure, const char *text, int textlen),
		      void *closure) {
#define NCLAUSES                                                      \
	ARRAY_SIZE(non_template_clauses) + ARRAY_SIZE(zone_clauses) + \
		ARRAY_SIZE(zone_only_clauses) - 2

	cfg_printer_t pctx;
	cfg_clausedef_t clauses[NCLAUSES];
	cfg_clausedef_t *clause = clauses;

	pctx.f = f;
	pctx.closure = closure;
	pctx.indent = 0;
	pctx.flags = flags;

	memmove(clause, zone_clauses, sizeof(zone_clauses));
	clause += ARRAY_SIZE(zone_clauses) - 1;
	memmove(clause, zone_only_clauses, sizeof(zone_only_clauses));
	clause += ARRAY_SIZE(zone_only_clauses) - 1;
	memmove(clause, non_template_clauses, sizeof(non_template_clauses));

	qsort(clauses, NCLAUSES - 1, sizeof(clause[0]), cmp_clause);

	cfg_print_cstr(&pctx, "zone <string> [ <class> ] {\n");
	pctx.indent++;

	switch (zonetype) {
	case CFG_ZONE_PRIMARY:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type primary;\n");
		break;
	case CFG_ZONE_SECONDARY:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type secondary;\n");
		break;
	case CFG_ZONE_MIRROR:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type mirror;\n");
		break;
	case CFG_ZONE_STUB:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type stub;\n");
		break;
	case CFG_ZONE_HINT:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type hint;\n");
		break;
	case CFG_ZONE_FORWARD:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type forward;\n");
		break;
	case CFG_ZONE_STATICSTUB:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type static-stub;\n");
		break;
	case CFG_ZONE_REDIRECT:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type redirect;\n");
		break;
	case CFG_ZONE_INVIEW:
		/* no zone type is specified for these */
		break;
	default:
		UNREACHABLE();
	}

	for (clause = clauses; clause->name != NULL; clause++) {
		if (((pctx.flags & CFG_PRINTER_ACTIVEONLY) != 0) &&
		    (((clause->flags & CFG_CLAUSEFLAG_OBSOLETE) != 0) ||
		     ((clause->flags & CFG_CLAUSEFLAG_TESTONLY) != 0)))
		{
			continue;
		}
		if ((clause->flags & CFG_CLAUSEFLAG_ANCIENT) != 0 ||
		    (clause->flags & CFG_CLAUSEFLAG_NODOC) != 0)
		{
			continue;
		}

		if ((clause->flags & zonetype) == 0 ||
		    strcasecmp(clause->name, "type") == 0)
		{
			continue;
		}
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, clause->name);
		cfg_print_cstr(&pctx, " ");
		cfg_doc_obj(&pctx, clause->type);
		cfg_print_cstr(&pctx, ";");
		cfg_print_clauseflags(&pctx, clause->flags);
		cfg_print_cstr(&pctx, "\n");
	}

	pctx.indent--;
	cfg_print_cstr(&pctx, "};\n");
}

/*%
 * "tls" and related statement syntax.
 */
static cfg_type_t cfg_type_tlsprotos = {
	.name = "tls_protocols",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_astring
};

static cfg_clausedef_t tls_clauses[] = {
	{ "key-file", &cfg_type_qstring, 0 },
	{ "cert-file", &cfg_type_qstring, 0 },
	{ "ca-file", &cfg_type_qstring, 0 },
	{ "remote-hostname", &cfg_type_qstring, 0 },
	{ "dhparam-file", &cfg_type_qstring, 0 },
	{ "protocols", &cfg_type_tlsprotos, 0 },
	{ "ciphers", &cfg_type_astring, 0 },
	{ "cipher-suites", &cfg_type_astring, 0 },
	{ "prefer-server-ciphers", &cfg_type_boolean, 0 },
	{ "session-tickets", &cfg_type_boolean, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *tls_clausesets[] = { tls_clauses, NULL };
static cfg_type_t cfg_type_tlsconf = { .name = "tlsconf",
				       .methods.parse = cfg_parse_named_map,
				       .methods.print = cfg_print_map,
				       .methods.doc = cfg_doc_map,
				       .rep = &cfg_rep_map,
				       .of = tls_clausesets };

static keyword_type_t tls_kw = { "tls", &cfg_type_astring };
static cfg_type_t cfg_type_optional_tls = {
	.name = "tlsoptional",
	.methods.parse = parse_optional_keyvalue,
	.methods.print = print_keyvalue,
	.methods.doc = doc_optional_keyvalue,
	.rep = &cfg_rep_string,
	.of = &tls_kw
};

/* http and https */

static cfg_type_t cfg_type_bracketed_http_endpoint_list = {
	.name = "bracketed_http_endpoint_list",
	.methods.parse = cfg_parse_bracketed_list,
	.methods.print = cfg_print_bracketed_list,
	.methods.doc = cfg_doc_bracketed_list,
	.rep = &cfg_rep_list,
	.of = &cfg_type_qstring
};

static cfg_clausedef_t cfg_http_description_clauses[] = {
	{ "endpoints", &cfg_type_bracketed_http_endpoint_list, 0 },
	{ "listener-clients", &cfg_type_uint32, 0 },
	{ "streams-per-connection", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_clausedef_t *http_description_clausesets[] = {
	cfg_http_description_clauses, NULL
};

static cfg_type_t cfg_type_http_description = {
	.name = "http_desc",
	.methods.parse = cfg_parse_named_map,
	.methods.print = cfg_print_map,
	.methods.doc = cfg_doc_map,
	.rep = &cfg_rep_map,
	.of = http_description_clausesets
};

cfg_obj_t *
cfg_effective_config(const cfg_obj_t *userconfig,
		     const cfg_obj_t *defaultconfig) {
	cfg_obj_t *effective = NULL;

	REQUIRE(defaultconfig != NULL &&
		defaultconfig->type == &cfg_type_namedconf);
	REQUIRE(userconfig != NULL && userconfig->type == &cfg_type_namedconf);

	cfg_obj_clone(userconfig, &effective);
	map_merge(effective, defaultconfig);

	return effective;
}
