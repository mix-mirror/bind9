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
#include <dns/ttl.h>

#include <named/namedconf2json.h>

#include <isc/buffer.h>

#include <isccfg/namedconf.h>
#include <isccfg/grammar.h>

#include <json_object.h>

static void
namedconf2json_cfgobj2string_f(void *closure, const char *text, int textlen) {
	isc_buffer_t *b = closure;

	isc_buffer_putmem(b, (const unsigned char *)text, textlen);
}


static json_object *
namedconf2json_cfgobj2string(const cfg_obj_t *obj) {
	char bdata[512];
	isc_buffer_t b;
	cfg_printer_t printer = { .f = namedconf2json_cfgobj2string_f,
				  .closure = &b };

	isc_buffer_init(&b, bdata, sizeof(bdata));
	obj->type->print(&printer, obj);
	INSIST(isc_buffer_availablelength(&b) > 1);
	isc_buffer_putuint8(&b, 0);
	return json_object_new_string(bdata);
}

static json_object *
namedconf2json_sockaddr2tuple(const cfg_obj_t *obj) {
	json_object *tuple = json_object_new_object();
	json_object *jaddr = NULL;
	isc_netaddr_t netaddr;
	in_port_t port;
	char addrbuf[ISC_NETADDR_FORMATSIZE];

	isc_netaddr_fromsockaddr(&netaddr, &obj->value.sockaddr);
	isc_netaddr_format(&netaddr, addrbuf, sizeof(addrbuf));
	jaddr = json_object_new_string(addrbuf);
	json_object_object_add(tuple, "address", jaddr);

	port = isc_sockaddr_getport(&obj->value.sockaddr);
	if (port != 0) {
		json_object *jport = json_object_new_int(port);

		json_object_object_add(tuple, "port", jport);
	}

	if (obj->value.sockaddrtls.tls.base != NULL) {
		json_object *jtls = json_object_new_string_len(
			obj->value.sockaddrtls.tls.base,
			obj->value.sockaddrtls.tls.length);

		json_object_object_add(tuple, "tls", jtls);
	}

	return tuple;
}

static isc_result_t
namedconf2json_foreach_map(const cfg_obj_t *map, json_object *jparent);

static isc_result_t
namedconf2json_foreach_tuple(const cfg_obj_t *tuple, json_object *jparent);

static isc_result_t
namedconf2json_foreach_list(const cfg_obj_t *list, json_object *jparent);

static isc_result_t
namedconf2json_clause(const cfg_obj_t *obj, const char *name,
		      json_object *jparent) {
	json_object *jobj = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	
	if (cfg_obj_isuint64(obj)) {
		jobj = json_object_new_int64(cfg_obj_asuint64(obj));
	} else if (cfg_obj_isuint32(obj)) {
		jobj = json_object_new_int(cfg_obj_asuint32(obj));
	} else if (cfg_obj_isboolean(obj)) {
		jobj = json_object_new_boolean(cfg_obj_asboolean(obj));
	} else if (cfg_obj_isstring(obj)) {
		jobj = json_object_new_string(cfg_obj_asstring(obj));
	} else if (cfg_obj_isnetprefix(obj) ||
		   cfg_obj_isduration(obj) || cfg_obj_ispercentage(obj) ||
		   cfg_obj_isfixedpoint(obj))
	{
		jobj = namedconf2json_cfgobj2string(obj);
	} else if (cfg_obj_ismap(obj)) {
		const cfg_obj_t *id = cfg_map_getname(obj);

		jobj = json_object_new_object();
		result = namedconf2json_foreach_map(obj, jobj);
		if (id != NULL) {
			json_object *nameobj =
				json_object_new_string(cfg_obj_asstring(id));
			if (json_object_object_add(jobj, "name", nameobj) != 0) {
				result = ISC_R_FAILURE;
				json_object_put(nameobj);
			}
		}
	} else if (cfg_obj_istuple(obj)) {
		jobj = json_object_new_object();
		result = namedconf2json_foreach_tuple(obj, jobj);
	} else if (cfg_obj_islist(obj)) {
		jobj = json_object_new_array();
		result = namedconf2json_foreach_list(obj, jobj);
	} else if (cfg_obj_isvoid(obj)) {
		jobj = json_object_new_null();
	} else if (cfg_obj_issockaddr(obj)) {
		jobj = namedconf2json_sockaddr2tuple(obj);
	} else if (cfg_obj_issockaddrtls(obj)) {
		jobj = namedconf2json_sockaddr2tuple(obj);
	} else {
		printf("type=%s\n", obj->type->name);
		exit(0);
		REQUIRE(false);
	}

	if (result == ISC_R_SUCCESS) {
		if (name == NULL) {
			/*
			 * `name` is NULL when this function is called from a
			 * list context
			 */
			if (json_object_array_add(jparent, jobj) != 0) {
				return ISC_R_FAILURE;
			}
		} else if (json_object_object_add(jparent, name, jobj) != 0) {
			return ISC_R_FAILURE;
		}
	} else {
		json_object_put(jobj);
	}

	return result;
}

static isc_result_t
namedconf2json_foreach_list(const cfg_obj_t *list, json_object *jparent) {
	const cfg_listelt_t *elt = cfg_list_first(list);

	while (elt != NULL) {
		const cfg_obj_t *obj = elt->obj;

		if (namedconf2json_clause(obj, NULL, jparent) != ISC_R_SUCCESS) {
			return ISC_R_FAILURE;
		}

		elt = cfg_list_next(elt);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
namedconf2json_foreach_tuple(const cfg_obj_t *tuple, json_object *jparent) {
	const cfg_tuplefielddef_t *fields;
	const cfg_tuplefielddef_t *field;
	size_t i = 0;

	fields = tuple->type->of;
	for (field = fields, i = 0; field->name != NULL; field++, i++) {
		const char *fname = field->name;
		const cfg_obj_t *fobj = tuple->value.tuple[i];

		if (namedconf2json_clause(fobj, fname, jparent) !=
		    ISC_R_SUCCESS)
		{
			return ISC_R_FAILURE;
		}
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
namedconf2json_foreach_map(const cfg_obj_t *map, json_object *jparent) {
	unsigned int idx = 0;
	const cfg_type_t *type = map->type;
	const char *clausename = NULL;
	const void *clauses = NULL;
	const cfg_obj_t *obj = NULL;

	clausename = cfg_map_firstclause(type, &clauses, &idx);
	INSIST(clausename != NULL);

	do {
		obj = NULL;
		if (cfg_map_get(map, clausename, &obj) == ISC_R_SUCCESS) {
			if (namedconf2json_clause(obj, clausename, jparent) !=
			    ISC_R_SUCCESS)
			{
				return ISC_R_FAILURE;
			}
		}
		clausename = cfg_map_nextclause(type, &clauses, &idx);
	} while (clausename != NULL);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_namedconf2json(const cfg_obj_t *nconfig, json_object **jconfig) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(nconfig != NULL);
	REQUIRE(jconfig != NULL && *jconfig == NULL);

	*jconfig = json_object_new_object();
	result = namedconf2json_foreach_map(nconfig, *jconfig);
	if (result != ISC_R_SUCCESS) {
		json_object_put(*jconfig);
		*jconfig = NULL;
	}
	
	return result;
}
