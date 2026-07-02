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

#include <arpa/inet.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <isc/u16bitmap.h>

#include "u16bitmap_server.pb-c.h"

typedef U16bitmap__Command Command;
typedef U16bitmap__Command__CommandCase CommandCase;
typedef U16bitmap__Response Response;
typedef U16bitmap__Response__Count CountResponse;
typedef U16bitmap__Response__Error ErrorResponse;
typedef U16bitmap__Response__Next NextResponse;
typedef U16bitmap__Response__Ok OkResponse;
typedef U16bitmap__Response__Value ValueResponse;
typedef U16bitmap__Response__Values ValuesResponse;

#define COMMAND_SET	 U16BITMAP__COMMAND__COMMAND_SET
#define COMMAND_UNSET	 U16BITMAP__COMMAND__COMMAND_UNSET
#define COMMAND_GET	 U16BITMAP__COMMAND__COMMAND_GET
#define COMMAND_POPCOUNT U16BITMAP__COMMAND__COMMAND_POPCOUNT
#define COMMAND_ISSET	 U16BITMAP__COMMAND__COMMAND_ISSET
#define COMMAND_RESET	 U16BITMAP__COMMAND__COMMAND_RESET
#define COMMAND_NEXT	 U16BITMAP__COMMAND__COMMAND_NEXT

#define RESPONSE_OK	U16BITMAP__RESPONSE__RESPONSE_OK
#define RESPONSE_VALUE	U16BITMAP__RESPONSE__RESPONSE_VALUE
#define RESPONSE_VALUES U16BITMAP__RESPONSE__RESPONSE_VALUES
#define RESPONSE_COUNT	U16BITMAP__RESPONSE__RESPONSE_COUNT
#define RESPONSE_ERROR	U16BITMAP__RESPONSE__RESPONSE_ERROR
#define RESPONSE_NEXT	U16BITMAP__RESPONSE__RESPONSE_NEXT

static bool
read_bytes(void *base, size_t size) {
	return fread(base, 1, size, stdin) == size;
}

static void
write_bytes(const void *base, size_t size) {
	if (fwrite(base, 1, size, stdout) != size) {
		exit(1);
	}
}

static Command *
read_command(void) {
	uint32_t length_be = 0;
	uint32_t length = 0;
	uint8_t *data = NULL;
	Command *command = NULL;

	if (!read_bytes(&length_be, sizeof(length_be))) {
		return NULL;
	}

	length = ntohl(length_be);
	data = malloc(length);
	if (data == NULL) {
		exit(1);
	}

	if (!read_bytes(data, length)) {
		free(data);
		return NULL;
	}

	command = u16bitmap__command__unpack(NULL, length, data);
	free(data);

	return command;
}

static void
write_response(const Response *response) {
	size_t length = u16bitmap__response__get_packed_size(response);
	uint32_t length_be = htonl((uint32_t)length);
	uint8_t *data = malloc(length);

	if (data == NULL) {
		exit(1);
	}

	u16bitmap__response__pack(response, data);
	write_bytes(&length_be, sizeof(length_be));
	write_bytes(data, length);
	fflush(stdout);
	free(data);
}

static void
reply_ok(void) {
	Response response = U16BITMAP__RESPONSE__INIT;
	OkResponse ok = U16BITMAP__RESPONSE__OK__INIT;

	response.response_case = RESPONSE_OK;
	response.ok = &ok;
	write_response(&response);
}

static void
reply_error(const char *message) {
	Response response = U16BITMAP__RESPONSE__INIT;
	ErrorResponse error = U16BITMAP__RESPONSE__ERROR__INIT;

	error.error = (char *)message;
	response.response_case = RESPONSE_ERROR;
	response.error = &error;
	write_response(&response);
}

static void
reply_value(bool present) {
	Response response = U16BITMAP__RESPONSE__INIT;
	ValueResponse value = U16BITMAP__RESPONSE__VALUE__INIT;

	value.present = present;
	response.response_case = RESPONSE_VALUE;
	response.value = &value;
	write_response(&response);
}

static void
reply_count(const isc_u16bitmap_t *bitmap) {
	Response response = U16BITMAP__RESPONSE__INIT;
	CountResponse count = U16BITMAP__RESPONSE__COUNT__INIT;

	count.count = isc_u16bitmap_count(bitmap);
	response.response_case = RESPONSE_COUNT;
	response.count = &count;
	write_response(&response);
}

static void
reply_next(ssize_t next) {
	Response response = U16BITMAP__RESPONSE__INIT;
	NextResponse value = U16BITMAP__RESPONSE__NEXT__INIT;

	value.value = next;
	response.response_case = RESPONSE_NEXT;
	response.next = &value;
	write_response(&response);
}

static void
reply_get(const isc_u16bitmap_t *bitmap) {
	Response response = U16BITMAP__RESPONSE__INIT;
	ValuesResponse values = U16BITMAP__RESPONSE__VALUES__INIT;
	uint32_t count = isc_u16bitmap_count(bitmap);
	uint32_t *array = count > 0 ? malloc(count * sizeof(array[0])) : NULL;
	size_t i = 0;

	if (count > 0 && array == NULL) {
		exit(1);
	}

	ISC_U16BITMAP_FOREACH(bitmap, value) {
		array[i++] = (uint32_t)value;
	}

	values.count = count;
	values.n_values = count;
	values.values = array;
	response.response_case = RESPONSE_VALUES;
	response.values = &values;
	write_response(&response);
	free(array);
}

static bool
valid_value(uint32_t value) {
	return value <= UINT16_MAX;
}

static void
bitmap_check_equal(const isc_u16bitmap_t *zero, const isc_u16bitmap_t *normal) {
	ssize_t znext = ISC_U16BITMAP_BEGIN;
	ssize_t nnext = ISC_U16BITMAP_BEGIN;

	if (isc_u16bitmap_count(zero) != isc_u16bitmap_count(normal)) {
		exit(1);
	}

	for (;;) {
		znext = isc_u16bitmap_next(zero, znext);
		nnext = isc_u16bitmap_next(normal, nnext);

		if (znext != nnext) {
			exit(1);
		}
		if (znext == ISC_U16BITMAP_END) {
			break;
		}
		if (isc_u16bitmap_isset(zero, (uint16_t)znext) !=
		    isc_u16bitmap_isset(normal, (uint16_t)nnext))
		{
			exit(1);
		}
	}
}

int
main(void) {
	isc_u16bitmap_t zero = { 0 };
	isc_u16bitmap_t normal;
	Command *command = NULL;

	isc_u16bitmap_reinit(&normal);
	bitmap_check_equal(&zero, &normal);

	while ((command = read_command()) != NULL) {
		switch ((CommandCase)command->command_case) {
		case COMMAND_SET:
			if (!valid_value(command->set->value)) {
				reply_error("set-argument");
			} else {
				isc_u16bitmap_set(&zero,
						  (uint16_t)command->set->value);
				isc_u16bitmap_set(&normal,
						  (uint16_t)command->set->value);
				reply_ok();
			}
			break;
		case COMMAND_UNSET:
			if (!valid_value(command->unset->value)) {
				reply_error("unset-argument");
			} else {
				isc_u16bitmap_unset(&zero,
						    (uint16_t)command->unset->value);
				isc_u16bitmap_unset(&normal,
						    (uint16_t)command->unset->value);
				reply_ok();
			}
			break;
		case COMMAND_GET:
			reply_get(&normal);
			break;
		case COMMAND_POPCOUNT:
			reply_count(&normal);
			break;
		case COMMAND_ISSET:
			if (!valid_value(command->isset->value)) {
				reply_error("isset-argument");
			} else {
				reply_value(isc_u16bitmap_isset(
					&normal,
					(uint16_t)command->isset->value));
			}
			break;
		case COMMAND_RESET:
			isc_u16bitmap_reinit(&zero);
			isc_u16bitmap_reinit(&normal);
			reply_ok();
			break;
		case COMMAND_NEXT:
			reply_next(isc_u16bitmap_next(&normal,
						      (ssize_t)command->next->value));
			break;
		default:
			reply_error("unknown-command");
			break;
		}

		bitmap_check_equal(&zero, &normal);
		u16bitmap__command__free_unpacked(command, NULL);
	}

	return 0;
}
