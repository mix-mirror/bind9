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

#include <ctype.h>
#include <stdbool.h>

#include <isc/mem.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "quic-int.h"

/*
 * We have used the following IETF draft to derive the grammar below:
 *
 * https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/
 *
 * Both the grammar and the parser should be *painfully* accurate and
 * describes what is used to be named "NSS Key Log Format".
 *
 * tls-keylog-entry = label " " client-random " " secret [ end-line ].
 * label = "CLIENT_EARLY_TRAFFIC_SECRET" |
 *         "CLIENT_HANDSHAKE_TRAFFIC_SECRET" |
 *         "CLIENT_RANDOM" |
 *         "CLIENT_TRAFFIC_SECRET_0" |
 *         "EARLY_EXPORTER_MASTER_SECRET" |
 *         "EXPORTER_SECRET" |
 *         "SERVER_HANDSHAKE_TRAFFIC_SECRET" |
 *         "SERVER_TRAFFIC_SECRET_0".
 * client-random = hex-byte { hex-byte }. (* 64 characters, 32 bytes *)
 * secret = hex-byte { hex-byte }.
 * end-line = end-char { end-char }.
 * hex-byte = hex-char hex-char.
 * hex-char = digit | "a" | "A" | "b" | "B" | "c" | "C" |
 *            "d" | "D" | "e" | "E" | "f" | "F".
 * digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9".
 * end-char = "\n" | "\r".
 */

#define CLIENT_RANDOM_LEN (32)

typedef struct keylog_parser_state {
	const char *restrict str;
	isc__tls_keylog_label_t *restrict out_label;
	isc_buffer_t *restrict out_client_random;
	isc_buffer_t *restrict out_secret;
	isc_result_t result;
} keylog_parser_state_t;

static bool
match_str(keylog_parser_state_t *restrict st, const char *s, const size_t len) {
	return strncasecmp(s, st->str, len) == 0;
}

static bool
match_str_advance(keylog_parser_state_t *restrict st, const char *s,
		  const size_t len) {
	if (!match_str(st, s, len)) {
		return false;
	}

	st->str += len;

	return true;
}

#define MATCH(ch)	    (st->str[0] == (ch))
#define MATCHSTR_ADVANCE(s) (match_str_advance(st, s, sizeof(s) - 1))
#define MATCH_XDIGIT()	    (isxdigit((unsigned char)(st->str[0])))
#define ADVANCE()	    (st->str++)
#define GETCH()		    (st->str[0])

static bool
rule_tls_keylog_entry(keylog_parser_state_t *restrict st);

static bool
rule_label(keylog_parser_state_t *restrict st);

static bool
rule_client_random(keylog_parser_state_t *restrict st);

static bool
rule_secret(keylog_parser_state_t *restrict st);

static bool
rule_endline(keylog_parser_state_t *restrict st);

static bool
rule_hex_byte(keylog_parser_state_t *restrict st, isc_buffer_t *buf);

static bool
rule_tls_keylog_entry(keylog_parser_state_t *restrict st) {
	if (!rule_label(st)) {
		return false;
	}

	if (!MATCH(' ')) {
		return false;
	}

	ADVANCE();

	if (!rule_client_random(st)) {
		return false;
	}

	if (!MATCH(' ')) {
		return false;
	}

	ADVANCE();

	if (!rule_secret(st)) {
		return false;
	}

	(void)rule_endline(st);

	return true;
}

static bool
rule_label(keylog_parser_state_t *restrict st) {
	isc__tls_keylog_label_t label = ISC__TLS_KL_ILLEGAL;

	if (MATCHSTR_ADVANCE("CLIENT_")) {
		if (MATCHSTR_ADVANCE("EARLY_TRAFFIC_SECRET")) {
			label = ISC__TLS_KL_CLIENT_EARLY_TRAFFIC_SECRET;
		} else if (MATCHSTR_ADVANCE("HANDSHAKE_TRAFFIC_SECRET")) {
			label = ISC__TLS_KL_CLIENT_HANDSHAKE_TRAFFIC_SECRET;
		} else if (MATCHSTR_ADVANCE("RANDOM")) {
			label = ISC__TLS_KL_CLIENT_RANDOM;
		} else if (MATCHSTR_ADVANCE("TRAFFIC_SECRET_0")) {
			label = ISC__TLS_KL_CLIENT_TRAFFIC_SECRET_0;
		} else {
			return false;
		}
	} else if (MATCHSTR_ADVANCE("SERVER_")) {
		if (MATCHSTR_ADVANCE("HANDSHAKE_TRAFFIC_SECRET")) {
			label = ISC__TLS_KL_SERVER_HANDSHAKE_TRAFFIC_SECRET;
		} else if (MATCHSTR_ADVANCE("TRAFFIC_SECRET_0")) {
			label = ISC__TLS_KL_SERVER_TRAFFIC_SECRET_0;
		} else {
			return false;
		}
	} else if (MATCHSTR_ADVANCE("EARLY_EXPORTER_MASTER_SECRET")) {
		label = ISC__TLS_KL_EARLY_EXPORTER_MASTER_SECRET;
	} else if (MATCHSTR_ADVANCE("EXPORTER_SECRET")) {
		label = ISC__TLS_KL_EXPORTER_SECRET;
	} else {
		return false;
	}

	if (st->out_label != NULL) {
		*st->out_label = label;
	}
	return true;
}

static bool
rule_client_random(keylog_parser_state_t *restrict st) {
	for (size_t i = 0; i < CLIENT_RANDOM_LEN; i++) {
		if (!rule_hex_byte(st, st->out_client_random)) {
			return false;
		}
	}
	return true;
}

static bool
rule_secret(keylog_parser_state_t *restrict st) {
	if (!rule_hex_byte(st, st->out_secret)) {
		return false;
	}

	for (;;) {
		bool ret = rule_hex_byte(st, st->out_secret);
		if (ret) {
			continue;
		}

		if (st->result != ISC_R_UNSET) {
			return false;
		} else {
			break;
		}
	}

	return true;
}

static bool
rule_endline(keylog_parser_state_t *restrict st) {
	if (!(MATCH('\n') || MATCH('\r'))) {
		return false;
	}

	ADVANCE();

	while (MATCH('\n') || MATCH('\r')) {
		ADVANCE();
	}

	return true;
}

static inline uint8_t
hex_subchar_val(const char ch) {
	uint8_t subval = 0;

	if (ch >= '0' && ch <= '9') {
		subval = ch - '0';
	} else {
		subval = tolower((unsigned char)ch) - 'a' + 10;
	}

	return subval;
}

static inline uint8_t
hex_chars_val(const char *restrict str) {
	uint8_t value = 0;

	value = (hex_subchar_val(str[0]) << 4);
	value += hex_subchar_val(str[1]);

	return value;
}

static bool
rule_hex_byte(keylog_parser_state_t *restrict st, isc_buffer_t *buf) {
	char byte_str[3];

	if (!MATCH_XDIGIT()) {
		return false;
	}

	byte_str[0] = GETCH();
	ADVANCE();

	if (!MATCH_XDIGIT()) {
		return false;
	}

	byte_str[1] = GETCH();
	ADVANCE();

	byte_str[2] = '\0';

	if (buf != NULL) {
		const uint8_t byte = hex_chars_val(byte_str);
		const isc_result_t result = isc_buffer_reserve(buf, 1);
		if (result != ISC_R_SUCCESS) {
			st->result = result;
			return false;
		}
		isc_buffer_putuint8(buf, byte);
	}

	return true;
}

isc_result_t
isc__tls_parse_keylog_entry(const char *restrict line,
			    isc__tls_keylog_label_t *restrict out_label,
			    isc_buffer_t *restrict out_client_random,
			    isc_buffer_t *restrict out_secret) {
	keylog_parser_state_t state;
	bool ret;

	REQUIRE(line != NULL);

	state = (keylog_parser_state_t){ .str = line,
					 .out_label = out_label,
					 .out_client_random = out_client_random,
					 .out_secret = out_secret,
					 .result = ISC_R_UNSET };

	ret = rule_tls_keylog_entry(&state);
	if (!ret && state.result != ISC_R_UNSET) {
		return state.result;
	} else if (!ret) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}
