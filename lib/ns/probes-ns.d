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

provider libns {
	probe rrl_drop(const char *, const char *, const char *, int);
	probe client_recursing(void *, const char *);
	probe client_request(void *);
	probe client_send(void *);
	probe client_sendraw(void *);
	probe client_drop(void *);
	probe client_senddone(void *);
	probe client_endrequest(void *);
	probe client_error(void *);
	probe client_query(void *);
	probe client_request(void *, const char *);
};
