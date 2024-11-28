# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

executable(
    'named-checkconf',
    files('check-tool.c', 'named-checkconf.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

executable(
    'named-checkzone',
    files('check-tool.c', 'named-checkzone.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)
