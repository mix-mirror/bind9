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

ns_srcset.add(
    files(
        'client.c',
        'hooks.c',
        'interfacemgr.c',
        'listenlist.c',
        'notify.c',
        'query.c',
        'server.c',
        'stats.c',
        'tracing.c',
        'update.c',
        'xfrout.c',
    ),
)

ns_srcset.add(when: 'ENABLE_TRACING', if_true: lttng_dep)
