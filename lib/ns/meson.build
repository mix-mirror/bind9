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

ns_inc += include_directories('include')
ns_inc_p += include_directories('.')

subdir('include' / 'ns')

ns_probe += files('probes.d')
ns_probed_src += dtrace_header.process('probes.d')
ns_probed_src += files('query.c')

ns_srcset.add(
    files(
        'client.c',
        'hooks.c',
        'interfacemgr.c',
        'listenlist.c',
        'notify.c',
        'server.c',
        'stats.c',
        'update.c',
        'xfrout.c',
    ),
)
