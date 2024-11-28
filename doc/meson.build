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

if not sphinx_build.found()
    subdir_done()
endif

rst_epilog = f'''.. |rndc_conf| replace:: ``@sysconfdir@/rndc.conf``
.. |rndc_key| replace:: ``@sysconfdir@/rndc.key``
.. |named_conf| replace:: ``@sysconfdir@/named.key``
.. |named_pid| replace:: ``@runstatedir@/named.key``
.. |session_key| replace:: ``@runstatedir@/session.key``'''

sphinx_common_options = ['-W', '-n', '-D', f'rst_epilog=@rst_epilog@']

subdir('arm')
subdir('man')
