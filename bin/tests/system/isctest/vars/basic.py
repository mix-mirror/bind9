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

import os

# pylint: disable=import-error
from .meson import MESON_VARS  # type: ignore

# pylint: enable=import-error


BASIC_VARS = {
    "ARPANAME": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/arpaname",
    "CDS": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-cds",
    "CHECKCONF": f"{MESON_VARS['TOP_BUILDDIR']}/bin/check/named-checkconf",
    "CHECKZONE": f"{MESON_VARS['TOP_BUILDDIR']}/bin/check/named-checkzone",
    "DIG": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dig/dig",
    "DNSTAPREAD": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/dnstap-read",
    "DSFROMKEY": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-dsfromkey",
    "FEATURETEST": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tests/system/feature-test",
    "HOST": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dig/host",
    "IMPORTKEY": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-importkey",
    "JOURNALPRINT": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/named-journalprint",
    "KEYFRLAB": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-keyfromlabel",
    "KEYGEN": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-keygen",
    "KSR": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-ksr",
    "MDIG": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/mdig",
    "NAMED": f"{MESON_VARS['TOP_BUILDDIR']}/bin/named/named",
    "NSEC3HASH": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/nsec3hash",
    "NSLOOKUP": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dig/nslookup",
    "NSUPDATE": f"{MESON_VARS['TOP_BUILDDIR']}/bin/nsupdate/nsupdate",
    "NZD2NZF": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/named-nzd2nzf",
    "REVOKE": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-revoke",
    "RNDC": f"{MESON_VARS['TOP_BUILDDIR']}/bin/rndc/rndc",
    "RNDCCONFGEN": f"{MESON_VARS['TOP_BUILDDIR']}/bin/confgen/rndc-confgen",
    "RRCHECKER": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tools/named-rrchecker",
    "SETTIME": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-settime",
    "SIGNER": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-signzone",
    "TSIGKEYGEN": f"{MESON_VARS['TOP_BUILDDIR']}/bin/confgen/tsig-keygen",
    "VERIFY": f"{MESON_VARS['TOP_BUILDDIR']}/bin/dnssec/dnssec-verify",
    "WIRETEST": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tests/wire_test",
    "BIGKEY": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tests/system/rsabigexponent/bigkey",
    "GENCHECK": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tests/system/rndc/gencheck",
    "MAKEJOURNAL": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tests/system/makejournal",
    "PIPEQUERIES": f"{MESON_VARS['TOP_BUILDDIR']}/bin/tests/system/pipelined/pipequeries",
    "TMPDIR": os.getenv("TMPDIR", "/tmp"),
    "KRB5_CONFIG": "/dev/null",  # we don't want a KRB5_CONFIG setting breaking the tests
    "KRB5_KTNAME": "dns.keytab",  # use local keytab instead of default /etc/krb5.keytab
    "DELV": (
        f"{MESON_VARS['TOP_BUILDDIR']}/bin/delv/delv"
        if not os.getenv("TSAN_OPTIONS", "")
        else ":"  # workaround for GL#4119
    ),
    "LC_ALL": "C",
    "ANS_LOG_LEVEL": "debug",
}
