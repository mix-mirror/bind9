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
import subprocess

from .basic import BASIC_VARS

FEATURES = {
    "AWS_LC": "--with-aws-lc",
    "DNSTAP": "--enable-dnstap",
    "EXTENDED_DS_DIGEST": "--extended-ds-digest",
    "FIPS_DH": "--have-fips-dh",
    "FIPS_MODE": "--have-fips-mode",
    "FIPS_PROVIDER": "--fips-provider",
    "GEOIP2": "--have-geoip2",
    "GSSAPI": "--gssapi",
    "JSON_C": "--have-json-c",
    "LIBIDN2": "--with-libidn2",
    "LIBNGHTTP2": "--with-libnghttp2",
    "LIBXML2": "--have-libxml2",
    "MD5": "--md5",
    "QUERYTRACE": "--enable-querytrace",
    "RSASHA1": "--rsasha1",
    "TSAN": "--tsan",
    "ZLIB": "--with-zlib",
}

FEATURE_VARS = {}


def feature_test(feature):
    feature_test_bin = BASIC_VARS["FEATURETEST"]
    if not feature_test_bin:  # this can be the case when running doctest
        return False
    try:
        subprocess.run([feature_test_bin, feature], check=True)
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        return False
    return True


def init_features():
    """Initialize the environment variables indicating feature support."""
    for name, arg in FEATURES.items():
        supported = feature_test(arg)
        envvar = f"FEATURE_{name}"
        val = "1" if supported else "0"
        FEATURE_VARS[envvar] = val
        os.environ[envvar] = val

    # Cipher lists used by tests configuring forward-secret TLS.  AWS-LC
    # supports fewer ciphers than OpenSSL, so the SHA1/SHA256/SHA384
    # exclusions used to constrain OpenSSL to AEAD ciphers leave AWS-LC
    # with an empty cipher list.
    if FEATURE_VARS["FEATURE_AWS_LC"] == "1":
        exclusions = (
            "!kRSA:!aNULL:!eNULL:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS"
        )
    else:
        exclusions = (
            "!kRSA:!aNULL:!eNULL:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS"
            ":!SHA1:!SHA256:!SHA384"
        )
    for prefix, varname in (
        ("HIGH", "FORWARD_SECRECY_CIPHERS"),
        ("AES256", "FORWARD_SECRECY_AES256_CIPHERS"),
        ("AES128", "FORWARD_SECRECY_AES128_CIPHERS"),
    ):
        value = f"{prefix}:{exclusions}"
        FEATURE_VARS[varname] = value
        os.environ[varname] = value
