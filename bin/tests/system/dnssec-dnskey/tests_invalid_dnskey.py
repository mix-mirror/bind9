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

from dataclasses import dataclass
import os
from re import compile as Re
import shutil

import dns.dnssec
from dns.dnssectypes import DSDigest
from dns.rdatatype import DNSKEY
import dns.rdtypes
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.zone

import pytest

import isctest
from isctest.template import Nameserver, Zone


pytestmark = pytest.mark.extra_artifacts(
    [
        "*/K*",
        "*/dsset-*",
        "*/*.conf",
        "*/*.db",
        "*/*.db.in",
        "*/*.db.signed",
        "*/*.key",
    ]
)


class CmdHelper:
    def __init__(self, env_name: str, base_params: str = ""):
        self.bin_path = os.environ[env_name]
        self.base_params = base_params

    def __call__(self, params: str, **kwargs):
        args = f"{self.base_params} {params}".split()
        return isctest.run.cmd([self.bin_path] + args, **kwargs).stdout.decode("utf-8")


def mutate_dnskey_rdata(rdata: dns.rdtypes.ANY.DNSKEY.DNSKEY) -> dns.rdtypes.ANY.DNSKEY.DNSKEY:
    return dns.rdtypes.ANY.DNSKEY.DNSKEY(
        rdclass=rdata.rdclass,
        rdtype=rdata.rdtype,
        flags=rdata.flags,
        protocol=rdata.protocol,
        algorithm=100,
        key=rdata.key
    )


def bootstrap():
    alg = os.environ["DEFAULT_ALGORITHM"]
    bits = os.environ["DEFAULT_BITS"]
    templates = isctest.template.TemplateEngine(".")
    keygen = CmdHelper("KEYGEN", f"-q -a {alg} -b {bits} -L 3600")
    signer = CmdHelper("SIGNER", "-S -g")

    data = {
        "zones": [],
        "trust_anchors": [],
    }

    zonename = "invalid-dnskey-rrsig."
    infile = "invalid-dnskey-rrsig.db.in"
    outfile = "invalid-dnskey-rrsig.db.signed"

    isctest.log.info(f"generate ns2 signing keys for {zonename}")
    keygen(f"-f KSK {zonename}", cwd="ns2")
    keygen(f"{zonename}", cwd="ns2")

    isctest.log.info(f"sign ns2 zone {zonename}")
    signer(f"-o {zonename} -f {outfile} {infile}", cwd="ns2")
    data["zones"].append(Zone(zonename, outfile, Nameserver("ns2", "10.53.0.2")))

    isctest.log.info(f"change the DNSKEY rdataset for {zonename}")
    zone = dns.zone.from_file(f"ns2/{outfile}", origin=zonename)
    rdataset = zone.get_rdataset(zonename, DNSKEY)
    old_rdata = rdataset[0]
    new_rdata = mutate_dnskey_rdata(old_rdata)
    rdataset.remove(old_rdata)
    rdataset.add(new_rdata)
    zone.to_file(f"ns2/{outfile}")

    zonename = "."
    template = "root.db.j2.manual"
    infile = "root.db.in"
    outfile = "root.db.signed"

    isctest.log.info(f"generate ns1 signing keys for {zonename}")
    ksk_name = keygen(f"-f KSK {zonename}", cwd="ns1").strip()
    keygen(f"{zonename}", cwd="ns1")

    isctest.log.info(f"create {zonename} zone with delegation(s) and sign")
    templates.render(f"ns1/{infile}", data, template=f"ns1/{template}")
    for zone in data["zones"]:
        shutil.copy(f"{zone.ns.name}/dsset-{zone.name}", "ns1/")
    signer(f"-o {zonename} -f {outfile} {infile}", cwd="ns1")

    isctest.log.info("read KSK and configure it as trust anchor")
    ksk = isctest.kasp.Key(ksk_name, keydir="ns1")
    ta = ksk.into_ta("static-ds")
    data["trust_anchors"].append(ta)

    return data


def test_invalid_dnskey_rrsig(ns3):
    isctest.log.info("check zone with invalid DNSKEY setup")
    msg = isctest.query.create("invalid-dnskey-rrsig", "SOA")
    with ns3.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, "10.53.0.3")
        watcher.wait_for_all([
            Re("validating invalid-dnskey-rrsig/DS.*success"),
            Re("invalid-dnskey-rrsig/DNSKEY.*RRSIG failed to verify"),
            Re("invalid-dnskey-rrsig/SOA.*validation failed"),
        ])
    isctest.check.servfail(res)
